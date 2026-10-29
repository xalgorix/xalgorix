// Package llm provides the LLM API client for Xalgorix.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
)

// Message represents a chat message.
//
// ToolCalls and ToolCallID are only populated on the native (OpenAI-style)
// tool-calling channel. Both are omitempty, so the Anthropic, Gemini and
// Responses wire formats are byte-identical when the feature is off — and the
// agent rebuilds plain messages for those protocols anyway.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`

	// ToolCalls is set on an assistant turn that invoked tools natively.
	ToolCalls []MessageToolCall `json:"tool_calls,omitempty"`

	// ToolCallID is the id of the call this message answers (role:"tool").
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// StreamChunk is a piece of streaming response.
type StreamChunk struct {
	Content string
	Done    bool
	Err     error
}

// Client is the LLM API client.
type Client struct {
	cfg           *config.Config
	httpClient    *http.Client
	apiModel      string
	provider      string // "openai", "anthropic", "google", "gemini", "deepseek", etc.
	promptCaching bool
	mu            sync.Mutex
	totalIn       int
	totalOut      int
	totalCached   int
	// ctx is read concurrently by chatWithRetry / ChatStream and written by
	// SetContext. Use atomic.Value to avoid a race; loadCtx() is the only
	// reader, storeCtx() is the only writer.
	ctx atomic.Value // context.Context
	// rateLimiter enforces cfg.RateLimitRPS / cfg.RateLimitBurst against
	// outbound LLM calls. Wait(ctx) blocks until a token is available
	// (or ctx is canceled), so the limiter cannot drop requests
	// (R3.5). nil when the configured RPS is non-positive.
	rateLimiter *rate.Limiter
	// resolver, when non-nil, is consulted by Wave D to obtain the
	// outbound Endpoint instead of resolveEndpoint(). Task 1.3 only
	// stores the resolver; doChat / ChatStream still go through the
	// existing path until Wave D (task 4.2) swaps the dispatch.
	//
	// Validates: Requirement 11.2.
	resolver Resolver
	// tempOverride stores a *float64 for per-role temperature overrides.
	// When set, effectiveTemperature() returns it instead of cfg.Temperature.
	// Use SetTemperature() to change at runtime (e.g. scanner→validator→reporter).
	tempOverride atomic.Value // *float64
	// keyRotator, when non-nil, replaces the resolved endpoint's API
	// key with the next eligible key from the operator's pool
	// (XALGORIX_API_KEYS + XALGORIX_API_KEY): requests spread
	// round-robin across the pool and a key that just hit a provider
	// rate limit is skipped for a short cooldown. nil when fewer than
	// two distinct keys are configured, so single-key setups produce
	// byte-identical requests.
	keyRotator *KeyRotator
}

// PromptTokensDetails carries detailed prompt token breakdowns (cached vs audio/etc).
type PromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// TokenUsage holds cumulative token counts.
type TokenUsage struct {
	PromptTokens         int                  `json:"prompt_tokens"`
	CompletionTokens     int                  `json:"completion_tokens"`
	TotalTokens          int                  `json:"total_tokens"`
	PromptTokensDetails  *PromptTokensDetails `json:"prompt_tokens_details,omitempty"`
	CachedTokens         int                  `json:"cached_tokens,omitempty"`
	CacheReadInputTokens int                  `json:"cache_read_input_tokens,omitempty"`
	// HasCachedTokens is true when the provider actually reported a
	// cached-token field in this response, so zero is never fabricated into
	// "not reported" (or the reverse).
	HasCachedTokens bool `json:"has_cached_tokens,omitempty"`
}

// GetCachedTokens returns the cached prompt token count from any provider-reported field.
func (u *TokenUsage) GetCachedTokens() int {
	if u == nil {
		return 0
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens > 0 {
		return u.PromptTokensDetails.CachedTokens
	}
	if u.CacheReadInputTokens > 0 {
		return u.CacheReadInputTokens
	}
	if u.CachedTokens > 0 {
		return u.CachedTokens
	}
	return 0
}

// hasAnyCachedField reports whether any provider cached-token field was present.
func (u *TokenUsage) hasAnyCachedField() bool {
	if u == nil {
		return false
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens > 0 {
		return true
	}
	return u.CacheReadInputTokens > 0 || u.CachedTokens > 0
}

// GetTokens returns cumulative token usage.
func (c *Client) GetTokens() (promptTokens, completionTokens, totalTokens int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalIn, c.totalOut, c.totalIn + c.totalOut
}

// GetCachedTokens returns cumulative cached prompt tokens reported by the provider.
func (c *Client) GetCachedTokens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalCached
}

// GetTokenUsage returns a copy of cumulative token usage including cached tokens.
func (c *Client) GetTokenUsage() TokenUsage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return TokenUsage{
		PromptTokens:     c.totalIn,
		CompletionTokens: c.totalOut,
		TotalTokens:      c.totalIn + c.totalOut,
		CachedTokens:     c.totalCached,
		HasCachedTokens:  c.totalCached > 0,
		PromptTokensDetails: &PromptTokensDetails{
			CachedTokens: c.totalCached,
		},
	}
}

// Clone returns a shallow copy of the client suitable for use by a subagent.
// It preserves configuration, HTTP client, provider, model, rate limiter,
// resolver, and temperature override, while giving the clone an independent
// context holder and fresh token usage counters.
func (c *Client) Clone() *Client {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	clone := &Client{
		cfg:           c.cfg,
		httpClient:    c.httpClient,
		apiModel:      c.apiModel,
		provider:      c.provider,
		promptCaching: c.promptCaching,
		rateLimiter:   c.rateLimiter,
		resolver:      c.resolver,
		// Share the key-pool rotator (pointer) so a cloned client keeps spreading
		// requests across the pool and shares round-robin + cooldown state with the
		// parent, instead of silently dropping to a single key.
		keyRotator: c.keyRotator,
	}
	clone.ctx.Store(ctxHolder{ctx: context.Background()})
	if v := c.tempOverride.Load(); v != nil {
		clone.tempOverride.Store(v)
	}
	return clone
}

// SetPromptCaching controls whether provider-supported non-semantic prompt caching hints are enabled.
func (c *Client) SetPromptCaching(enabled bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.promptCaching = enabled
}

// IsPromptCachingEnabled reports whether prompt caching hints are enabled.
func (c *Client) IsPromptCachingEnabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.promptCaching
}

// isKnownProvider reports whether candidate matches a known provider slug
// from legacyProviderBases or the built-in catalog.
func isKnownProvider(candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if candidate == "" {
		return false
	}
	if _, ok := legacyProviderBases[candidate]; ok {
		return true
	}
	if _, ok := providers.LookupBuiltin(candidate); ok {
		return true
	}
	return false
}

// NewClient creates a new LLM client. Optional opts (such as
// WithResolver) tune the client for catalog-aware resolution; the
// no-option form preserves the existing legacy resolveEndpoint
// behavior so existing callers compile unchanged.
func NewClient(cfg *config.Config, opts ...Option) *Client {
	apiModel := ""
	if cfg != nil {
		apiModel = cfg.ResolveModel()
	}
	provider := ""
	if idx := strings.Index(apiModel, "/"); idx >= 0 {
		candidate := strings.ToLower(apiModel[:idx])
		if isKnownProvider(candidate) {
			provider = candidate
		}
	}
	if provider == "" && cfg != nil && strings.TrimSpace(cfg.LLMProvider) != "" {
		provider = strings.ToLower(strings.TrimSpace(cfg.LLMProvider))
	}
	// Bound each outbound request. The 10-minute default suits hosted API
	// backends; a local runtime (llama.cpp on CPU) can legitimately need far
	// longer to prefill a large prompt, so allow overriding it via
	// XALGORIX_LLM_TIMEOUT_SECONDS. Non-positive values keep the default.
	timeout := 10 * time.Minute
	if cfg != nil && cfg.LLMTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.LLMTimeoutSeconds) * time.Second
	}
	c := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
		apiModel:   apiModel,
		provider:   provider,
	}
	c.ctx.Store(ctxHolder{ctx: context.Background()})
	// Construct the token-bucket rate limiter from cfg.RateLimitRPS /
	// cfg.RateLimitBurst (R3.5). Wait(ctx) is the only consumer, so
	// requests block instead of being dropped, and ctx cancellation is
	// honored. A non-positive RPS leaves rateLimiter nil so chatWithRetry
	// skips the wait (matching legacy behavior).
	if cfg != nil && cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst < 1 {
			burst = 1
		}
		c.rateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), burst)
	}
	// Build the API-key pool rotator from XALGORIX_API_KEY +
	// XALGORIX_API_KEYS. Only engages with two or more distinct keys;
	// otherwise requests stay byte-identical to the single-key path.
	if cfg != nil {
		pool := make([]string, 0, len(cfg.APIKeys)+1)
		pool = append(pool, cfg.APIKey)
		pool = append(pool, cfg.APIKeys...)
		if r := NewKeyRotator(pool); r != nil && r.Len() > 1 {
			// Sticky/overflow failover when configured; round-robin otherwise.
			if strings.EqualFold(strings.TrimSpace(cfg.KeyPoolStrategy), "sticky") {
				r.SetSticky(true)
			}
			c.keyRotator = r
		}
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// ctxHolder wraps context.Context so atomic.Value sees a concrete type even
// when callers pass a nil context.Context interface.
type ctxHolder struct{ ctx context.Context }

// SetContext sets the context for HTTP requests, enabling cancellation.
// Safe for concurrent use.
func (c *Client) SetContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.ctx.Store(ctxHolder{ctx: ctx})
}

// loadCtx returns the current request context, falling back to Background
// if SetContext has never been called.
func (c *Client) loadCtx() context.Context {
	if v := c.ctx.Load(); v != nil {
		if h, ok := v.(ctxHolder); ok && h.ctx != nil {
			return h.ctx
		}
	}
	return context.Background()
}

// chatRequest is the OpenAI-compatible chat completion request.
type chatRequest struct {
	Model         string         `json:"model"`
	Messages      []Message      `json:"messages"`
	Stream        bool           `json:"stream"`
	StreamOptions *streamOptions `json:"stream_options,omitempty"`
	Temperature   *float64       `json:"temperature,omitempty"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	// MaxCompletionTokens is the replacement for MaxTokens on OpenAI's newer
	// models (GPT-5 family, o-series reasoning models), which reject the legacy
	// `max_tokens` param with a 400. Exactly one of MaxTokens /
	// MaxCompletionTokens is set per request (see buildChatRequest).
	MaxCompletionTokens int    `json:"max_completion_tokens,omitempty"`
	ReasoningEffort     string `json:"reasoning_effort,omitempty"`
	// Tools carries the native tool definitions. Only populated when native
	// tool calling is enabled (XALGORIX_NATIVE_TOOL_CALLS) and the endpoint
	// speaks the OpenAI chat-completions protocol.
	Tools []chatTool `json:"tools,omitempty"`
}

// streamOptions opts into usage stats for OpenAI-compatible streaming
// responses (OpenAI, Groq, DeepSeek, MiniMax, etc.). Without this the
// final `usage` field is omitted from the SSE stream.
type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// contentField accepts the two shapes OpenAI-compatible APIs use for
// message/delta content: a plain string (the classic form) or an array
// of typed parts like [{"type":"text","text":"..."], which Mistral
// returns for newer models (e.g. zai-glm-latest). Non-text parts and
// null decode to an empty string instead of failing the whole response.
type contentField string

func (f *contentField) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = ""
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = contentField(s)
		return nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(data, &parts); err != nil {
		return err
	}
	var sb strings.Builder
	for _, p := range parts {
		if p.Type == "text" || p.Type == "" {
			sb.WriteString(p.Text)
		}
	}
	*f = contentField(sb.String())
	return nil
}

// chatChoice represents a response choice.
type chatChoice struct {
	Delta struct {
		Content   contentField   `json:"content"`
		ToolCalls []chatToolCall `json:"tool_calls"`
	} `json:"delta"`
	Message struct {
		Content   contentField   `json:"content"`
		ToolCalls []chatToolCall `json:"tool_calls"`
		// Refusal and reasoning are only inspected for presence, so the
		// raw form tolerates providers that send a string, list or object.
		Refusal          json.RawMessage `json:"refusal,omitempty"`
		Reasoning        json.RawMessage `json:"reasoning,omitempty"`
		ReasoningContent json.RawMessage `json:"reasoning_content,omitempty"`
	} `json:"message"`
	FinishReason       string `json:"finish_reason,omitempty"`
	NativeFinishReason string `json:"native_finish_reason,omitempty"`
	// Error is set by some OpenAI-compatible gateways when the upstream
	// model failed after the HTTP 200 was already committed.
	Error json.RawMessage `json:"error,omitempty"`
}

// choiceErrorMessage extracts a readable message from a per-choice error
// object, which gateways send either as {"message": "...", "code": ...} or
// as a bare string. Returns "" when there is no error.
func choiceErrorMessage(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var obj struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &obj) == nil && strings.TrimSpace(obj.Message) != "" {
		return strings.TrimSpace(obj.Message)
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return strings.TrimSpace(str)
	}
	return trimmed
}

func hasRawContent(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null" && trimmed != `""` && trimmed != "[]"
}

// chatResponse is the OpenAI-compatible response.
type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   *TokenUsage  `json:"usage,omitempty"`
}

// ── Google Gemini types ──────────────────────────────────────────────────────

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

// geminiGenerationConfig carries the per-request generation controls Gemini
// accepts under "generationConfig". Without it Gemini applies its own
// server-side defaults, ignoring the operator's configured max output tokens
// (which truncates large tool calls such as report_vulnerability) and the
// agent's per-role temperature overrides (e.g. the validator running at 0).
type geminiGenerationConfig struct {
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
}

// geminiSafetySetting is one entry of Gemini's "safetySettings" array: an
// adjustable harm category paired with the HarmBlockThreshold to apply. Xalgorix
// is an authorized security-testing tool, so by default it sends BLOCK_NONE for
// every category to stop Gemini's content filter from refusing legitimate
// exploit payloads / offensive-security methodology (classified under
// HARM_CATEGORY_DANGEROUS_CONTENT). Operator-configurable via
// XALGORIX_GEMINI_SAFETY — see config.Config.GeminiSafetyThreshold.
type geminiSafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

type geminiRequest struct {
	Contents          []geminiContent         `json:"contents,omitempty"`
	SystemInstruction *geminiContent          `json:"system_instruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
	SafetySettings    []geminiSafetySetting   `json:"safetySettings,omitempty"`
}

type geminiCandidate struct {
	Content struct {
		Parts []geminiPart `json:"parts"`
	} `json:"content"`
	// FinishReason is captured so a safety block (finishReason "SAFETY") is
	// diagnosable instead of surfacing as an opaque "no content" error.
	FinishReason string `json:"finishReason,omitempty"`
}

// geminiPromptFeedback carries prompt-level safety verdicts. BlockReason is
// non-empty (e.g. "SAFETY", "PROHIBITED_CONTENT") when Gemini refused the whole
// prompt before generating any candidate.
type geminiPromptFeedback struct {
	BlockReason string `json:"blockReason,omitempty"`
}

type geminiResponse struct {
	Candidates     []geminiCandidate     `json:"candidates"`
	UsageMetadata  *geminiUsageMetadata  `json:"usageMetadata,omitempty"`
	PromptFeedback *geminiPromptFeedback `json:"promptFeedback,omitempty"`
}

// geminiUsageMetadata carries token counts returned by the Gemini
// generateContent and streamGenerateContent endpoints. Unlike the
// OpenAI-style `usage` object, Gemini reports usage under `usageMetadata`;
// in a streamed response the counts are cumulative and the final chunk
// carries the totals.
type geminiUsageMetadata struct {
	PromptTokenCount        int `json:"promptTokenCount"`
	CandidatesTokenCount    int `json:"candidatesTokenCount"`
	TotalTokenCount         int `json:"totalTokenCount"`
	CachedContentTokenCount int `json:"cachedContentTokenCount,omitempty"`
}

// geminiStreamResponse is the same structure but used for SSE streaming responses.
type geminiStreamResponse = geminiResponse

// ── Anthropic types ──────────────────────────────────────────────────────────

type anthropicCacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

type anthropicSystemBlock struct {
	Type         string                 `json:"type"` // "text"
	Text         string                 `json:"text"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

type anthropicRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	System    any       `json:"system,omitempty"` // string or []anthropicSystemBlock
	MaxTokens int       `json:"max_tokens"`
	Stream    bool      `json:"stream"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type anthropicMessage struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Content    []anthropicContentBlock `json:"content"`
	Model      string                  `json:"model"`
	StopReason string                  `json:"stop_reason,omitempty"`
	Usage      struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	} `json:"usage"`
}

type anthropicResponse struct {
	Type    string           `json:"type"`
	Message anthropicMessage `json:"message,omitempty"`
	Delta   struct {
		Text string `json:"text"`
	} `json:"delta,omitempty"`
	Index int `json:"index,omitempty"`
	// Usage at the top level (message_delta events carry final output token count here).
	Usage struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	} `json:"usage,omitempty"`
}

// ResolveEndpoint returns the Endpoint used for outbound requests.
// It is useful for testing and verifying provider/model resolution without sending HTTP traffic.
func (c *Client) ResolveEndpoint(ctx context.Context) (Endpoint, error) {
	return c.resolveRequestEndpoint(ctx)
}

// resolveRequestEndpoint returns the Endpoint to use for one
// outbound chat / stream request. When c.resolver is wired
// (Wave D / task 4.1) we delegate to it so the catalog +
// profile stack drives URL, model, headerStyle, and
// credentials. Otherwise we synthesize an Endpoint from the
// existing resolveEndpoint() + cfg path so callers that haven't
// adopted the resolver yet still produce byte-identical
// outbound requests.
//
// Validates: Requirements 2.2, 2.3, 11.2.
func (c *Client) resolveRequestEndpoint(ctx context.Context) (Endpoint, error) {
	if c.resolver != nil {
		ep, err := c.resolver.Resolve(ctx)
		if err != nil {
			return Endpoint{}, err
		}
		ep.Model = normalizeEndpointModel(c.cfg.LLMProvider, ep.URL, ep.Model)
		return c.applyKeyRotation(ep), nil
	}
	url, model := c.resolveEndpoint()
	providerID := strings.TrimSpace(c.cfg.LLMProvider)
	if providerID == "" {
		providerID = c.provider
	}
	model = normalizeEndpointModel(providerID, url, model)
	hs := "openai"
	switch {
	case c.usesGeminiAPI(url):
		hs = "gemini"
	case c.usesAnthropicAPI(url):
		hs = "anthropic"
	}
	return c.applyKeyRotation(Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: hs,
		Auth:        AuthAPIKey,
		APIKey:      c.cfg.APIKey,
	}), nil
}

// applyKeyRotation replaces the resolved endpoint's API key with the
// next eligible pooled key. Only endpoints carrying the legacy
// configured key (ep.APIKey == cfg.APIKey) are rotated: per-scan
// provider-profile and keystore credentials may belong to a different
// provider and are left untouched, as are OAuth bearer endpoints and
// credential-free (no-auth) endpoints whose key does not match the
// configured one.
func (c *Client) applyKeyRotation(ep Endpoint) Endpoint {
	if c.keyRotator == nil || c.cfg == nil || ep.Auth != AuthAPIKey {
		return ep
	}
	// Rotate when the endpoint carries the legacy configured key (ep.APIKey ==
	// cfg.APIKey) OR already carries one of the pooled keys. The pool holds only
	// the operator's own keys (XALGORIX_API_KEY + XALGORIX_API_KEYS), so a request
	// already using a pooled key is ours to spread across the pool — this is the
	// common case when the keys are supplied via XALGORIX_API_KEYS with an empty
	// XALGORIX_API_KEY and a provider profile resolves every request to the first
	// key (which otherwise never matched the empty cfg.APIKey, pinning all traffic
	// to one key). A credential outside the pool (a different provider's
	// profile/keystore key) is never in the pool and is left untouched.
	if ep.APIKey != c.cfg.APIKey && !c.keyRotator.Contains(ep.APIKey) {
		return ep
	}
	if k := c.keyRotator.Pick(); k != "" {
		ep.APIKey = k
	}
	return ep
}

// noteKeyRateLimited puts the pooled key used by the request that just
// failed with a provider rate limit into cooldown, so the next pick
// concentrates on the remaining keys.
func (c *Client) noteKeyRateLimited() {
	if c.keyRotator != nil {
		c.keyRotator.MarkLastRateLimited()
	}
}

// noteKeyQuotaExhausted cools the pooled key used by the request that just
// failed with quota_exhausted using the longer quota cooldown, so the rotator
// stops routing to a key whose usage window is drained until it very likely
// resets, instead of thrashing requests back onto it every 90s.
func (c *Client) noteKeyQuotaExhausted() {
	if c.keyRotator != nil {
		c.keyRotator.MarkLastQuotaExhausted()
	}
}

// noteKeyRateLimitedForError cools the pooled key used by a failed request,
// choosing the long quota-exhausted cooldown when the error classifies as
// quota_exhausted and the short transient cooldown otherwise.
func (c *Client) noteKeyRateLimitedForError(errStr string) {
	if c.keyRotator == nil {
		return
	}
	if ClassifyErrorString(errStr).Class == ErrorClassQuotaExhausted {
		c.keyRotator.MarkLastQuotaExhausted()
		return
	}
	c.keyRotator.MarkLastRateLimited()
}

// unknownHeaderStyleOnce guards a single log line per process so a
// catalog file edited out-of-band with a corrupt headerStyle
// produces exactly one breadcrumb instead of spamming the log on
// every outbound request. M10.
var unknownHeaderStyleOnce sync.Once

// applyAuthHeaders writes the outbound auth headers for the
// resolved endpoint. The matrix is HeaderStyle × AuthMethod:
//
//   - anthropic: x-api-key (api_key) | Authorization: Bearer
//     (oauth_bearer); always emit anthropic-version: 2023-06-01.
//   - gemini:    x-goog-api-key (api_key) | Authorization:
//     Bearer (oauth_bearer).
//   - openai:    Authorization: Bearer for both auth modes
//     (the access token replaces the api key).
//
// Empty credentials skip the header entirely so downstream
// transports don't see "Authorization: Bearer ".
//
// Validates: Requirements 2.2, 2.3, 11.2.
func applyAuthHeaders(req *http.Request, ep Endpoint) {
	switch ep.HeaderStyle {
	case "anthropic":
		req.Header.Set("anthropic-version", "2023-06-01")
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("x-api-key", ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	case "gemini":
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("x-goog-api-key", ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	case "openai", "openai_responses", "":
		// "openai" / "openai_responses" / unspecified — apply the
		// OpenAI-compatible Bearer header for both auth modes.
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	default:
		// Unknown HeaderStyle — validateEntry rejects this on
		// catalog write, so reaching this branch means the
		// providers.json file was edited out-of-band. Log
		// exactly once via sync.Once so a triage reader sees
		// the breadcrumb without the log being spammed on
		// every outbound request, then fall through to the
		// OpenAI-compatible Bearer header so the request still
		// has a chance of succeeding (a catalog entry pointing
		// at an OpenAI-compatible base URL with a corrupt
		// headerStyle is the most common shape of this bug).
		// M10.
		unknownHeaderStyleOnce.Do(func() {
			log.Printf("[llm] applyAuthHeaders: unknown HeaderStyle %q (catalog corruption?); falling back to openai-style Bearer auth", ep.HeaderStyle)
		})
		switch ep.Auth {
		case AuthAPIKey:
			if ep.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+ep.APIKey)
			}
		case AuthOAuthBearer:
			if ep.AccessToken != "" {
				req.Header.Set("Authorization", "Bearer "+ep.AccessToken)
			}
		}
	}
	if ep.VendorOverride != nil {
		ep.VendorOverride(req)
	}
}

// resolveEndpoint returns the full chat completions URL and clean model name.
// Handles provider prefixes like "minimax/", "openai/", "anthropic/", etc.
// Appends the OpenAI-compatible chat path while preserving an explicit API
// version already present in the base (for example Z.AI's /v4).
// Also supports custom providers - just set XALGORIX_API_BASE to your endpoint.
//
// This is the legacy single-call resolver kept on the Client so
// the no-resolver fallback path in resolveRequestEndpoint can
// reuse it (Requirement 2.3 — preserved endpoint shape).
func (c *Client) resolveEndpoint() (string, string) {
	apiBase := ""
	if c.cfg != nil {
		apiBase = c.cfg.APIBase
	}
	model := c.apiModel

	// Extract provider prefix if present and recognized as a known provider
	// (e.g., "openai/gpt-5.6" -> provider="openai", model="gpt-5.6").
	// Models with org-scoped names (e.g. "zai-org/GLM-5.3", "meta-llama/Llama-3.1-70B-Instruct")
	// retain the full model identifier when the prefix is not a known provider.
	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		candidate := strings.ToLower(model[:idx])
		if isKnownProvider(candidate) {
			provider = candidate
			model = model[idx+1:]
		}
	}
	if provider == "" {
		if c.cfg != nil && strings.TrimSpace(c.cfg.LLMProvider) != "" {
			provider = strings.ToLower(strings.TrimSpace(c.cfg.LLMProvider))
		} else if c.provider != "" {
			provider = c.provider
		}
	}

	providerBases := legacyProviderBases

	if apiBase == "" {
		// No explicit API base set — use provider default
		if knownBase, ok := providerBases[provider]; ok {
			apiBase = knownBase
		} else {
			// Unknown/no provider — default to OpenAI
			apiBase = "https://api.openai.com/v1"
		}
	}

	apiBase = strings.TrimRight(apiBase, "/")

	// Build the URL based on provider
	url := apiBase
	if provider == "anthropic" || strings.Contains(strings.ToLower(apiBase), "anthropic") {
		// Anthropic uses /v1/messages
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	} else if isGeminiProvider(provider) || isGeminiAPIBase(apiBase) {
		// Google Gemini uses /v1beta/models/MODEL:generateContent.
		// Strip any trailing /v1 so we don't end up with /v1beta concatenated
		// onto a version segment the user supplied.
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	} else {
		url = providers.OpenAICompatibleURL(apiBase, "chat/completions")
	}

	return url, model
}

func isGeminiProvider(provider string) bool {
	provider = strings.ToLower(provider)
	return provider == "google" || provider == "gemini"
}

func isGeminiAPIBase(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "generativelanguage.googleapis.com") ||
		strings.Contains(value, "generativelanguage")
}

func (c *Client) usesGeminiAPI(endpoint string) bool {
	return isGeminiProvider(c.provider) ||
		isGeminiAPIBase(c.cfg.APIBase) ||
		isGeminiAPIBase(endpoint)
}

func isAnthropicAPIBase(value string) bool {
	return strings.Contains(strings.ToLower(value), "anthropic")
}

func (c *Client) usesAnthropicAPI(endpoint string) bool {
	return c.provider == "anthropic" ||
		isAnthropicAPIBase(c.cfg.APIBase) ||
		isAnthropicAPIBase(endpoint)
}

// usesOllamaAPI reports whether the resolved OpenAI-compatible endpoint is
// backed by Ollama. Modern catalog settings keep the provider separate from
// the bare model name, while legacy settings encode it as "ollama/model";
// profiles and the conventional :11434 endpoint cover the remaining routes.
func (c *Client) usesOllamaAPI(endpoint string) bool {
	if c == nil || c.cfg == nil {
		return false
	}
	if c.cfg.OllamaCompatible || strings.EqualFold(strings.TrimSpace(c.cfg.LLMProvider), "ollama") || c.provider == "ollama" {
		return true
	}
	profileProvider, _, _ := strings.Cut(strings.TrimSpace(c.cfg.LLMProfile), ":")
	if strings.EqualFold(profileProvider, "ollama") {
		return true
	}
	return hasOllamaPort(c.cfg.APIBase) || hasOllamaPort(endpoint)
}

func hasOllamaPort(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	return err == nil && parsed.Port() == "11434"
}

// ollamaReasoningEffort maps the global setting to Ollama's supported
// OpenAI-compatible values. Ollama has no xhigh level, so xhigh degrades to
// high instead of sending a value the runtime may reject.
func (c *Client) ollamaReasoningEffort(endpoint string) string {
	if !c.usesOllamaAPI(endpoint) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(c.cfg.ReasoningEffort)) {
	case "none", "low", "medium", "high":
		return strings.ToLower(strings.TrimSpace(c.cfg.ReasoningEffort))
	case "xhigh":
		return "high"
	default:
		return ""
	}
}

func apiErrorHasStatus(errStr string, status int) bool {
	return responseErrorStatus(errStr) == status
}

func isContextWindowError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	return strings.Contains(errStr, "400") &&
		(strings.Contains(errStr, "context window") ||
			strings.Contains(errStr, "maximum context length") ||
			strings.Contains(errStr, "too many tokens") ||
			strings.Contains(errStr, "token limit") ||
			strings.Contains(errStr, "invalid params"))
}

func isRateLimitError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	return apiErrorHasStatus(errStr, http.StatusTooManyRequests) ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate limited") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "rate_limit") ||
		strings.Contains(errStr, "ratelimit") ||
		strings.Contains(errStr, "resource_exhausted")
}

func isNonRetryableLLMError(errStr string) bool {
	errStr = strings.ToLower(errStr)
	if strings.Contains(errStr, "context canceled") || strings.Contains(errStr, "context deadline exceeded") {
		return true
	}
	if apiErrorHasStatus(errStr, http.StatusBadRequest) ||
		apiErrorHasStatus(errStr, http.StatusUnauthorized) ||
		apiErrorHasStatus(errStr, http.StatusForbidden) ||
		apiErrorHasStatus(errStr, http.StatusNotFound) ||
		apiErrorHasStatus(errStr, http.StatusMethodNotAllowed) ||
		apiErrorHasStatus(errStr, http.StatusUnprocessableEntity) {
		return true
	}
	return strings.Contains(errStr, "unauthenticated") ||
		strings.Contains(errStr, "access_token_type_unsupported") ||
		strings.Contains(errStr, "invalid authentication credentials") ||
		strings.Contains(errStr, "invalid_request_error") ||
		strings.Contains(errStr, "unsupported_parameter") ||
		strings.Contains(errStr, "invalid_parameter") ||
		strings.Contains(errStr, "invalid_payload") ||
		strings.Contains(errStr, "permission_denied") ||
		strings.Contains(errStr, "permission_error") ||
		strings.Contains(errStr, "model not found") ||
		strings.Contains(errStr, "unknown_model") ||
		strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "invalid_api_key") ||
		strings.Contains(errStr, "account_deactivated") ||
		strings.Contains(errStr, "billing_not_active") ||
		strings.Contains(errStr, "context_length_exceeded") ||
		strings.Contains(errStr, "string_above_max_length")
}

// Chat sends a non-streaming chat request and returns the full response.
func (c *Client) Chat(messages []Message) (string, error) {
	resp, _, err := c.ChatWithUsage(messages)
	return resp, err
}

// ChatWithUsage sends a non-streaming chat request and returns the full response along with per-request token usage.
func (c *Client) ChatWithUsage(messages []Message) (string, *TokenUsage, error) {
	return c.chatWithRetry(messages, nil, nil)
}

// ChatWithUsageToolCalls is ChatWithUsage plus the native tool-calling channel:
// the definitions are offered to the model and any calls it makes come back
// alongside the text.
//
// Passing an empty tools slice is exactly equivalent to ChatWithUsage. Only the
// OpenAI chat-completions path understands the tools/tool_calls wire format;
// every other protocol ignores the definitions and returns no calls, which
// leaves the XML parser in parser.go as the sole tool channel there.
func (c *Client) ChatWithUsageToolCalls(messages []Message, tools []ToolDefinition) (string, []ToolCall, *TokenUsage, error) {
	var calls []ToolCall
	content, usage, err := c.chatWithRetry(messages, tools, &calls)
	return content, calls, usage, err
}

// NativeToolCallingSupported reports whether the resolved endpoint speaks the
// OpenAI chat-completions tool protocol — the only wire format where sending
// `tools` and reading `tool_calls` is understood.
//
// It resolves the endpoint without touching key rotation, so calling it does
// not advance the round-robin of API keys.
func (c *Client) NativeToolCallingSupported() bool {
	ep, err := c.resolveRequestEndpoint(c.loadCtx())
	if err != nil {
		return false
	}
	// The Responses API has its own tool-calling shape, which responses.go does
	// not model — keep it on the XML path rather than half-supporting it.
	if ep.HeaderStyle == headerStyleResponses {
		return false
	}
	return !c.usesAnthropicAPI(ep.URL) && !c.usesGeminiAPI(ep.URL)
}

// minimaxUsageShapeOnce guarantees the redacted usage-structure diagnostic is
// logged at most once per process per source (streaming/non-streaming).
var minimaxUsageShapeOnce = map[string]*sync.Once{}
var minimaxUsageShapeMu sync.Mutex

// logMiniMaxUsageShape logs ONLY the field NAMES (structure) of a provider
// usage object for MiniMax, once per process per source. Values, prompts,
// credentials, and target data are never logged. This verifies which exact
// cached-token field MiniMax actually returns without inventing estimates.
func (c *Client) logMiniMaxUsageShape(rawUsage json.RawMessage, source string) {
	if c == nil || len(rawUsage) == 0 {
		return
	}
	if !c.isMiniMaxProvider() {
		return
	}
	minimaxUsageShapeMu.Lock()
	once, ok := minimaxUsageShapeOnce[source]
	if !ok {
		once = &sync.Once{}
		minimaxUsageShapeOnce[source] = once
	}
	minimaxUsageShapeMu.Unlock()
	once.Do(func() {
		var top map[string]json.RawMessage
		if json.Unmarshal(rawUsage, &top) != nil {
			log.Printf("[llm] MiniMax usage structure (%s): unparseable (keys withheld)", source)
			return
		}
		keys := make([]string, 0, len(top))
		nested := []string{}
		for k, v := range top {
			keys = append(keys, k)
			var inner map[string]json.RawMessage
			if json.Unmarshal(v, &inner) != nil {
				continue
			}
			for ik := range inner {
				nested = append(nested, k+"."+ik)
			}
		}
		sort.Strings(keys)
		sort.Strings(nested)
		log.Printf("[llm] MiniMax usage structure (%s): fields=%v nested=%v", source, keys, nested)
	})
}

// isMiniMaxProvider reports whether the configured model targets MiniMax.
func (c *Client) isMiniMaxProvider() bool {
	if c == nil || c.cfg == nil {
		return false
	}
	model := strings.ToLower(c.cfg.LLM + " " + c.apiModel + " " + c.provider)
	return strings.Contains(model, "minimax")
}

// SetTemperature overrides the LLM temperature for subsequent calls.
// Pass nil to revert to the config default.
// This is goroutine-safe and takes effect on the next Chat/ChatStream call.
func (c *Client) SetTemperature(temp *float64) {
	if temp == nil {
		c.tempOverride.Store((*float64)(nil))
	} else {
		// Copy so caller can't mutate after setting
		v := *temp
		c.tempOverride.Store(&v)
	}
}

// modelRequiresFixedTemperature reports whether a model rejects any
// temperature other than the default 1 (returns 400 "only 1 is allowed for
// this model"). Moonshot's Kimi K2.6 and K3 models enforce this. For these the
// agent's per-role SetTemperature overrides (validator/reporter/scanner, which
// use values like 0.0) MUST be ignored — otherwise every call errors. Matching
// on the bare model name is safe: only Moonshot serves these names.
func modelRequiresFixedTemperature(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	return strings.Contains(m, "kimi-k2.6") || strings.Contains(m, "kimi-k3")
}

// modelRequiresPositiveTemperature identifies providers/models whose API
// rejects temperature=0. MiniMax's OpenAI-compatible contract requires a
// value in (0, 1] and recommends 1. The agent normally applies a deterministic
// 0.0 scanner override, so without this guard MiniMax behavior depends on
// undocumented server coercion and can degrade into malformed output.
func modelRequiresPositiveTemperature(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	return strings.HasPrefix(m, "minimax-")
}

// effectiveTemperature returns the temperature to send. Models that only accept
// the default (Kimi K2.6 / K3) always get 1 regardless of config or per-call
// overrides. Otherwise the per-call override wins, falling back to the config
// default.
func (c *Client) effectiveTemperature() *float64 {
	if modelRequiresFixedTemperature(c.apiModel) {
		one := 1.0
		return &one
	}
	var selected *float64
	if v, ok := c.tempOverride.Load().(*float64); ok && v != nil {
		selected = v
	} else {
		selected = c.cfg.Temperature
	}
	if modelRequiresPositiveTemperature(c.apiModel) && selected != nil && *selected <= 0 {
		one := 1.0
		return &one
	}
	return selected
}

// maxOutputTokens returns the per-call completion cap (max_tokens). Reasoning
// models spend part of this budget on hidden thinking before emitting a tool
// call, so we send an explicit, generous value rather than relying on the
// provider's unset default (which some OpenAI-compatible backends set very
// low, truncating large calls like report_vulnerability mid-stream). Clamped
// to a sane floor so a misconfigured tiny value can't starve every call.
func (c *Client) maxOutputTokens() int {
	n := c.cfg.MaxOutputTokens
	if n <= 0 {
		n = 8192
	}
	if n < 1024 {
		n = 1024
	}
	return n
}

// geminiHarmCategories are the adjustable Gemini safety categories Xalgorix sets
// a threshold on. All four get the same operator-configured threshold so an
// authorized assessment is not blocked mid-scan when the model reasons about
// exploit payloads or offensive-security methodology (Gemini files these under
// HARM_CATEGORY_DANGEROUS_CONTENT). HARM_CATEGORY_CIVIC_INTEGRITY is
// intentionally omitted — it is unrelated to security testing.
var geminiHarmCategories = []string{
	"HARM_CATEGORY_HARASSMENT",
	"HARM_CATEGORY_HATE_SPEECH",
	"HARM_CATEGORY_SEXUALLY_EXPLICIT",
	"HARM_CATEGORY_DANGEROUS_CONTENT",
}

// unknownGeminiSafetyOnce guards a single warning line for an unrecognized
// XALGORIX_GEMINI_SAFETY value so a typo produces one breadcrumb, not log spam.
var unknownGeminiSafetyOnce sync.Once

// normalizeGeminiSafetyThreshold maps the operator-facing XALGORIX_GEMINI_SAFETY
// value to a canonical Gemini HarmBlockThreshold. It returns ("", false) when no
// safetySettings should be sent — empty / "default" / "unspecified" — so Gemini
// applies its own server-side defaults (preserving the pre-change behavior for
// operators who explicitly opt back into it). Unknown values fall back to
// BLOCK_NONE (the tool's default posture for authorized security testing) with a
// one-time warning rather than sending an invalid value that Gemini would 400.
func normalizeGeminiSafetyThreshold(raw string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "DEFAULT", "UNSPECIFIED", "HARM_BLOCK_THRESHOLD_UNSPECIFIED":
		return "", false
	case "OFF":
		return "OFF", true
	case "BLOCK_NONE", "NONE":
		return "BLOCK_NONE", true
	case "BLOCK_ONLY_HIGH", "ONLY_HIGH":
		return "BLOCK_ONLY_HIGH", true
	case "BLOCK_MEDIUM_AND_ABOVE", "MEDIUM":
		return "BLOCK_MEDIUM_AND_ABOVE", true
	case "BLOCK_LOW_AND_ABOVE", "LOW":
		return "BLOCK_LOW_AND_ABOVE", true
	default:
		unknownGeminiSafetyOnce.Do(func() {
			log.Printf("[llm] unknown XALGORIX_GEMINI_SAFETY=%q; using BLOCK_NONE (authorized-security-testing default)", raw)
		})
		return "BLOCK_NONE", true
	}
}

// geminiSafetySettings builds the per-request safetySettings array from the
// operator's configured threshold. Returns nil (the field is omitted, so Gemini
// uses its server-side defaults) when the operator opted into DEFAULT/"".
func (c *Client) geminiSafetySettings() []geminiSafetySetting {
	raw := ""
	if c.cfg != nil {
		raw = c.cfg.GeminiSafetyThreshold
	}
	threshold, ok := normalizeGeminiSafetyThreshold(raw)
	if !ok {
		return nil
	}
	settings := make([]geminiSafetySetting, 0, len(geminiHarmCategories))
	for _, cat := range geminiHarmCategories {
		settings = append(settings, geminiSafetySetting{Category: cat, Threshold: threshold})
	}
	return settings
}

// geminiBlockDetail returns a human-readable suffix explaining WHY a Gemini
// response carried no usable content, so a safety block is diagnosable instead
// of surfacing as an opaque "no content" error. Empty when no signal is present.
func geminiBlockDetail(resp geminiResponse) string {
	var finishReason, blockReason string
	if len(resp.Candidates) > 0 {
		finishReason = resp.Candidates[0].FinishReason
	}
	if resp.PromptFeedback != nil {
		blockReason = resp.PromptFeedback.BlockReason
	}
	if finishReason == "" && blockReason == "" {
		return ""
	}
	detail := fmt.Sprintf(" (finishReason=%q promptFeedback.blockReason=%q", finishReason, blockReason)
	if strings.EqualFold(finishReason, "SAFETY") ||
		strings.EqualFold(blockReason, "SAFETY") ||
		strings.EqualFold(blockReason, "PROHIBITED_CONTENT") {
		detail += "; Gemini's safety filter blocked this response — set XALGORIX_GEMINI_SAFETY=BLOCK_NONE (or OFF) to allow authorized security-testing content"
	}
	return detail + ")"
}

// usesMaxCompletionTokens reports whether an OpenAI model requires the
// `max_completion_tokens` parameter and rejects the legacy `max_tokens` with a
// 400 ("Unsupported parameter: 'max_tokens' is not supported with this model.
// Use 'max_completion_tokens' instead."). This covers the GPT-5 family and the
// o-series reasoning models (o1/o3/o4). These same models also only accept the
// default temperature, so buildChatRequest omits temperature for them.
//
// Only OpenAI serves these model names, so matching on the bare model name is
// safe even though the OpenAI-compatible request path is shared with providers
// (MiniMax/DeepSeek/Groq/Ollama) that still use `max_tokens`.
func usesMaxCompletionTokens(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	return strings.HasPrefix(m, "gpt-5") ||
		strings.HasPrefix(m, "o1") ||
		strings.HasPrefix(m, "o3") ||
		strings.HasPrefix(m, "o4")
}

// buildChatRequest assembles the OpenAI-compatible chat completion request,
// picking the correct completion-token parameter for the model. Newer OpenAI
// models (GPT-5 / o-series) require `max_completion_tokens` and reject both
// `max_tokens` and a non-default temperature; every other model keeps the
// legacy `max_tokens` + configured temperature.
func (c *Client) buildChatRequest(model string, messages []Message, endpoint string, stream bool) chatRequest {
	req := chatRequest{
		Model:           model,
		Messages:        messages,
		Stream:          stream,
		ReasoningEffort: c.ollamaReasoningEffort(endpoint),
	}
	if stream {
		req.StreamOptions = &streamOptions{IncludeUsage: true}
	}
	if usesMaxCompletionTokens(model) {
		req.MaxCompletionTokens = c.maxOutputTokens()
		// Leave Temperature nil — these models only accept the default.
	} else {
		req.MaxTokens = c.maxOutputTokens()
		req.Temperature = c.effectiveTemperature()
	}
	return req
}

func (c *Client) buildAnthropicSystem(systemPrompt string) any {
	if systemPrompt == "" {
		return nil
	}
	if c != nil && c.IsPromptCachingEnabled() {
		return []anthropicSystemBlock{
			{
				Type:         "text",
				Text:         systemPrompt,
				CacheControl: &anthropicCacheControl{Type: "ephemeral"},
			},
		}
	}
	return systemPrompt
}

// chatWithRetry owns the retry/backoff loop around a single chat call.
//
// tools carries the native tool definitions (nil on the legacy XML path), and
// callsOut — when non-nil — receives the native tool calls produced by the
// attempt that succeeded. Using an out-parameter instead of a fourth return
// value keeps the fourteen error paths below untouched.
func (c *Client) chatWithRetry(messages []Message, tools []ToolDefinition, callsOut *[]ToolCall) (string, *TokenUsage, error) {
	maxRetries := c.cfg.LLMMaxRetries
	if maxRetries < 3 {
		maxRetries = 3
	}
	var lastErr error

	for attempt := range maxRetries {
		if ctx := c.loadCtx(); ctx.Err() != nil {
			return "", nil, fmt.Errorf("LLM request canceled: %w", ctx.Err())
		}

		if attempt > 0 {
			if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) ||
				strings.Contains(lastErr.Error(), "context canceled") || strings.Contains(lastErr.Error(), "context deadline exceeded") {
				return "", nil, fmt.Errorf("LLM request canceled: %w", lastErr)
			}

			// Smart backoff based on error type
			backoff := time.Duration(attempt*3) * time.Second
			if lastErr != nil {
				errStr := lastErr.Error()
				if isRateLimitError(errStr) {
					backoff = 30 * time.Second // rate limit: wait longer
				} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "EOF") {
					backoff = time.Duration(attempt*10) * time.Second // network: longer backoff
				} else if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") || strings.Contains(errStr, "503") {
					backoff = time.Duration(attempt*5) * time.Second // server error
				}
			}
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			log.Printf("[llm] Retry %d/%d after %s (%s)", attempt+1, maxRetries, backoff, SafeErrorDiagnostic(lastErr))
			select {
			case <-c.loadCtx().Done():
				return "", nil, fmt.Errorf("LLM request canceled: %w", c.loadCtx().Err())
			case <-time.After(backoff):
			}
		}

		// Check if context is canceled before retrying
		if ctx := c.loadCtx(); ctx.Err() != nil {
			return "", nil, fmt.Errorf("LLM request canceled: %w", ctx.Err())
		}

		result, usage, err := c.doChatWithUsage(messages, tools, callsOut)
		if err == nil {
			return result, usage, nil
		}
		lastErr = err

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(err.Error(), "context canceled") || strings.Contains(err.Error(), "context deadline exceeded") {
			return "", nil, fmt.Errorf("LLM request canceled: %w", err)
		}

		// Configuration errors are deterministic — a missing base
		// URL, unknown provider, or unset profile will never succeed
		// on retry. Surface them immediately instead of running the
		// full backoff loop (issue #122: a custom provider with no
		// base URL produced `unsupported protocol scheme ""` and was
		// retried 5 times, making a config bug look transient).
		var cfgErr *ConfigError
		if errors.As(err, &cfgErr) {
			log.Printf("[llm] Non-retryable config error, returning immediately: %v", err)
			return "", nil, fmt.Errorf("LLM request failed: %w", err)
		}

		// Non-retryable errors: context window overflow, malformed request, etc.
		// These will never succeed on retry — return immediately so the caller
		// can handle them (e.g. by pruning messages).
		errStr := err.Error()
		if isContextWindowError(errStr) {
			log.Printf("[llm] Non-retryable error (context overflow), returning immediately: %v", err)
			return "", nil, fmt.Errorf("context window overflow: %w", err)
		}

		// Capacity and credit waits belong to the agent's bounded backoff,
		// just like rate limits. Avoid replaying a full request inside both loops.
		classified := ClassifyErrorString(errStr)
		if classified.Class == ErrorClassOverloaded || classified.Class == ErrorClassQuotaExhausted {
			// Cool the pooled key before handing off to the agent's bounded
			// backoff, so the retry that follows picks a different key instead
			// of round-robining back onto this one. Quota exhaustion gets the
			// long cooldown (the usage window stays drained far longer than a
			// transient overload).
			if classified.Class == ErrorClassQuotaExhausted {
				c.noteKeyQuotaExhausted()
			} else {
				c.noteKeyRateLimited()
			}
			return "", nil, fmt.Errorf("upstream unavailable: %w", err)
		}

		if isNonRetryableLLMError(errStr) {
			log.Printf("[llm] Non-retryable LLM error, returning immediately: %v", err)
			return "", nil, fmt.Errorf("LLM request failed: %w", err)
		}

		// Track if last error was a rate limit for the post-loop wrapper
		if isRateLimitError(errStr) {
			c.noteKeyRateLimited()
			// A 429/usage-window response is not made more likely to succeed by
			// replaying the same full context three to five times immediately.
			// Return to the agent loop so its bounded, interruptible backoff owns
			// the retry decision and we issue at most one provider request per
			// wait interval.
			return "", nil, fmt.Errorf("rate limited: %w", err)
		}
	}

	// Preserve rate-limit marker if the final error was rate-limited
	if lastErr != nil && strings.Contains(lastErr.Error(), "rate limited:") {
		return "", nil, fmt.Errorf("rate limited: LLM request failed after %d retries: %w", maxRetries, lastErr)
	}
	return "", nil, fmt.Errorf("LLM request failed after %d retries: %w", maxRetries, lastErr)
}

// ChatStream sends a streaming chat request and returns a channel of chunks.
func (c *Client) ChatStream(messages []Message) <-chan StreamChunk {
	ch := make(chan StreamChunk, 64)

	// Spawn the streaming goroutine under safe.Go (R1.2 / R1.5) so a
	// panic in JSON parsing, transport, or scanner produces exactly one
	// recovery log line and increments PanicsRecovered. Without this
	// wrapper a panic here would crash the entire process.
	safe.Go("llm.stream", "", func() {
		defer close(ch)

		// Honor the LLM token-bucket rate limiter (R3.5) and the
		// in-flight cap (R3.3 / R3.4) for streaming calls too — both
		// limits are about outbound LLM volume, not request shape.
		// On ctx cancellation neither call consumes a slot (P3.4).
		streamCtx := c.loadCtx()
		if c.rateLimiter != nil {
			if err := c.rateLimiter.Wait(streamCtx); err != nil {
				ch <- StreamChunk{Err: fmt.Errorf("llm rate limit: %w", err)}
				return
			}
		}
		release, err := resources.AcquireLLMSlot(streamCtx)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("llm slot: %w", err)}
			return
		}
		defer release()

		ep, err := c.resolveRequestEndpoint(streamCtx)
		if err != nil {
			ch <- StreamChunk{Err: err}
			return
		}
		// OpenAI Responses API (Codex / ChatGPT subscription) uses a
		// distinct streaming contract — delegate and stop here.
		if ep.HeaderStyle == headerStyleResponses {
			c.streamResponses(streamCtx, ep, messages, ch)
			return
		}
		endpoint, model := ep.URL, ep.Model
		isGoogle := ep.HeaderStyle == "gemini"
		isAnthropic := ep.HeaderStyle == "anthropic"

		var body []byte
		if isGoogle {
			endpoint = strings.TrimSuffix(endpoint, "generateContent") + "streamGenerateContent?alt=sse"
			var systemParts []geminiPart
			contents := make([]geminiContent, 0, len(messages))
			for _, m := range messages {
				if m.Role == "system" {
					systemParts = append(systemParts, geminiPart{Text: m.Content})
				} else {
					role := m.Role
					if role == "assistant" {
						role = "model"
					}
					contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
				}
			}
			gemReq := geminiRequest{Contents: contents}
			if len(systemParts) > 0 {
				gemReq.SystemInstruction = &geminiContent{Role: "user", Parts: systemParts}
			}
			gemReq.GenerationConfig = &geminiGenerationConfig{
				MaxOutputTokens: c.maxOutputTokens(),
				Temperature:     c.effectiveTemperature(),
			}
			gemReq.SafetySettings = c.geminiSafetySettings()
			body, _ = json.Marshal(gemReq)
		} else if isAnthropic {
			var systemPrompt string
			anthropicMsgs := make([]Message, 0, len(messages))
			for _, m := range messages {
				if m.Role == "system" {
					systemPrompt = m.Content
				} else {
					anthropicMsgs = append(anthropicMsgs, m)
				}
			}
			maxTokens := c.maxOutputTokens()
			anReq := anthropicRequest{
				Model:     model,
				Messages:  anthropicMsgs,
				System:    c.buildAnthropicSystem(systemPrompt),
				MaxTokens: maxTokens,
				Stream:    true,
			}
			body, _ = json.Marshal(anReq)
		} else {
			reqBody := c.buildChatRequest(model, messages, endpoint, true)
			body, _ = json.Marshal(reqBody)
		}

		req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			ch <- StreamChunk{Err: err}
			return
		}

		req.Header.Set("Content-Type", "application/json")
		applyAuthHeaders(req, ep)
		if c.IsPromptCachingEnabled() && c.usesAnthropicAPI(endpoint) {
			req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				ch <- StreamChunk{Err: fmt.Errorf("API returned %d (failed to read body: %w)", resp.StatusCode, readErr)}
				return
			}
			rlErr := fmt.Sprintf("API returned %d: %s", resp.StatusCode, string(respBody))
			if isRateLimitError(rlErr) {
				c.noteKeyRateLimitedForError(rlErr)
			}
			ch <- StreamChunk{Err: fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		if isAnthropic {
			// Anthropic SSE: each line is "event: TYPE" followed by "data: JSON"
			var currentEvent string
			var anResp anthropicResponse
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if ev, ok := strings.CutPrefix(line, "event: "); ok {
					currentEvent = ev
					continue
				}
				data, ok := strings.CutPrefix(line, "data: ")
				if !ok {
					continue
				}
				data = strings.TrimSpace(data)

				if err := json.Unmarshal([]byte(data), &anResp); err != nil {
					continue
				}

				switch currentEvent {
				case "message_start":
					c.mu.Lock()
					c.totalIn += anResp.Message.Usage.InputTokens
					c.totalOut += anResp.Message.Usage.OutputTokens
					c.totalCached += anResp.Message.Usage.CacheReadInputTokens
					c.mu.Unlock()
				case "content_block_delta":
					if anResp.Delta.Text != "" {
						ch <- StreamChunk{Content: anResp.Delta.Text}
					}
				case "message_delta":
					// Final usage update — output_tokens arrives at the top level here.
					if anResp.Usage.OutputTokens > 0 || anResp.Usage.CacheReadInputTokens > 0 {
						c.mu.Lock()
						c.totalOut += anResp.Usage.OutputTokens
						c.totalCached += anResp.Usage.CacheReadInputTokens
						c.mu.Unlock()
					}
				case "message_stop":
					ch <- StreamChunk{Done: true}
					return
				}
			}
			ch <- StreamChunk{Done: true}
			return
		}

		// OpenAI/Google streaming: "data: JSON" lines. Gemini reports token usage
		// under usageMetadata (cumulative per chunk); keep the latest values and
		// add them to the running totals once, after the stream ends.
		var gemPromptTokens, gemCandidateTokens, gemCachedTokens int
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				ch <- StreamChunk{Done: true}
				return
			}

			if isGoogle {
				var gemResp geminiStreamResponse
				if err := json.Unmarshal([]byte(data), &gemResp); err != nil {
					continue
				}
				if gemResp.UsageMetadata != nil {
					// Gemini streams cumulative usage; remember the latest.
					gemPromptTokens = gemResp.UsageMetadata.PromptTokenCount
					gemCandidateTokens = gemResp.UsageMetadata.CandidatesTokenCount
					gemCachedTokens = gemResp.UsageMetadata.CachedContentTokenCount
				}
				if len(gemResp.Candidates) > 0 && len(gemResp.Candidates[0].Content.Parts) > 0 {
					content := gemResp.Candidates[0].Content.Parts[0].Text
					if content != "" {
						ch <- StreamChunk{Content: content}
					}
				}
			} else {
				var sseResp chatResponse
				if err := json.Unmarshal([]byte(data), &sseResp); err != nil {
					continue
				}
				if sseResp.Usage != nil {
					sseResp.Usage.HasCachedTokens = sseResp.Usage.hasAnyCachedField()
					var env struct {
						Usage json.RawMessage `json:"usage"`
					}
					if json.Unmarshal([]byte(data), &env) == nil {
						c.logMiniMaxUsageShape(env.Usage, "streaming")
					}
					cached := sseResp.Usage.GetCachedTokens()
					c.mu.Lock()
					c.totalIn += sseResp.Usage.PromptTokens
					c.totalOut += sseResp.Usage.CompletionTokens
					c.totalCached += cached
					c.mu.Unlock()
				}
				if len(sseResp.Choices) > 0 {
					content := sseResp.Choices[0].Delta.Content
					if content != "" {
						ch <- StreamChunk{Content: string(content)}
					}
				}
			}
		}

		if gemPromptTokens > 0 || gemCandidateTokens > 0 {
			c.mu.Lock()
			c.totalIn += gemPromptTokens
			c.totalOut += gemCandidateTokens
			c.totalCached += gemCachedTokens
			c.mu.Unlock()
		}
		ch <- StreamChunk{Done: true}
	})

	return ch
}

// doChat performs a single non-streaming API call.
func (c *Client) doChat(messages []Message) (string, error) {
	resp, _, err := c.doChatWithUsage(messages, nil, nil)
	return resp, err
}

// doChatWithUsage performs a single non-streaming API call and returns per-request token usage.
//
// tools and callsOut enable the native tool-calling channel; both are nil on
// the legacy XML path, where the request body must stay byte-identical.
func (c *Client) doChatWithUsage(messages []Message, tools []ToolDefinition, callsOut *[]ToolCall) (out string, usage *TokenUsage, err error) {
	// Panic boundary (R1.5): any panic in the LLM client (JSON
	// marshaling, header construction, HTTP transport panic) is
	// converted into a typed error so the caller can decide whether to
	// retry. The recovered panic is logged exactly once and the
	// PanicsRecovered counter is incremented by safe.Recover.
	defer safe.Recover("llm.doChat", "", &err)

	// Honor the LLM token-bucket rate limiter (R3.5): block instead of
	// dropping, and propagate ctx cancellation (R3.4 / P3.4) without
	// consuming a token slot.
	reqCtx := c.loadCtx()
	if c.rateLimiter != nil {
		if err = c.rateLimiter.Wait(reqCtx); err != nil {
			return "", nil, fmt.Errorf("llm rate limit: %w", err)
		}
	}

	// Reserve one in-flight LLM slot (R3.3 / R3.4). The slot is held
	// for the entire request, including body read, so a stalled
	// upstream cannot let more requests pile up than the cap allows.
	release, err := resources.AcquireLLMSlot(reqCtx)
	if err != nil {
		return "", nil, fmt.Errorf("llm slot: %w", err)
	}
	defer release()

	ep, err := c.resolveRequestEndpoint(reqCtx)
	if err != nil {
		return "", nil, err
	}
	endpoint, model := ep.URL, ep.Model
	log.Printf("[llm] Request → URL=%s model=%s apiModel=%s cfgLLM=%s cfgAPIBase=%s", endpoint, model, c.apiModel, c.cfg.LLM, c.cfg.APIBase)

	// OpenAI Responses API (Codex / ChatGPT subscription backend) has its
	// own request/response contract — delegate to the dedicated path.
	if ep.HeaderStyle == headerStyleResponses {
		return c.doResponsesWithUsage(reqCtx, ep, messages)
	}

	isGoogle := ep.HeaderStyle == "gemini"
	isAnthropic := ep.HeaderStyle == "anthropic"

	var body []byte
	if isGoogle {
		// Google Gemini: extract system messages, convert roles
		var systemParts []geminiPart
		contents := make([]geminiContent, 0, len(messages))
		for _, m := range messages {
			if m.Role == "system" {
				systemParts = append(systemParts, geminiPart{Text: m.Content})
			} else {
				role := m.Role
				if role == "assistant" {
					role = "model"
				}
				contents = append(contents, geminiContent{Role: role, Parts: []geminiPart{{Text: m.Content}}})
			}
		}
		gemReq := geminiRequest{Contents: contents}
		if len(systemParts) > 0 {
			gemReq.SystemInstruction = &geminiContent{Role: "user", Parts: systemParts}
		}
		gemReq.GenerationConfig = &geminiGenerationConfig{
			MaxOutputTokens: c.maxOutputTokens(),
			Temperature:     c.effectiveTemperature(),
		}
		gemReq.SafetySettings = c.geminiSafetySettings()
		body, err = json.Marshal(gemReq)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal Gemini request: %w", err)
		}
	} else if isAnthropic {
		// Anthropic: system as top-level field, max_tokens required
		var systemPrompt string
		anthropicMsgs := make([]Message, 0, len(messages))
		for _, m := range messages {
			if m.Role == "system" {
				systemPrompt = m.Content
			} else {
				anthropicMsgs = append(anthropicMsgs, m)
			}
		}
		// Anthropic requires this field; use the configured budget.
		maxTokens := c.maxOutputTokens()
		anReq := anthropicRequest{
			Model:     model,
			Messages:  anthropicMsgs,
			System:    c.buildAnthropicSystem(systemPrompt),
			MaxTokens: maxTokens,
			Stream:    false,
		}
		body, err = json.Marshal(anReq)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal Anthropic request: %w", err)
		}
	} else {
		reqBody := c.buildChatRequest(model, messages, endpoint, false)
		// Native tool definitions only travel on the OpenAI-compatible branch;
		// the Anthropic, Gemini and Responses paths are handled above and keep
		// using the XML dialect.
		if len(tools) > 0 {
			reqBody.Tools = buildChatTools(tools)
		}
		body, err = json.Marshal(reqBody)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	applyAuthHeaders(req, ep)
	if c.IsPromptCachingEnabled() && c.usesAnthropicAPI(endpoint) {
		req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		rlErr := fmt.Sprintf("API returned %d: %s", resp.StatusCode, string(respBody))
		if isRateLimitError(rlErr) {
			c.noteKeyRateLimitedForError(rlErr)
		}
		return "", nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	if isGoogle {
		var gemResp geminiResponse
		if err := json.Unmarshal(respBody, &gemResp); err != nil {
			return "", nil, fmt.Errorf("failed to parse Gemini response: %w", err)
		}
		if len(gemResp.Candidates) == 0 || len(gemResp.Candidates[0].Content.Parts) == 0 {
			return "", nil, fmt.Errorf("no content in Gemini response%s", geminiBlockDetail(gemResp))
		}
		var gemUsage *TokenUsage
		if gemResp.UsageMetadata != nil {
			cached := gemResp.UsageMetadata.CachedContentTokenCount
			c.mu.Lock()
			c.totalIn += gemResp.UsageMetadata.PromptTokenCount
			c.totalOut += gemResp.UsageMetadata.CandidatesTokenCount
			c.totalCached += cached
			c.mu.Unlock()
			gemUsage = &TokenUsage{
				PromptTokens:     gemResp.UsageMetadata.PromptTokenCount,
				CompletionTokens: gemResp.UsageMetadata.CandidatesTokenCount,
				TotalTokens:      gemResp.UsageMetadata.TotalTokenCount,
				CachedTokens:     cached,
				HasCachedTokens:  cached > 0,
				PromptTokensDetails: &PromptTokensDetails{
					CachedTokens: cached,
				},
			}
		}
		return gemResp.Candidates[0].Content.Parts[0].Text, gemUsage, nil
	}

	if isAnthropic {
		var anMsg anthropicMessage
		if err := json.Unmarshal(respBody, &anMsg); err != nil {
			return "", nil, fmt.Errorf("failed to parse Anthropic response: %w", err)
		}
		// Track token usage
		cached := anMsg.Usage.CacheReadInputTokens
		c.mu.Lock()
		c.totalIn += anMsg.Usage.InputTokens
		c.totalOut += anMsg.Usage.OutputTokens
		c.totalCached += cached
		c.mu.Unlock()
		anUsage := &TokenUsage{
			PromptTokens:         anMsg.Usage.InputTokens,
			CompletionTokens:     anMsg.Usage.OutputTokens,
			TotalTokens:          anMsg.Usage.InputTokens + anMsg.Usage.OutputTokens,
			CachedTokens:         cached,
			CacheReadInputTokens: cached,
			HasCachedTokens:      cached > 0,
			PromptTokensDetails: &PromptTokensDetails{
				CachedTokens: cached,
			},
		}
		// Extract text from content blocks
		for _, block := range anMsg.Content {
			if block.Type == "text" && block.Text != "" {
				return block.Text, anUsage, nil
			}
		}
		log.Printf("[llm] Anthropic response with no text content (stop_reason: %s, content_blocks: %d): %s", anMsg.StopReason, len(anMsg.Content), string(respBody))
		return "", anUsage, fmt.Errorf("no text content in Anthropic response (stop_reason: %s, content_blocks: %d)", anMsg.StopReason, len(anMsg.Content))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return "", nil, fmt.Errorf("no choices in response")
	}
	usage = chatResp.Usage
	if usage != nil {
		usage.HasCachedTokens = usage.hasAnyCachedField()
		// Redacted structure diagnostic: which usage fields did MiniMax
		// actually return? Names only, once per process.
		var envelope struct {
			Usage json.RawMessage `json:"usage"`
		}
		if json.Unmarshal(respBody, &envelope) == nil {
			c.logMiniMaxUsageShape(envelope.Usage, "non-streaming")
		}
		cached := usage.GetCachedTokens()
		c.mu.Lock()
		c.totalIn += usage.PromptTokens
		c.totalOut += usage.CompletionTokens
		c.totalCached += cached
		c.mu.Unlock()
	}
	choice := chatResp.Choices[0]
	calls := parseOpenAIToolCalls(choice.Message.ToolCalls)
	if callsOut != nil {
		*callsOut = calls
	}
	content := string(choice.Message.Content)
	if strings.TrimSpace(content) == "" && len(calls) == 0 {
		// An empty completion is otherwise indistinguishable from a model
		// that chose to say nothing. Surface gateway-reported failures as
		// errors and record why the rest came back empty.
		if msg := choiceErrorMessage(choice.Error); msg != "" {
			return "", usage, fmt.Errorf("provider returned an error inside the completion (finish_reason: %s): %s", choice.FinishReason, msg)
		}
		completionTokens := 0
		if usage != nil {
			completionTokens = usage.CompletionTokens
		}
		log.Printf("[llm] Empty completion from %s (model=%s, finish_reason=%q, native_finish_reason=%q, refusal=%t, reasoning=%t, completion_tokens=%d)",
			endpoint, model, choice.FinishReason, choice.NativeFinishReason, hasRawContent(choice.Message.Refusal),
			hasRawContent(choice.Message.Reasoning) || hasRawContent(choice.Message.ReasoningContent), completionTokens)
	}
	return content, usage, nil
}
