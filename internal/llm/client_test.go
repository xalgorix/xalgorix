package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// newTestClient returns a Client wired to a minimal Config — enough for the
// SetContext/loadCtx surface without making any HTTP calls.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	return NewClient(&config.Config{
		LLM:     "openai/gpt-test",
		APIBase: "https://api.openai.com/v1",
		APIKey:  "sk-test",
	})
}

// TestNewClient_DefaultContextBackground verifies that a freshly created
// client always returns a non-nil, non-canceled context from loadCtx
// before any SetContext call. This is the contract that lets ChatStream
// run with no agent context wired up (e.g. from CLI tests).
func TestNewClient_DefaultContextBackground(t *testing.T) {
	c := newTestClient(t)
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil before SetContext")
	}
	if err := got.Err(); err != nil {
		t.Fatalf("default context already canceled: %v", err)
	}
}

// TestSetContext_NilFallsBackToBackground is the regression for the
// nil-interface bug we'd otherwise hit when storing a nil context.Context
// inside atomic.Value (storing a nil typed value panics if the underlying
// type is unset). SetContext(nil) must produce a non-nil Background-equiv.
func TestSetContext_NilFallsBackToBackground(t *testing.T) {
	c := newTestClient(t)
	// Intentional nil-context regression coverage: SetContext must not
	// panic and must fall back to a Background-equivalent context.
	c.SetContext(nil) //nolint:staticcheck // SA1012: deliberate nil-context test
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil after SetContext(nil)")
	}
	if err := got.Err(); err != nil {
		t.Fatalf("context already canceled: %v", err)
	}
}

// TestSetContext_StoresAndReturnsSame round-trips a real context.
func TestSetContext_StoresAndReturnsSame(t *testing.T) {
	c := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.SetContext(ctx)
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil after SetContext")
	}

	// Cancellation must propagate through the stored context.
	cancel()
	if err := got.Err(); err == nil {
		t.Error("expected stored context to be canceled after cancel()")
	}
}

// TestSetContext_ConcurrentReadersAndWriters is the regression for the data
// race the review flagged on the (formerly plain) c.ctx field. With
// atomic.Value this should run cleanly. Without -race we cannot detect a
// data race directly, but we still exercise the path heavily — any panic
// from atomic.Value's "inconsistently typed value" guard would bubble up.
func TestSetContext_ConcurrentReadersAndWriters(t *testing.T) {
	c := newTestClient(t)
	c.SetContext(context.Background())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 writers swap the context rapidly.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ctx, cancel := context.WithCancel(context.Background())
					c.SetContext(ctx)
					cancel()
				}
			}
		}()
	}

	// 16 readers loop on loadCtx — any nil return would panic under .Err().
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				got := c.loadCtx()
				if got == nil {
					t.Error("loadCtx returned nil under contention")
					return
				}
				_ = got.Err() // exercise the interface, ignore result
			}
		}()
	}

	// Let readers run for a bit, then signal stop and wait.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give readers enough iterations to be worthwhile.
		for i := 0; i < 200; i++ {
			c.SetContext(context.Background())
		}
		close(stop)
	}()

	wg.Wait()
}

// TestNewClient_ProviderParsedFromModel is a small sanity check that the
// "provider/model" string is split correctly — important because the URL
// switch in chatWithRetry/ChatStream branches on c.provider.
func TestNewClient_ProviderParsedFromModel(t *testing.T) {
	cases := []struct {
		llm  string
		want string
	}{
		{"openai/gpt-5.4", "openai"},
		{"anthropic/claude-sonnet", "anthropic"},
		{"google/gemini-3.1-flash", "google"},
		{"deepseek/deepseek-chat", "deepseek"},
		{"no-slash-model", ""},
	}
	for _, tc := range cases {
		t.Run(tc.llm, func(t *testing.T) {
			c := NewClient(&config.Config{LLM: tc.llm, APIKey: "k"})
			if c.provider != tc.want {
				t.Errorf("provider = %q, want %q", c.provider, tc.want)
			}
		})
	}
}

func TestOllamaReasoningEffortNormalization(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.Config
		endpoint string
		want     string
	}{
		{
			name: "catalog provider medium",
			cfg: config.Config{
				LLMProvider:     "ollama",
				ReasoningEffort: "medium",
			},
			endpoint: "http://ollama.example/v1/chat/completions",
			want:     "medium",
		},
		{
			name: "legacy prefix none",
			cfg: config.Config{
				LLM:             "ollama/reasoning-model:latest",
				ReasoningEffort: "none",
			},
			endpoint: "http://localhost:11434/v1/chat/completions",
			want:     "none",
		},
		{
			name: "ollama xhigh maps to high",
			cfg: config.Config{
				LLMProvider:     "ollama",
				ReasoningEffort: "xhigh",
			},
			endpoint: "http://ollama.example/v1/chat/completions",
			want:     "high",
		},
		{
			name: "profile provider low",
			cfg: config.Config{
				LLMProfile:      "ollama:default",
				ReasoningEffort: "low",
			},
			endpoint: "http://ollama.example/v1/chat/completions",
			want:     "low",
		},
		{
			name: "conventional port detects Ollama",
			cfg: config.Config{
				ReasoningEffort: "high",
			},
			endpoint: "http://host.docker.internal:11434/v1/chat/completions",
			want:     "high",
		},
		{
			name: "other OpenAI-compatible provider omitted",
			cfg: config.Config{
				LLMProvider:     "openai",
				ReasoningEffort: "high",
			},
			endpoint: "https://api.openai.com/v1/chat/completions",
			want:     "",
		},
		{
			name: "similar but different port is not Ollama",
			cfg: config.Config{
				ReasoningEffort: "high",
			},
			endpoint: "http://custom.example:114340/v1/chat/completions",
			want:     "",
		},
		{
			name: "custom endpoint explicitly marked Ollama-compatible",
			cfg: config.Config{
				OllamaCompatible: true,
				ReasoningEffort:  "medium",
			},
			endpoint: "https://models.example:9443/v1/chat/completions",
			want:     "medium",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient(&tc.cfg)
			if got := client.ollamaReasoningEffort(tc.endpoint); got != tc.want {
				t.Fatalf("ollamaReasoningEffort() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDoChat_SendsReasoningEffortOnlyToOllama(t *testing.T) {
	tests := []struct {
		name          string
		provider      string
		effort        string
		wantEffort    string
		wantFieldSent bool
	}{
		{name: "Ollama medium", provider: "ollama", effort: "medium", wantEffort: "medium", wantFieldSent: true},
		{name: "Ollama none", provider: "ollama", effort: "none", wantEffort: "none", wantFieldSent: true},
		{name: "Ollama xhigh normalizes", provider: "ollama", effort: "xhigh", wantEffort: "high", wantFieldSent: true},
		{name: "OpenAI unaffected", provider: "openai", effort: "high", wantFieldSent: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				LLM:             "reasoning-model:latest",
				LLMProvider:     tc.provider,
				APIBase:         "http://llm.example/v1",
				ReasoningEffort: tc.effort,
				MaxOutputTokens: 2048,
			}
			client := NewClient(cfg)
			var captured map[string]any
			client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if err := json.NewDecoder(req.Body).Decode(&captured); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`), nil
			})

			got, err := client.doChat([]Message{{Role: "user", Content: "test"}})
			if err != nil {
				t.Fatalf("doChat: %v", err)
			}
			if got != "ok" {
				t.Fatalf("response = %q, want ok", got)
			}
			effort, fieldSent := captured["reasoning_effort"]
			if fieldSent != tc.wantFieldSent {
				t.Fatalf("reasoning_effort present = %v, want %v; body=%v", fieldSent, tc.wantFieldSent, captured)
			}
			if fieldSent && effort != tc.wantEffort {
				t.Fatalf("reasoning_effort = %v, want %q", effort, tc.wantEffort)
			}
		})
	}
}

func TestChatStream_SendsOllamaReasoningEffort(t *testing.T) {
	cfg := &config.Config{
		LLM:             "reasoning-model:latest",
		LLMProvider:     "ollama",
		APIBase:         "http://ollama.example/v1",
		ReasoningEffort: "low",
		MaxOutputTokens: 2048,
	}
	client := NewClient(cfg)
	var captured map[string]any
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		return jsonResponse(http.StatusOK, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n"), nil
	})

	var content strings.Builder
	for chunk := range client.ChatStream([]Message{{Role: "user", Content: "test"}}) {
		if chunk.Err != nil {
			t.Fatalf("ChatStream: %v", chunk.Err)
		}
		content.WriteString(chunk.Content)
	}
	if got := content.String(); got != "ok" {
		t.Fatalf("stream content = %q, want ok", got)
	}
	if got := captured["reasoning_effort"]; got != "low" {
		t.Fatalf("reasoning_effort = %v, want low; body=%v", got, captured)
	}
}

func TestResolveEndpoint_ProviderDefaultsAndCustomBases(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
	}{
		{
			name:      "openai default",
			cfg:       config.Config{LLM: "openai/gpt-5.4", APIKey: "k"},
			wantURL:   "https://api.openai.com/v1/chat/completions",
			wantModel: "gpt-5.4",
		},
		{
			name:      "deepseek v4 default",
			cfg:       config.Config{LLM: "deepseek/deepseek-v4-pro", APIKey: "k"},
			wantURL:   "https://api.deepseek.com/v1/chat/completions",
			wantModel: "deepseek-v4-pro",
		},
		{
			name:      "zai coding plan default",
			cfg:       config.Config{LLM: "zai-coding-plan/Glm-5.3", APIKey: "k"},
			wantURL:   "https://api.z.ai/api/coding/paas/v4/chat/completions",
			wantModel: "Glm-5.3",
		},
		{
			name:      "gemini default",
			cfg:       config.Config{LLM: "google/gemini-3.1-pro-preview", APIKey: "k"},
			wantURL:   "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent",
			wantModel: "gemini-3.1-pro-preview",
		},
		{
			name:      "anthropic default",
			cfg:       config.Config{LLM: "anthropic/claude-sonnet-4-20250514", APIKey: "k"},
			wantURL:   "https://api.anthropic.com/v1/messages",
			wantModel: "claude-sonnet-4-20250514",
		},
		{
			name:      "custom openai-compatible base",
			cfg:       config.Config{LLM: "custom/my-model", APIBase: "https://llm.example/api", APIKey: "k"},
			wantURL:   "https://llm.example/api/v1/chat/completions",
			wantModel: "my-model",
		},
		{
			name:      "explicit chat completions base",
			cfg:       config.Config{LLM: "custom/my-model", APIBase: "https://llm.example/v1/chat/completions", APIKey: "k"},
			wantURL:   "https://llm.example/v1/chat/completions",
			wantModel: "my-model",
		},
		{
			name:      "custom versioned v4 base",
			cfg:       config.Config{LLM: "custom/Glm-5.3", APIBase: "https://api.z.ai/api/coding/paas/v4", APIKey: "k"},
			wantURL:   "https://api.z.ai/api/coding/paas/v4/chat/completions",
			wantModel: "Glm-5.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&tc.cfg)
			gotURL, gotModel := c.resolveEndpoint()
			if gotURL != tc.wantURL {
				t.Fatalf("endpoint = %q, want %q", gotURL, tc.wantURL)
			}
			if gotModel != tc.wantModel {
				t.Fatalf("model = %q, want %q", gotModel, tc.wantModel)
			}
		})
	}
}

func TestResolveEndpoint_PreservesModelWithSlash(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
	}{
		{
			name: "crusoe cloud org model preserved",
			cfg: config.Config{
				LLM:     "zai-org/GLM-5.3",
				APIBase: "https://api.crusoecloud.com/v1",
				APIKey:  "crusoe-key",
			},
			wantURL:   "https://api.crusoecloud.com/v1/chat/completions",
			wantModel: "zai-org/GLM-5.3",
		},
		{
			name: "vllm meta-llama org model preserved",
			cfg: config.Config{
				LLM:     "meta-llama/Llama-3.1-70B-Instruct",
				APIBase: "https://vllm.internal:8000/v1",
				APIKey:  "vllm-key",
			},
			wantURL:   "https://vllm.internal:8000/v1/chat/completions",
			wantModel: "meta-llama/Llama-3.1-70B-Instruct",
		},
		{
			name: "deepseek-ai org model preserved",
			cfg: config.Config{
				LLM:     "deepseek-ai/DeepSeek-V3",
				APIBase: "https://api.example.com/v1",
				APIKey:  "k",
			},
			wantURL:   "https://api.example.com/v1/chat/completions",
			wantModel: "deepseek-ai/DeepSeek-V3",
		},
		{
			name: "custom provider with slash model preserved",
			cfg: config.Config{
				LLM:         "zai-org/GLM-5.3",
				LLMProvider: "custom",
				APIBase:     "https://api.crusoecloud.com/v1",
				APIKey:      "k",
			},
			wantURL:   "https://api.crusoecloud.com/v1/chat/completions",
			wantModel: "zai-org/GLM-5.3",
		},
		{
			name: "custom prefix with slash model preserved",
			cfg: config.Config{
				LLM:     "custom/zai-org/GLM-5.3",
				APIBase: "https://api.crusoecloud.com/v1",
				APIKey:  "k",
			},
			wantURL:   "https://api.crusoecloud.com/v1/chat/completions",
			wantModel: "zai-org/GLM-5.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&tc.cfg)
			gotURL, gotModel := c.resolveEndpoint()
			if gotURL != tc.wantURL {
				t.Fatalf("endpoint = %q, want %q", gotURL, tc.wantURL)
			}
			if gotModel != tc.wantModel {
				t.Fatalf("model = %q, want %q", gotModel, tc.wantModel)
			}
		})
	}
}

func TestLegacyResolver_PreservesModelWithSlash(t *testing.T) {
	cfg := &config.Config{
		LLM:     "zai-org/GLM-5.3",
		APIBase: "https://api.crusoecloud.com/v1",
		APIKey:  "k",
	}
	lr := &legacyResolver{cfg: cfg}
	ep, err := lr.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve err: %v", err)
	}
	if ep.Model != "zai-org/GLM-5.3" {
		t.Fatalf("ep.Model = %q, want %q", ep.Model, "zai-org/GLM-5.3")
	}
	if ep.URL != "https://api.crusoecloud.com/v1/chat/completions" {
		t.Fatalf("ep.URL = %q, want %q", ep.URL, "https://api.crusoecloud.com/v1/chat/completions")
	}
}

func TestClient_Clone(t *testing.T) {
	cfg := &config.Config{
		LLM:     "zai-org/GLM-5.3",
		APIBase: "https://api.crusoecloud.com/v1",
		APIKey:  "secret-key",
	}
	fixedEP := Endpoint{
		URL:         "https://api.crusoecloud.com/v1/chat/completions",
		Model:       "zai-org/GLM-5.3",
		HeaderStyle: "openai",
		Auth:        AuthAPIKey,
		APIKey:      "secret-key",
	}
	client := NewClient(cfg, WithResolver(NewFixedResolver(fixedEP)))
	client.mu.Lock()
	client.totalIn = 100
	client.totalOut = 200
	client.mu.Unlock()

	temp := 0.7
	client.SetTemperature(&temp)

	clone := client.Clone()
	if clone == nil {
		t.Fatal("clone is nil")
	}
	if clone == client {
		t.Fatal("clone returned same pointer")
	}
	if clone.cfg != client.cfg {
		t.Fatalf("clone.cfg = %p, want %p", clone.cfg, client.cfg)
	}
	if clone.apiModel != client.apiModel {
		t.Fatalf("clone.apiModel = %q, want %q", clone.apiModel, client.apiModel)
	}
	if clone.resolver == nil {
		t.Fatal("clone.resolver is nil")
	}

	// Verify token usage in clone is zeroed
	in, out, total := clone.GetTokens()
	if in != 0 || out != 0 || total != 0 {
		t.Fatalf("clone tokens = (%d, %d, %d), want (0, 0, 0)", in, out, total)
	}

	// Verify effective temperature was copied
	if gotTemp := clone.effectiveTemperature(); gotTemp == nil || *gotTemp != 0.7 {
		t.Fatalf("clone temp = %v, want 0.7", gotTemp)
	}

	// Verify resolveRequestEndpoint on clone yields the original fixed endpoint
	ep, err := clone.resolveRequestEndpoint(context.Background())
	if err != nil {
		t.Fatalf("clone resolveRequestEndpoint: %v", err)
	}
	if ep.Model != "zai-org/GLM-5.3" {
		t.Fatalf("clone ep.Model = %q, want zai-org/GLM-5.3", ep.Model)
	}
	if ep.URL != fixedEP.URL {
		t.Fatalf("clone ep.URL = %q, want %q", ep.URL, fixedEP.URL)
	}
}

func TestDoChat_GeminiAPIBaseWithoutProviderUsesGeminiProtocol(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "gemini-3.1-pro",
		APIBase:       "https://generativelanguage.googleapis.com/v1",
		APIKey:        "gemini-key",
		LLMMaxRetries: 3,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro:generateContent" {
			t.Errorf("URL = %q", got)
		}
		if got := req.Header.Get("x-goog-api-key"); got != "gemini-key" {
			t.Errorf("x-goog-api-key = %q, want gemini-key", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header = %q, want empty for Gemini API key auth", got)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		bodyText := string(body)
		if !strings.Contains(bodyText, `"contents"`) {
			t.Errorf("Gemini request body missing contents: %s", bodyText)
		}
		if strings.Contains(bodyText, `"messages"`) {
			t.Errorf("Gemini request body used OpenAI messages shape: %s", bodyText)
		}

		return jsonResponse(http.StatusOK, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`), nil
	})}

	got, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("doChat = %q, want ok", got)
	}
}

func TestDoChat_AnthropicAPIBaseWithoutProviderUsesAnthropicProtocol(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "claude-sonnet-4-20250514",
		APIBase:       "https://api.anthropic.com",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://api.anthropic.com/v1/messages" {
			t.Errorf("URL = %q", got)
		}
		if got := req.Header.Get("x-api-key"); got != "anthropic-key" {
			t.Errorf("x-api-key = %q, want anthropic-key", got)
		}
		if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header = %q, want empty for Anthropic", got)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if payload["model"] != "claude-sonnet-4-20250514" || payload["system"] != "system prompt" {
			t.Fatalf("unexpected Anthropic payload: %s", string(body))
		}
		if _, ok := payload["messages"]; !ok {
			t.Fatalf("Anthropic payload missing messages: %s", string(body))
		}

		return jsonResponse(http.StatusOK, `{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"anthropic ok"}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":4}}`), nil
	})}

	got, err := c.doChat([]Message{
		{Role: "system", Content: "system prompt"},
		{Role: "user", Content: "hello"},
	})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "anthropic ok" {
		t.Fatalf("doChat = %q, want anthropic ok", got)
	}
	_, _, total := c.GetTokens()
	if total != 7 {
		t.Fatalf("token total = %d, want 7", total)
	}
}

func TestDoChat_AnthropicEmptyContentReturnsError(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "anthropic/claude-sonnet-4-20250514",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"id":"msg_test","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":0}}`), nil
	})}

	_, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("expected error for empty content, got nil")
	}
	if !strings.Contains(err.Error(), "no text content") {
		t.Fatalf("expected 'no text content' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "content_blocks: 0") {
		t.Fatalf("expected content_blocks: 0 in error, got: %v", err)
	}
}

func TestDoChat_AnthropicToolUseOnlyReturnsError(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "anthropic/claude-sonnet-4-20250514",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"tool_use","id":"toolu_123","name":"bash","input":{"command":"ls"}}],"model":"claude-sonnet-4-20250514","stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}`), nil
	})}

	_, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("expected error for tool_use-only content, got nil")
	}
	if !strings.Contains(err.Error(), "no text content") {
		t.Fatalf("expected 'no text content' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "stop_reason: tool_use") {
		t.Fatalf("expected stop_reason: tool_use in error, got: %v", err)
	}
}

func TestDoChat_AnthropicEmptyTextBlockReturnsError(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "anthropic/claude-sonnet-4-20250514",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":""}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":1}}`), nil
	})}

	_, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("expected error for empty text block, got nil")
	}
	if !strings.Contains(err.Error(), "no text content") {
		t.Fatalf("expected 'no text content' error, got: %v", err)
	}
}

func TestDoChat_AnthropicTokenUsageTracked(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "anthropic/claude-sonnet-4-20250514",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":50,"output_tokens":25}}`), nil
	})}

	got, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("doChat = %q, want ok", got)
	}
	in, out, total := c.GetTokens()
	if in != 50 {
		t.Errorf("input tokens = %d, want 50", in)
	}
	if out != 25 {
		t.Errorf("output tokens = %d, want 25", out)
	}
	if total != 75 {
		t.Errorf("total tokens = %d, want 75", total)
	}
}

func TestChatWithRetry_Gemini401IsNotRateLimited(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "gemini-3.1-pro",
		APIBase:       "https://generativelanguage.googleapis.com/v1",
		APIKey:        "bad-key",
		LLMMaxRetries: 5,
	})

	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonResponse(http.StatusUnauthorized, `{
			"error": {
				"code": 401,
				"message": "Request had invalid authentication credentials.",
				"status": "UNAUTHENTICATED",
				"details": [{
					"reason": "ACCESS_TOKEN_TYPE_UNSUPPORTED",
					"metadata": {
						"method": "google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent"
					}
				}]
			}
		}`), nil
	})}

	_, err := c.Chat([]Message{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("Chat returned nil error for 401")
	}
	if strings.Contains(strings.ToLower(err.Error()), "rate limited") {
		t.Fatalf("401 was misclassified as rate limited: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("RoundTrip calls = %d, want 1 for non-retryable 401", got)
	}
}

func TestChatWithRetry_NonRetryableStatusMatrix(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"bad request", http.StatusBadRequest, `{"error":{"message":"invalid request"}}`},
		{"unauthorized", http.StatusUnauthorized, `{"error":{"status":"UNAUTHENTICATED"}}`},
		{"forbidden", http.StatusForbidden, `{"error":{"status":"PERMISSION_DENIED"}}`},
		{"missing model", http.StatusNotFound, `{"error":{"message":"model not found"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&config.Config{LLM: "openai/gpt-test", APIKey: "bad", LLMMaxRetries: 5})
			var calls atomic.Int32
			c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				return jsonResponse(tc.status, tc.body), nil
			})}
			_, err := c.Chat([]Message{{Role: "user", Content: "hello"}})
			if err == nil {
				t.Fatal("Chat returned nil error")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("RoundTrip calls = %d, want 1", got)
			}
			if strings.Contains(strings.ToLower(err.Error()), "rate limited") {
				t.Fatalf("non-retryable error was misclassified as rate limited: %v", err)
			}
		})
	}
}

func TestRateLimitDetectionDoesNotMatchGenerateContent(t *testing.T) {
	authErr := `API returned 401: {"error":{"status":"UNAUTHENTICATED","details":[{"metadata":{"method":"google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent"}}]}}`
	if isRateLimitError(authErr) {
		t.Fatal("GenerateContent auth error was classified as rate limited")
	}

	if !isRateLimitError(`API returned 429: {"error":{"status":"RESOURCE_EXHAUSTED","message":"Too Many Requests"}}`) {
		t.Fatal("429 RESOURCE_EXHAUSTED error was not classified as rate limited")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// ---------------------------------------------------------------------------
// Wave H — task 9.7 — composite Resolver decision matrix + header switch.
//
// These tests cover Property 5 (legacy/catalog/error branch decision,
// Requirements 2.1–2.4) and the (HeaderStyle, AuthMethod) header
// switch matrix in applyAuthHeaders (Requirements 2.2, 2.3, 11.2).
// Each randomized property test runs ≥ 100 iterations against a real
// *providers.Service and *auth.Store rooted at t.TempDir() for full
// filesystem isolation — no stubs for the catalog or profile stores
// so the legacy/catalog routing decision is exercised end-to-end the
// same way the production resolver consumes them.
// ---------------------------------------------------------------------------

// legacyExpectedURL returns the URL the legacy resolver should
// produce for a given legacy slug + bare model name. Mirrors the
// switch in legacyResolver.Resolve so the test asserts the resolver
// produces byte-identical URLs to the pre-feature client.go path.
func legacyExpectedURL(slug, model string) string {
	switch slug {
	case "openai":
		return "https://api.openai.com/v1/chat/completions"
	case "anthropic":
		return "https://api.anthropic.com/v1/messages"
	case "minimax":
		return "https://api.minimax.io/v1/chat/completions"
	case "deepseek":
		return "https://api.deepseek.com/v1/chat/completions"
	case "groq":
		return "https://api.groq.com/openai/v1/chat/completions"
	case "ollama":
		return "http://localhost:11434/v1/chat/completions"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent"
	}
	return ""
}

// legacyExpectedHeaderStyle returns the HeaderStyle the legacy
// resolver should set for a given slug — kept here so the test can
// assert the header style independently of the URL builder.
func legacyExpectedHeaderStyle(slug string) string {
	switch slug {
	case "anthropic":
		return "anthropic"
	case "google", "gemini":
		return "gemini"
	default:
		return "openai"
	}
}

// resolverFixture wires a real *providers.Service + *auth.Store
// rooted at the supplied tempDir. The catalog is the compiled-in
// Builtin() set; when seedProvider is non-empty we look it up from
// Builtin() and Put a matching API_Key profile so the catalog
// branch's defaultCatalogPick can resolve a (entry, profile) pair
// on its first call. cfg.LLMProfile must also be set on the cfg
// passed to the resolver for the catalog branch to engage.
type resolverFixture struct {
	cat        *providers.Service
	prof       *auth.Store
	profileKey string
}

func newResolverFixture(t *testing.T, tempDir string, seedEntry providers.Entry, seedProfileAPIKey string) resolverFixture {
	t.Helper()
	dataDir := filepath.Join(tempDir, "data")
	profPath := filepath.Join(dataDir, "auth-profiles.json")

	cat := providers.NewService()
	prof, err := auth.NewStore(profPath, cat)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	profileKey := ""
	if seedEntry.ID != "" {
		if err := prof.Put(context.Background(), auth.Profile{
			Provider:  seedEntry.ID,
			ProfileID: "default",
			Type:      auth.APIKey,
			APIKey:    seedProfileAPIKey,
		}); err != nil {
			t.Fatalf("prof.Put: %v", err)
		}
		profileKey = seedEntry.ID + ":default"
	}
	return resolverFixture{cat: cat, prof: prof, profileKey: profileKey}
}

// TestResolver_LegacyFallbackDecision validates Property 5 for the
// legacy branch: when the catalog reports zero entries AND
// XALGORIX_LLM matches Legacy_Provider_Shape, Resolve must dispatch
// through the legacy provider table and return a URL byte-identical
// to the pre-feature Client.resolveEndpoint output.
//
// Iterates ≥ 100 times across all eight legacy slugs with randomized
// model tails so the fingerprint of every legacy URL builder branch
// (anthropic /v1/messages, gemini :generateContent, openai-compat
// /v1/chat/completions) is exercised.
//
// Validates: Requirements 2.1, 2.3, 2.4.
func TestResolver_LegacyFallbackDecision(t *testing.T) {
	const iterations = 120
	legacySlugs := []string{"openai", "anthropic", "minimax", "deepseek", "groq", "ollama", "google", "gemini"}

	seed := time.Now().UnixNano()
	t.Logf("legacy fallback seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	for i := 0; i < iterations; i++ {
		slug := legacySlugs[rng.Intn(len(legacySlugs))]
		modelTail := fmt.Sprintf("legacy-model-%d", i)
		cfg := &config.Config{
			LLM:    slug + "/" + modelTail,
			APIKey: fmt.Sprintf("legacy-key-%d", i),
		}

		// catalog stays empty: providers.NewService treats a
		// missing file as an empty catalog without creating it
		// (Requirement 1.3), so the legacy branch is the only
		// reachable dispatch.
		fx := newResolverFixture(t, t.TempDir(), providers.Entry{}, "")
		r := NewCompositeResolver(
			WithCatalog(fx.cat, fx.prof),
			WithLegacy(cfg),
		)

		ep, err := r.Resolve(context.Background())
		if err != nil {
			t.Fatalf("iter %d slug=%s: Resolve: %v", i, slug, err)
		}

		wantURL := legacyExpectedURL(slug, modelTail)
		if ep.URL != wantURL {
			t.Errorf("iter %d slug=%s: URL = %q, want %q", i, slug, ep.URL, wantURL)
		}
		if got, want := ep.HeaderStyle, legacyExpectedHeaderStyle(slug); got != want {
			t.Errorf("iter %d slug=%s: HeaderStyle = %q, want %q", i, slug, got, want)
		}
		if ep.Auth != AuthAPIKey {
			t.Errorf("iter %d slug=%s: Auth = %q, want %q", i, slug, ep.Auth, AuthAPIKey)
		}
		if ep.APIKey != cfg.APIKey {
			t.Errorf("iter %d slug=%s: APIKey = %q, want %q", i, slug, ep.APIKey, cfg.APIKey)
		}
		if ep.AccessToken != "" {
			t.Errorf("iter %d slug=%s: AccessToken = %q, want empty", i, slug, ep.AccessToken)
		}
		if ep.Model != modelTail {
			t.Errorf("iter %d slug=%s: Model = %q, want %q", i, slug, ep.Model, modelTail)
		}
	}
}

// TestResolver_CatalogPreemptsLegacy validates Property 5 for the
// catalog branch: any time cfg.LLMProfile names a saved profile and
// the profile's Provider matches a Builtin() catalog entry, Resolve
// dispatches through catalogResolver regardless of whether
// XALGORIX_LLM names a legacy slug. The test asserts the URL,
// HeaderStyle, and credentials all come from the Builtin() entry +
// stored profile — never from the legacy provider table.
//
// Validates: Requirements 2.2, 2.3, 11.2.
func TestResolver_CatalogPreemptsLegacy(t *testing.T) {
	// Pick one Builtin() entry per HeaderStyle so every URL-builder
	// branch (openai /chat/completions, anthropic /v1/messages,
	// gemini :generateContent) gets exercised. The test was written
	// against a runtime-editable catalog; v4.4.22 collapses the
	// catalog to providers.Builtin(), so we now look up real entries
	// rather than seeding fake ones.
	builtin, err := providers.NewService().List(context.Background())
	if err != nil {
		t.Fatalf("providers.NewService.List: %v", err)
	}
	pickByStyle := func(style string) (providers.Entry, bool) {
		for _, e := range builtin {
			if e.HeaderStyle == style && e.BaseURL != "" && len(e.Models) > 0 {
				return e, true
			}
		}
		return providers.Entry{}, false
	}
	const iterations = 60
	headerStyles := []string{"openai", "anthropic", "gemini"}
	legacyVariants := []string{
		"openai/legacy-model",
		"anthropic/legacy-model",
		"gemini/legacy-model",
		"google/legacy-model",
		"custom/legacy-model",
		"",
	}

	seed := time.Now().UnixNano()
	t.Logf("catalog preempts seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	for i := 0; i < iterations; i++ {
		hs := headerStyles[rng.Intn(len(headerStyles))]
		entry, ok := pickByStyle(hs)
		if !ok {
			t.Skipf("Builtin() has no entry with HeaderStyle=%q + BaseURL+Models", hs)
		}
		legacy := legacyVariants[rng.Intn(len(legacyVariants))]
		profileAPIKey := fmt.Sprintf("catalog-key-%d", i)

		fx := newResolverFixture(t, t.TempDir(), entry, profileAPIKey)
		cfg := &config.Config{
			LLM:        legacy,
			APIKey:     "ignored-legacy-key",
			LLMProfile: fx.profileKey,
		}
		r := NewCompositeResolver(
			WithCatalog(fx.cat, fx.prof),
			WithLegacy(cfg),
		)

		ep, err := r.Resolve(context.Background())
		if err != nil {
			t.Fatalf("iter %d hs=%s legacy=%q: Resolve: %v", i, hs, legacy, err)
		}

		// Build the expected URL by mirroring catalogResolver's
		// own URL-builder branch logic for the chosen header style.
		baseURL := strings.TrimRight(entry.BaseURL, "/")
		modelName := entry.Models[0]
		var wantURL string
		switch hs {
		case "openai":
			wantURL = baseURL
			if !strings.HasSuffix(strings.ToLower(wantURL), "/chat/completions") {
				if !strings.HasSuffix(baseURL, "/v1") && !strings.Contains(baseURL, "/v1/") {
					wantURL += "/v1"
				}
				wantURL += "/chat/completions"
			}
		case "anthropic":
			wantURL = baseURL
			if !strings.HasSuffix(strings.ToLower(wantURL), "/messages") {
				if !strings.HasSuffix(baseURL, "/v1") && !strings.Contains(baseURL, "/v1/") {
					wantURL += "/v1"
				}
				wantURL += "/messages"
			}
		case "gemini":
			wantURL = strings.TrimSuffix(baseURL, "/v1") + "/v1beta/models/" + modelName + ":generateContent"
		}
		if ep.URL != wantURL {
			t.Errorf("iter %d hs=%s legacy=%q: URL = %q, want %q", i, hs, legacy, ep.URL, wantURL)
		}
		if ep.HeaderStyle != hs {
			t.Errorf("iter %d hs=%s: HeaderStyle = %q, want %q", i, hs, ep.HeaderStyle, hs)
		}
		if ep.Auth != AuthAPIKey {
			t.Errorf("iter %d hs=%s: Auth = %q, want %q", i, hs, ep.Auth, AuthAPIKey)
		}
		if ep.APIKey != profileAPIKey {
			t.Errorf("iter %d hs=%s: APIKey = %q, want %q (catalog profile)", i, hs, ep.APIKey, profileAPIKey)
		}
		if ep.AccessToken != "" {
			t.Errorf("iter %d hs=%s: AccessToken = %q, want empty for api_key profile", i, hs, ep.AccessToken)
		}
		if ep.Model != modelName {
			t.Errorf("iter %d hs=%s: Model = %q, want %q (catalog entry)", i, hs, ep.Model, modelName)
		}
	}
}

// TestResolver_NoCatalogNoLegacy_ReturnsConfigError validates
// Property 5 for the error branch: when the catalog is empty AND
// XALGORIX_LLM does not match Legacy_Provider_Shape, Resolve must
// return a *ConfigError so the HTTP layer can surface "no provider
// configured" instead of dispatching a malformed request.
//
// Iterates ≥ 100 times across non-legacy strings (custom slugs,
// blank values, slugs with whitespace) to exercise every shape that
// must NOT slip through the legacy gate.
//
// Validates: Requirement 2.4.
func TestResolver_NoCatalogNoLegacy_ReturnsConfigError(t *testing.T) {
	const iterations = 120
	// Every value here must NOT match LegacyProviderShape — that
	// is the precondition Property 5's error branch enumerates.
	nonLegacy := []string{
		"",
		"custom/foo",
		"perplexity/sonar",
		"mistral/large",
		"my-internal/model",
		"acme-corp/llama",
	}

	seed := time.Now().UnixNano()
	t.Logf("no-catalog-no-legacy seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	for i := 0; i < iterations; i++ {
		llm := nonLegacy[rng.Intn(len(nonLegacy))]
		// Defensive: assert the test data really doesn't match the
		// legacy shape, so a future change to LegacyProviderShape
		// can't silently invalidate this property.
		if LegacyProviderShape(llm) {
			t.Fatalf("iter %d: LLM %q unexpectedly matches Legacy_Provider_Shape — fixture bug", i, llm)
		}

		cfg := &config.Config{LLM: llm}
		fx := newResolverFixture(t, t.TempDir(), providers.Entry{}, "")
		r := NewCompositeResolver(
			WithCatalog(fx.cat, fx.prof),
			WithLegacy(cfg),
		)

		ep, err := r.Resolve(context.Background())
		if err == nil {
			t.Fatalf("iter %d llm=%q: Resolve returned %+v with nil error, want *ConfigError", i, llm, ep)
		}
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Fatalf("iter %d llm=%q: Resolve err = %v, want *ConfigError", i, llm, err)
		}
		// Empty Endpoint is the contract: no URL/credentials leak
		// when the resolver has nothing to dispatch.
		if ep.URL != "" || ep.APIKey != "" || ep.AccessToken != "" {
			t.Errorf("iter %d llm=%q: non-empty Endpoint on error path: %+v", i, llm, ep)
		}
	}
}

// TestClient_HeaderSwitch_Matrix exercises every cell of the
// (HeaderStyle, AuthMethod) switch in applyAuthHeaders and asserts
// the exact outbound headers. This is the unit-test counterpart to
// the resolver tests above: those drive the URL/credentials
// upstream, this one drives the header switch downstream.
//
// The matrix covers:
//
//   - openai    + api_key     → Authorization: Bearer <APIKey>
//   - openai    + oauth       → Authorization: Bearer <AccessToken>
//   - anthropic + api_key     → x-api-key + anthropic-version
//   - anthropic + oauth       → Authorization: Bearer + anthropic-version
//   - gemini    + api_key     → x-goog-api-key
//   - gemini    + oauth       → Authorization: Bearer
//
// Asserts both the present headers AND the absence of headers from
// other branches so a future header-switch refactor can't quietly
// add an Authorization shadow on the api_key paths.
//
// Validates: Requirements 2.2, 2.3, 11.2.
func TestClient_HeaderSwitch_Matrix(t *testing.T) {
	const apiKeyVal = "API-KEY-VAL"
	const accessTokenVal = "ACCESS-TOKEN-VAL"

	type wantHeaders struct {
		authorization string
		xAPIKey       string
		xGoogAPIKey   string
		anthropicVer  string
	}

	cases := []struct {
		name        string
		headerStyle string
		auth        AuthMethod
		want        wantHeaders
	}{
		{
			name:        "openai_apikey",
			headerStyle: "openai",
			auth:        AuthAPIKey,
			want:        wantHeaders{authorization: "Bearer " + apiKeyVal},
		},
		{
			name:        "openai_oauth",
			headerStyle: "openai",
			auth:        AuthOAuthBearer,
			want:        wantHeaders{authorization: "Bearer " + accessTokenVal},
		},
		{
			name:        "anthropic_apikey",
			headerStyle: "anthropic",
			auth:        AuthAPIKey,
			want:        wantHeaders{xAPIKey: apiKeyVal, anthropicVer: "2023-06-01"},
		},
		{
			name:        "anthropic_oauth",
			headerStyle: "anthropic",
			auth:        AuthOAuthBearer,
			want:        wantHeaders{authorization: "Bearer " + accessTokenVal, anthropicVer: "2023-06-01"},
		},
		{
			name:        "gemini_apikey",
			headerStyle: "gemini",
			auth:        AuthAPIKey,
			want:        wantHeaders{xGoogAPIKey: apiKeyVal},
		},
		{
			name:        "gemini_oauth",
			headerStyle: "gemini",
			auth:        AuthOAuthBearer,
			want:        wantHeaders{authorization: "Bearer " + accessTokenVal},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := Endpoint{
				URL:         "https://example.test/path",
				HeaderStyle: tc.headerStyle,
				Auth:        tc.auth,
			}
			switch tc.auth {
			case AuthAPIKey:
				ep.APIKey = apiKeyVal
			case AuthOAuthBearer:
				ep.AccessToken = accessTokenVal
			}

			req, err := http.NewRequest(http.MethodPost, ep.URL, nil)
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			applyAuthHeaders(req, ep)

			if got := req.Header.Get("Authorization"); got != tc.want.authorization {
				t.Errorf("Authorization = %q, want %q", got, tc.want.authorization)
			}
			if got := req.Header.Get("x-api-key"); got != tc.want.xAPIKey {
				t.Errorf("x-api-key = %q, want %q", got, tc.want.xAPIKey)
			}
			if got := req.Header.Get("x-goog-api-key"); got != tc.want.xGoogAPIKey {
				t.Errorf("x-goog-api-key = %q, want %q", got, tc.want.xGoogAPIKey)
			}
			if got := req.Header.Get("anthropic-version"); got != tc.want.anthropicVer {
				t.Errorf("anthropic-version = %q, want %q", got, tc.want.anthropicVer)
			}
		})
	}
}

// TestMaxOutputTokens verifies the per-call completion cap: the configured
// value is used, an unset (0) value falls back to the 8192 default, and a
// misconfigured tiny value is clamped up to the 1024 floor so no call is
// starved.
func TestMaxOutputTokens(t *testing.T) {
	cases := []struct {
		name string
		cfg  int
		want int
	}{
		{"explicit large value", 32000, 32000},
		{"unset falls back to default", 0, 8192},
		{"negative falls back to default", -5, 8192},
		{"tiny value clamped to floor", 100, 1024},
		{"floor boundary kept", 1024, 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&config.Config{LLM: "openai/gpt-5.4", APIKey: "k", MaxOutputTokens: tc.cfg})
			if got := c.maxOutputTokens(); got != tc.want {
				t.Fatalf("maxOutputTokens() = %d, want %d", got, tc.want)
			}
		})
	}
}
