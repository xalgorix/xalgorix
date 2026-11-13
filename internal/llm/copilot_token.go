// Package llm — GitHub Copilot token exchange.
//
// Copilot is an OpenAI-compatible chat-completions backend
// (https://api.githubcopilot.com) gated behind a two-step auth
// handshake that the generic OpenAI path in client.go cannot do on
// its own:
//
//  1. The operator stores a GitHub credential — a device-code OAuth
//     token (the "copilot" provider's Flow == "device_code", the
//     recommended path) or a fine-grained PAT (github_pat_…) entered
//     as the API key.
//
//  2. That GitHub token is exchanged at
//     https://api.github.com/copilot_internal/v2/token for a
//     short-lived Copilot bearer JWT (~25 min). The exchange response
//     also advertises the API host for the account's plan.
//
//  3. Chat requests carry the Copilot bearer plus a small set of
//     editor-identifying headers; without a Copilot-Integration-Id
//     header the API answers 400.
//
// BuildCatalogEndpoint wires this in for entry.ID == "copilot" by
// attaching exchangeAndApply as the Endpoint.VendorOverride, so the
// exchange runs lazily at request time (honoring the request context
// and proxy settings) and the result is cached until shortly before
// expiry. Classic ghp_ PATs are rejected by Copilot and surface as a
// 4xx from the exchange.
package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// copilotTokenExchangeURL is GitHub's (undocumented but widely-used)
// endpoint that trades a GitHub token for a short-lived Copilot session
// token. A var, not a const, so tests can redirect it at a httptest
// server.
var copilotTokenExchangeURL = "https://api.github.com/copilot_internal/v2/token"

const (
	// copilotDefaultAPIBase is the OpenAI-compatible Copilot chat host
	// used when the exchange response does not advertise one.
	copilotDefaultAPIBase = "https://api.githubcopilot.com"

	// Editor identity headers. Copilot keys entitlement and routing off
	// the integration id; the version strings only need to be plausible.
	copilotEditorVersion       = "vscode/1.95.0"
	copilotEditorPluginVersion = "copilot-chat/0.26.7"

	// Integration ids. OAuth / GitHub-App tokens are accepted under the
	// editor id; fine-grained PATs must use the CLI id.
	copilotIntegrationEditor = "vscode-chat"
	copilotIntegrationCLI    = "copilot-developer-cli"

	// copilotTokenSkew refreshes a cached token this far before its
	// advertised expiry so an in-flight request never races expiry.
	copilotTokenSkew = 90 * time.Second
)

// copilotHTTPClient is a dedicated client for the exchange call. It
// honors HTTP(S)_PROXY via the default transport, matching the LLM
// client's proxy behavior, and bounds the handshake independently of
// the (streaming) chat request timeout.
var copilotHTTPClient = &http.Client{Timeout: 30 * time.Second}

// copilotIntegrationID picks the Copilot-Integration-Id header value
// for a GitHub credential. Fine-grained PATs (github_pat_…) are only
// accepted under the CLI integration id; OAuth user tokens (gho_),
// GitHub-App user tokens (ghu_) and anything else use the editor id.
func copilotIntegrationID(githubToken string) string {
	if strings.HasPrefix(strings.TrimSpace(githubToken), "github_pat_") {
		return copilotIntegrationCLI
	}
	return copilotIntegrationEditor
}

// cachedCopilotToken is one memoized exchange result. When direct is
// true the exchange was unavailable (e.g. Copilot Free) and callers
// should send the raw GitHub token as the Bearer — the path the
// official Copilot CLI uses; bearer/apiBase are then unset.
type cachedCopilotToken struct {
	bearer    string
	apiBase   string
	expiresAt time.Time
	direct    bool
}

// copilotDirectNegativeTTL is how long a "exchange unavailable, use the
// direct path" decision is cached before the exchange is retried (in
// case the account gains a Copilot seat that enables the exchange).
const copilotDirectNegativeTTL = 10 * time.Minute

// copilotTokenCache memoizes exchange results keyed by a hash of the
// source GitHub token, so a stable credential triggers one network
// handshake per ~25-minute window rather than one per chat request.
type copilotTokenCache struct {
	mu     sync.Mutex
	byHash map[string]cachedCopilotToken
}

func newCopilotTokenCache() *copilotTokenCache {
	return &copilotTokenCache{byHash: make(map[string]cachedCopilotToken)}
}

// defaultCopilotTokens is the process-wide cache.
var defaultCopilotTokens = newCopilotTokenCache()

func copilotTokenKey(githubToken string) string {
	sum := sha256.Sum256([]byte(githubToken))
	return hex.EncodeToString(sum[:])
}

// get returns a non-expired cached token for the credential, if any.
func (c *copilotTokenCache) get(githubToken string, now time.Time) (cachedCopilotToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.byHash[copilotTokenKey(githubToken)]
	if !ok {
		return cachedCopilotToken{}, false
	}
	if now.Add(copilotTokenSkew).After(tok.expiresAt) {
		return cachedCopilotToken{}, false
	}
	return tok, true
}

func (c *copilotTokenCache) put(githubToken string, tok cachedCopilotToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byHash[copilotTokenKey(githubToken)] = tok
}

// resolveBearer returns (bearer, apiBase): the Bearer token to send on a
// Copilot chat request, and the Copilot API host the exchange advertised
// for this account. bearer is the short-lived exchanged token when the
// exchange works, or the raw GitHub token (the Copilot CLI's direct
// path) when the exchange endpoint is unavailable — e.g. Copilot Free,
// which does not serve copilot_internal/v2/token. apiBase is non-empty
// only on the exchange path; it lets the caller repoint the request for
// Enterprise / data-residency tenants whose API host is not the default
// api.githubcopilot.com. Both outcomes are cached so a request never
// pays a failed exchange round-trip more than once per window. An empty
// credential returns ("", "").
func (c *copilotTokenCache) resolveBearer(ctx context.Context, githubToken string) (bearer, apiBase string) {
	if strings.TrimSpace(githubToken) == "" {
		return "", ""
	}
	if tok, ok := c.get(githubToken, time.Now()); ok {
		if tok.direct {
			return githubToken, ""
		}
		return tok.bearer, tok.apiBase
	}
	tok, err := exchangeCopilotToken(ctx, githubToken)
	if err != nil {
		// Exchange unavailable — negative-cache the direct decision,
		// then fall back to the direct-Bearer path.
		c.put(githubToken, cachedCopilotToken{direct: true, expiresAt: time.Now().Add(copilotDirectNegativeTTL)})
		return githubToken, ""
	}
	c.put(githubToken, tok)
	return tok.bearer, tok.apiBase
}

// copilotTokenResponse is the subset of the exchange response we read.
type copilotTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Endpoints struct {
		API string `json:"api"`
	} `json:"endpoints"`
}

// exchangeCopilotToken performs the GitHub → Copilot token handshake.
func exchangeCopilotToken(ctx context.Context, githubToken string) (cachedCopilotToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, copilotTokenExchangeURL, nil)
	if err != nil {
		return cachedCopilotToken{}, fmt.Errorf("copilot: build token request: %w", err)
	}
	// The exchange authenticates with the raw GitHub token (token
	// scheme, not Bearer) and wants the editor-identifying headers.
	req.Header.Set("Authorization", "token "+strings.TrimSpace(githubToken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GitHubCopilotChat/"+copilotEditorPluginVersion)
	req.Header.Set("Editor-Version", copilotEditorVersion)
	req.Header.Set("Editor-Plugin-Version", copilotEditorPluginVersion)
	req.Header.Set("Copilot-Integration-Id", copilotIntegrationID(githubToken))

	resp, err := copilotHTTPClient.Do(req)
	if err != nil {
		return cachedCopilotToken{}, fmt.Errorf("copilot: token exchange request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return cachedCopilotToken{}, copilotExchangeError(resp.StatusCode, githubToken, body)
	}

	var parsed copilotTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return cachedCopilotToken{}, fmt.Errorf("copilot: decode token response: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return cachedCopilotToken{}, fmt.Errorf("copilot: token exchange returned an empty token")
	}

	apiBase := copilotDefaultAPIBase
	if a := strings.TrimSpace(parsed.Endpoints.API); a != "" {
		apiBase = strings.TrimRight(a, "/")
	}
	expires := time.Now().Add(25 * time.Minute)
	if parsed.ExpiresAt > 0 {
		expires = time.Unix(parsed.ExpiresAt, 0)
	}
	return cachedCopilotToken{bearer: parsed.Token, apiBase: apiBase, expiresAt: expires}, nil
}

// copilotExchangeError turns a non-200 exchange into an actionable
// message, calling out the two most common misconfigurations: a
// classic ghp_ PAT (unsupported) and an account without Copilot.
func copilotExchangeError(status int, githubToken string, body []byte) error {
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 300 {
		snippet = snippet[:300] + "…"
	}
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		hint := "the GitHub credential was rejected"
		if strings.HasPrefix(strings.TrimSpace(githubToken), "ghp_") {
			hint = "classic ghp_ personal access tokens are not supported by Copilot — use device-code OAuth or a fine-grained github_pat_ token"
		}
		return fmt.Errorf("copilot: token exchange %d — %s (ensure the account has an active Copilot subscription): %s", status, hint, snippet)
	case status == http.StatusNotFound:
		return fmt.Errorf("copilot: token exchange 404 — no Copilot token could be minted for this credential. For a fine-grained PAT: it must be owned by your personal account (not an org) AND granted the \"Copilot Requests\" permission (off by default), and the account needs an active Copilot subscription: %s", snippet)
	default:
		return fmt.Errorf("copilot: token exchange returned HTTP %d: %s", status, snippet)
	}
}

// applyCopilotRequestHeaders sets the per-request editor-identity
// headers Copilot's chat endpoint requires. It does not touch
// Authorization — the caller sets the exchanged bearer.
func applyCopilotRequestHeaders(req *http.Request, integrationID string) {
	req.Header.Set("Copilot-Integration-Id", integrationID)
	req.Header.Set("Editor-Version", copilotEditorVersion)
	req.Header.Set("Editor-Plugin-Version", copilotEditorPluginVersion)
	req.Header.Set("Openai-Intent", "conversation-panel")
}

// copilotVendorOverride returns the Endpoint.VendorOverride closure for
// the Copilot provider. On each outbound chat request it adds the
// editor-identity headers and sets Authorization to the resolved Bearer
// — an exchanged short-lived Copilot token when the exchange is
// available, otherwise the raw GitHub token (the Copilot CLI's direct
// path, which is what Copilot Free requires). The destination host is
// GitHub's own Copilot API (api.githubcopilot.com), so sending the
// GitHub token there is the intended flow, not a leak.
func copilotVendorOverride(githubToken string) func(req *http.Request) {
	integrationID := copilotIntegrationID(githubToken)
	return func(req *http.Request) {
		applyCopilotRequestHeaders(req, integrationID)
		bearer, apiBase := defaultCopilotTokens.resolveBearer(req.Context(), githubToken)
		if bearer == "" {
			req.Header.Del("Authorization")
			return
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		repointCopilotHost(req, apiBase)
	}
}

// repointCopilotHost rewrites the request's scheme/host (and any path
// prefix) to the API base the exchange advertised. This is what makes
// Copilot Enterprise / data-residency (ghe.com) tenants work: their
// Copilot API lives on a tenant-specific host, not api.githubcopilot.com,
// and the exchange response's endpoints.api carries that host. A blank
// apiBase (the direct-Bearer fallback, which has no advertised host) or
// one that already matches the request is a no-op, so the default path
// is unchanged.
func repointCopilotHost(req *http.Request, apiBase string) {
	if apiBase == "" || req.URL == nil {
		return
	}
	u, err := url.Parse(apiBase)
	if err != nil || u.Host == "" {
		return
	}
	if u.Scheme == req.URL.Scheme && u.Host == req.URL.Host {
		return
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	req.Host = u.Host
	if prefix := strings.TrimRight(u.Path, "/"); prefix != "" && !strings.HasPrefix(req.URL.Path, prefix+"/") {
		req.URL.Path = prefix + req.URL.Path
	}
}
