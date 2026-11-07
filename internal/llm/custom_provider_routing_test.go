package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// endpointResolvers runs every no-profile resolution path a scan or a
// post-scan chat can take for cfg: the client's own fallback (CLI scans and
// web scans without a fixed endpoint), the legacy resolver, and the composite
// resolver with the built-in catalog wired (post-scan chat, web legacy
// fallback).
func endpointResolvers(t *testing.T, cfg *config.Config) map[string]func() (Endpoint, error) {
	t.Helper()
	fx := newResolverFixture(t, t.TempDir(), providers.Entry{}, "")
	return map[string]func() (Endpoint, error){
		"client": func() (Endpoint, error) {
			return NewClient(cfg).resolveRequestEndpoint(context.Background())
		},
		"legacy": func() (Endpoint, error) {
			return (&legacyResolver{cfg: cfg}).Resolve(context.Background())
		},
		"composite": func() (Endpoint, error) {
			return NewCompositeResolver(WithCatalog(fx.cat, fx.prof), WithLegacy(cfg)).Resolve(context.Background())
		},
	}
}

// TestCustomProvider_KeepsGatewayModelIDs is the regression test for an
// explicit Custom Provider (XALGORIX_LLM_PROVIDER=custom, as written by
// `xalgorix --setup`) whose model ID starts with a known provider slug.
// Gateways commonly name models "vendor/model"; the slug used to be taken as
// the routing provider, so requests left the operator's chat-completions
// endpoint for another protocol (/messages or :generateContent) with the
// gateway's model ID stripped.
func TestCustomProvider_KeepsGatewayModelIDs(t *testing.T) {
	const base = "https://gateway.example/api/v1"
	const wantURL = base + "/chat/completions"
	cases := []struct {
		name      string
		provider  string
		model     string
		wantModel string
	}{
		{name: "anthropic-prefixed", provider: "custom", model: "anthropic/claude-sonnet-4.5", wantModel: "anthropic/claude-sonnet-4.5"},
		{name: "google-prefixed", provider: "custom", model: "google/gemini-3-pro", wantModel: "google/gemini-3-pro"},
		{name: "deepseek-prefixed", provider: "custom", model: "deepseek/deepseek-v4", wantModel: "deepseek/deepseek-v4"},
		{name: "openai-prefixed", provider: "custom", model: "openai/gpt-5.6", wantModel: "openai/gpt-5.6"},
		{name: "org-prefixed", provider: "custom", model: "meta-llama/Llama-3.1-70B-Instruct", wantModel: "meta-llama/Llama-3.1-70B-Instruct"},
		{name: "redundant custom prefix", provider: "custom", model: "custom/anthropic/claude-sonnet-4.5", wantModel: "anthropic/claude-sonnet-4.5"},
		{name: "provider casing", provider: " Custom ", model: "anthropic/claude-sonnet-4.5", wantModel: "anthropic/claude-sonnet-4.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{LLMProvider: tc.provider, LLM: tc.model, APIBase: base, APIKey: "k"}
			if got := NewClient(cfg).provider; got != "custom" {
				t.Fatalf("client provider = %q, want custom", got)
			}
			for path, resolve := range endpointResolvers(t, cfg) {
				ep, err := resolve()
				if err != nil {
					t.Errorf("%s: Resolve: %v", path, err)
					continue
				}
				if ep.URL != wantURL {
					t.Errorf("%s: URL = %q, want %q", path, ep.URL, wantURL)
				}
				if ep.Model != tc.wantModel {
					t.Errorf("%s: Model = %q, want %q", path, ep.Model, tc.wantModel)
				}
				if ep.HeaderStyle != "openai" {
					t.Errorf("%s: HeaderStyle = %q, want openai", path, ep.HeaderStyle)
				}
				if ep.APIKey != "k" {
					t.Errorf("%s: APIKey = %q, want the configured key", path, ep.APIKey)
				}
			}
		})
	}
}

// TestCustomProvider_RequestReachesConfiguredEndpoint drives a real chat
// call and checks the wire request: the chat-completions path, bearer
// auth, and the verbatim gateway model ID.
func TestCustomProvider_RequestReachesConfiguredEndpoint(t *testing.T) {
	cfg := &config.Config{
		LLMProvider: "custom",
		LLM:         "anthropic/claude-sonnet-4.5",
		APIBase:     "http://gateway.example/api/v1",
		APIKey:      "gateway-key",
	}
	client := NewClient(cfg)
	var gotPath, gotAuth, gotVendorKey string
	var body map[string]any
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotPath = req.URL.Path
		gotAuth = req.Header.Get("Authorization")
		gotVendorKey = req.Header.Get("x-api-key")
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
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
	if gotPath != "/api/v1/chat/completions" {
		t.Errorf("path = %q, want /api/v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer gateway-key" {
		t.Errorf("Authorization = %q, want bearer gateway key", gotAuth)
	}
	if gotVendorKey != "" {
		t.Errorf("x-api-key = %q, want unset", gotVendorKey)
	}
	if body["model"] != "anthropic/claude-sonnet-4.5" {
		t.Errorf("body model = %v, want anthropic/claude-sonnet-4.5", body["model"])
	}
}

// TestCustomProvider_ExplicitProviderWithoutPrefixUnchanged pins the paths
// this change must not move: no explicit provider keeps prefix routing, an
// explicit provider that matches the prefix still strips it, and a custom
// provider whose base URL is the prefixed vendor's own API (or that has no
// base URL at all) still routes by the prefix.
func TestCustomProvider_ExplicitProviderWithoutPrefixUnchanged(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
		wantStyle string
	}{
		{
			name:      "custom on the vendor's own chat-completions API",
			cfg:       config.Config{LLMProvider: "custom", LLM: "deepseek/deepseek-v4", APIBase: "https://api.deepseek.com/v1", APIKey: "k"},
			wantURL:   "https://api.deepseek.com/v1/chat/completions",
			wantModel: "deepseek-v4",
			wantStyle: "openai",
		},
		{
			name:      "custom on the vendor's own versioned API",
			cfg:       config.Config{LLMProvider: "custom", LLM: "zai/GLM-5.3", APIBase: "https://api.z.ai/api/paas/v4", APIKey: "k"},
			wantURL:   "https://api.z.ai/api/paas/v4/chat/completions",
			wantModel: "glm-5.3",
			wantStyle: "openai",
		},
		{
			name:      "custom on the vendor's regional host",
			cfg:       config.Config{LLMProvider: "custom", LLM: "moonshot/kimi-k2", APIBase: "https://api.moonshot.ai/v1", APIKey: "k"},
			wantURL:   "https://api.moonshot.ai/v1/chat/completions",
			wantModel: "kimi-k2",
			wantStyle: "openai",
		},
		{
			name:      "custom on a local runtime's default port",
			cfg:       config.Config{LLMProvider: "custom", LLM: "ollama/llama3", APIBase: "http://127.0.0.1:11434/v1", APIKey: "k"},
			wantURL:   "http://127.0.0.1:11434/v1/chat/completions",
			wantModel: "llama3",
			wantStyle: "openai",
		},
		{
			name:      "custom on a messages-protocol base",
			cfg:       config.Config{LLMProvider: "custom", LLM: "anthropic/claude-sonnet-4.5", APIBase: "https://api.anthropic.com", APIKey: "k"},
			wantURL:   "https://api.anthropic.com/v1/messages",
			wantModel: "claude-sonnet-4.5",
			wantStyle: "anthropic",
		},
		{
			name:      "custom on a generateContent base",
			cfg:       config.Config{LLMProvider: "custom", LLM: "google/gemini-3-pro", APIBase: "https://generativelanguage.googleapis.com", APIKey: "k"},
			wantURL:   "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro:generateContent",
			wantModel: "gemini-3-pro",
			wantStyle: "gemini",
		},
		{
			name:      "custom without a base URL",
			cfg:       config.Config{LLMProvider: "custom", LLM: "anthropic/claude-sonnet-4.5", APIKey: "k"},
			wantURL:   "https://api.anthropic.com/v1/messages",
			wantModel: "claude-sonnet-4.5",
			wantStyle: "anthropic",
		},
		{
			name:      "prefix routing without explicit provider",
			cfg:       config.Config{LLM: "anthropic/claude-sonnet-4.5", APIKey: "k"},
			wantURL:   "https://api.anthropic.com/v1/messages",
			wantModel: "claude-sonnet-4.5",
			wantStyle: "anthropic",
		},
		{
			name:      "explicit provider matching the prefix",
			cfg:       config.Config{LLMProvider: "deepseek", LLM: "deepseek/deepseek-v4", APIKey: "k"},
			wantURL:   "https://api.deepseek.com/v1/chat/completions",
			wantModel: "deepseek-v4",
			wantStyle: "openai",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			for path, resolve := range endpointResolvers(t, &cfg) {
				ep, err := resolve()
				if err != nil {
					t.Errorf("%s: Resolve: %v", path, err)
					continue
				}
				if ep.URL != tc.wantURL || ep.Model != tc.wantModel || ep.HeaderStyle != tc.wantStyle {
					t.Errorf("%s: got (%q, %q, %q), want (%q, %q, %q)", path,
						ep.URL, ep.Model, ep.HeaderStyle, tc.wantURL, tc.wantModel, tc.wantStyle)
				}
			}
		})
	}
}

// TestResolver_ExplicitProviderWithBareModel covers the configuration
// `xalgorix --setup` writes: XALGORIX_LLM_PROVIDER plus a bare model ID and
// no saved profile. Scans already routed it through the client fallback, but
// the composite resolver used by post-scan chat only accepted a
// "<provider>/model" XALGORIX_LLM and answered "no provider configured".
func TestResolver_ExplicitProviderWithBareModel(t *testing.T) {
	routable := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
	}{
		{
			name:      "provider with built-in base",
			cfg:       config.Config{LLMProvider: "openai", LLM: "gpt-5.6", APIKey: "k"},
			wantURL:   "https://api.openai.com/v1/chat/completions",
			wantModel: "gpt-5.6",
		},
		{
			name:      "custom provider with operator base",
			cfg:       config.Config{LLMProvider: "custom", LLM: "my-model", APIBase: "https://llm.example/v1", APIKey: "k"},
			wantURL:   "https://llm.example/v1/chat/completions",
			wantModel: "my-model",
		},
	}
	for _, tc := range routable {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			for path, resolve := range endpointResolvers(t, &cfg) {
				ep, err := resolve()
				if err != nil {
					t.Errorf("%s: Resolve: %v", path, err)
					continue
				}
				if ep.URL != tc.wantURL || ep.Model != tc.wantModel {
					t.Errorf("%s: got (%q, %q), want (%q, %q)", path, ep.URL, ep.Model, tc.wantURL, tc.wantModel)
				}
			}
		})
	}

	// Without a key, or without any base URL to send it to, the composite
	// resolver must still refuse rather than guess a host.
	unroutable := []struct {
		name string
		cfg  config.Config
	}{
		{name: "missing key", cfg: config.Config{LLMProvider: "openai", LLM: "gpt-5.6"}},
		{name: "missing model", cfg: config.Config{LLMProvider: "custom", APIBase: "https://llm.example/v1", APIKey: "k"}},
		{name: "custom without base", cfg: config.Config{LLMProvider: "custom", LLM: "my-model", APIKey: "k"}},
		{name: "catalog provider without any base", cfg: config.Config{LLMProvider: "kilo", LLM: "my-model", APIKey: "k"}},
		{name: "catalog provider of another protocol without base", cfg: config.Config{LLMProvider: "googlevertex", LLM: "my-model", APIKey: "k"}},
	}
	for _, tc := range unroutable {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			fx := newResolverFixture(t, t.TempDir(), providers.Entry{}, "")
			ep, err := NewCompositeResolver(WithCatalog(fx.cat, fx.prof), WithLegacy(&cfg)).Resolve(context.Background())
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("Resolve = (%+v, %v), want *ConfigError", ep, err)
			}
		})
	}
}
