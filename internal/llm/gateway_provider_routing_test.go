package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// TestExplicitGatewayProvider_KeepsVendorModelIDs is the regression test for
// an explicit built-in provider that hosts other vendors' models (a gateway,
// an inference host or a local runtime) whose model ID starts with a known
// provider slug, such as OpenRouter's "google/gemini-3-pro" or Groq's
// "qwen/qwen3-32b". The slug used to be taken as the routing provider, so the
// request, with the gateway's key, went to that vendor's own API with the ID
// stripped, or reached the gateway with the stripped ID and the vendor's
// protocol.
func TestExplicitGatewayProvider_KeepsVendorModelIDs(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.Config
		wantURL string
	}{
		{
			name:    "gateway with the base the dashboard writes",
			cfg:     config.Config{LLMProvider: "openrouter", LLM: "google/gemini-3-pro", APIBase: "https://openrouter.ai/api/v1", APIKey: "k"},
			wantURL: "https://openrouter.ai/api/v1/chat/completions",
		},
		{
			name:    "gateway without a base URL",
			cfg:     config.Config{LLMProvider: "openrouter", LLM: "deepseek/deepseek-v4", APIKey: "k"},
			wantURL: "https://openrouter.ai/api/v1/chat/completions",
		},
		{
			name:    "legacy inference host without a base URL",
			cfg:     config.Config{LLMProvider: "groq", LLM: "qwen/qwen3-32b", APIKey: "k"},
			wantURL: "https://api.groq.com/openai/v1/chat/completions",
		},
		{
			name:    "legacy inference host with its own base URL",
			cfg:     config.Config{LLMProvider: "groq", LLM: "deepseek/deepseek-r1-distill", APIBase: "https://api.groq.com/openai/v1", APIKey: "k"},
			wantURL: "https://api.groq.com/openai/v1/chat/completions",
		},
		{
			name:    "catalog inference host without a base URL",
			cfg:     config.Config{LLMProvider: "together", LLM: "deepseek/deepseek-v4", APIKey: "k"},
			wantURL: "https://api.together.xyz/v1/chat/completions",
		},
		{
			name:    "credential-free local runtime with a case-sensitive model path",
			cfg:     config.Config{LLMProvider: "vllm", LLM: "Qwen/Qwen3-32B", APIBase: "http://gpu.example:8000/v1"},
			wantURL: "http://gpu.example:8000/v1/chat/completions",
		},
		{
			name:    "provider casing",
			cfg:     config.Config{LLMProvider: " OpenRouter ", LLM: "google/gemini-3-pro", APIKey: "k"},
			wantURL: "https://openrouter.ai/api/v1/chat/completions",
		},
		{
			// Only a legacy provider's prefix can switch vendors away from
			// a single-vendor provider; a catalog vendor's prefix must not
			// take this key to that vendor's catalog host.
			name:    "single-vendor provider with a catalog vendor's prefix",
			cfg:     config.Config{LLMProvider: "deepseek", LLM: "qwen/qwen3-max", APIKey: "k"},
			wantURL: "https://api.deepseek.com/v1/chat/completions",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if got, want := NewClient(&cfg).provider, strings.ToLower(strings.TrimSpace(cfg.LLMProvider)); got != want {
				t.Fatalf("client provider = %q, want %q", got, want)
			}
			for path, resolve := range endpointResolvers(t, &cfg) {
				ep, err := resolve()
				if err != nil {
					t.Errorf("%s: Resolve: %v", path, err)
					continue
				}
				if ep.URL != tc.wantURL || ep.Model != cfg.LLM || ep.HeaderStyle != "openai" || ep.APIKey != cfg.APIKey {
					t.Errorf("%s: got (%q, %q, %q, key %q), want (%q, %q, openai, key %q)", path,
						ep.URL, ep.Model, ep.HeaderStyle, ep.APIKey, tc.wantURL, cfg.LLM, cfg.APIKey)
				}
			}
		})
	}
}

// TestExplicitGatewayProvider_RequestReachesGateway drives a real chat call
// and checks the wire request: the gateway's host and chat-completions path,
// bearer auth, no vendor-specific credential, and the verbatim model ID.
func TestExplicitGatewayProvider_RequestReachesGateway(t *testing.T) {
	cfg := &config.Config{
		LLMProvider: "openrouter",
		LLM:         "google/gemini-3-pro",
		APIKey:      "gateway-key",
	}
	client := NewClient(cfg)
	var gotHost, gotPath, gotQuery, gotAuth, gotVendorKey string
	var body map[string]any
	client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotHost = req.URL.Host
		gotPath = req.URL.Path
		gotQuery = req.URL.RawQuery
		gotAuth = req.Header.Get("Authorization")
		gotVendorKey = req.Header.Get("x-goog-api-key") + req.Header.Get("x-api-key")
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
	if gotHost != "openrouter.ai" || gotPath != "/api/v1/chat/completions" {
		t.Errorf("request = %s%s, want openrouter.ai/api/v1/chat/completions", gotHost, gotPath)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want none (no key in the URL)", gotQuery)
	}
	if gotAuth != "Bearer gateway-key" {
		t.Errorf("Authorization = %q, want bearer gateway key", gotAuth)
	}
	if gotVendorKey != "" {
		t.Errorf("vendor key header = %q, want unset", gotVendorKey)
	}
	if body["model"] != "google/gemini-3-pro" {
		t.Errorf("body model = %v, want google/gemini-3-pro", body["model"])
	}
}

// TestExplicitProvider_PrefixStillRoutes pins the cases where the model's
// prefix keeps choosing the route, or is stripped as before.
func TestExplicitProvider_PrefixStillRoutes(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
		wantStyle string
	}{
		{
			// A legacy "<vendor>/model" switch under a stale single-vendor
			// provider selection.
			name:      "single-vendor provider without a base URL",
			cfg:       config.Config{LLMProvider: "deepseek", LLM: "google/gemini-3-pro", APIKey: "k"},
			wantURL:   "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro:generateContent",
			wantModel: "gemini-3-pro",
			wantStyle: "gemini",
		},
		{
			name:      "base URL is the prefixed vendor's own API",
			cfg:       config.Config{LLMProvider: "openrouter", LLM: "deepseek/deepseek-v4", APIBase: "https://api.deepseek.com/v1", APIKey: "k"},
			wantURL:   "https://api.deepseek.com/v1/chat/completions",
			wantModel: "deepseek-v4",
			wantStyle: "openai",
		},
		{
			// Only chat-completions providers override a prefix; the
			// explicit provider's own protocol is not chat completions.
			name:      "explicit provider of another protocol",
			cfg:       config.Config{LLMProvider: "googlevertex", LLM: "google/gemini-3-pro", APIBase: "https://us-central1-aiplatform.googleapis.com", APIKey: "k"},
			wantURL:   "https://us-central1-aiplatform.googleapis.com/v1beta/models/gemini-3-pro:generateContent",
			wantModel: "gemini-3-pro",
			wantStyle: "gemini",
		},
		{
			name:      "redundant explicit provider prefix",
			cfg:       config.Config{LLMProvider: "openrouter", LLM: "openrouter/google/gemini-3-pro", APIBase: "https://openrouter.ai/api/v1", APIKey: "k"},
			wantURL:   "https://openrouter.ai/api/v1/chat/completions",
			wantModel: "google/gemini-3-pro",
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

// TestPrefixOverExplicitProvider_GetsNoCatalogBase pins the guard on the
// catalog default base: when a catalog vendor's prefix routes instead of a
// different explicit provider (one without a base URL, unknown, a Custom
// Provider without a base URL, or one of another protocol), the key must not
// go to that vendor's catalog host, and the composite resolver refuses as
// before.
func TestPrefixOverExplicitProvider_GetsNoCatalogBase(t *testing.T) {
	entry, ok := providers.LookupBuiltin("qwen")
	if !ok || entry.BaseURL == "" {
		t.Fatal("qwen catalog entry with a base URL is required by this test")
	}
	vendorHost := mustHost(t, entry.BaseURL)
	cases := []config.Config{
		{LLMProvider: "kilo", LLM: "qwen/qwen3-max", APIKey: "k"},
		{LLMProvider: "my-gateway", LLM: "qwen/qwen3-max", APIKey: "k"},
		{LLMProvider: "custom", LLM: "qwen/qwen3-max", APIKey: "k"},
		{LLMProvider: "googlevertex", LLM: "qwen/qwen3-max", APIKey: "k"},
	}
	for _, cfg := range cases {
		t.Run(cfg.LLMProvider, func(t *testing.T) {
			for path, resolve := range endpointResolvers(t, &cfg) {
				ep, err := resolve()
				if err == nil && mustHost(t, ep.URL) == vendorHost {
					t.Errorf("%s: URL = %q, want no request to the prefixed vendor's catalog host", path, ep.URL)
				}
				if path == "composite" {
					var ce *ConfigError
					if !errors.As(err, &ce) {
						t.Errorf("composite: Resolve = (%+v, %v), want *ConfigError", ep, err)
					}
				}
			}
		})
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Hostname()
}

// TestCatalogProviderWithoutBase_UsesCatalogBase covers the client and legacy
// fallbacks for a chat-completions catalog provider with no
// XALGORIX_API_BASE. They used to fall back to the generic default host
// because only the legacy providers had a default base URL.
func TestCatalogProviderWithoutBase_UsesCatalogBase(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
	}{
		{
			name:      "explicit provider with a bare model",
			cfg:       config.Config{LLMProvider: "openrouter", LLM: "my-model", APIKey: "k"},
			wantURL:   "https://openrouter.ai/api/v1/chat/completions",
			wantModel: "my-model",
		},
		{
			name:      "provider prefix without an explicit provider",
			cfg:       config.Config{LLM: "mistral/mistral-large", APIKey: "k"},
			wantURL:   "https://api.mistral.ai/v1/chat/completions",
			wantModel: "mistral-large",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			resolvers := map[string]func() (Endpoint, error){
				"client": func() (Endpoint, error) {
					return NewClient(&cfg).resolveRequestEndpoint(context.Background())
				},
				"legacy": func() (Endpoint, error) {
					return (&legacyResolver{cfg: &cfg}).Resolve(context.Background())
				},
			}
			for path, resolve := range resolvers {
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
}
