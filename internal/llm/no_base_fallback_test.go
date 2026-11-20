package llm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// cfgCaseName names a subtest after its provider and model without the "/"
// that would nest it.
func cfgCaseName(cfg config.Config) string {
	return strings.ReplaceAll("provider="+cfg.LLMProvider+",model="+cfg.LLM, "/", ":")
}

// TestKnownProviderWithoutBase_RefusesGenericHost is the regression test for
// the no-profile request paths (CLI and TUI scans, web scans without a fixed
// endpoint) sending a known provider's key to the generic default host when
// XALGORIX_API_BASE is unset and the provider has no default base URL. The
// composite resolver already refused these configurations; the client
// fallback and the legacy resolver now refuse them too.
func TestKnownProviderWithoutBase_RefusesGenericHost(t *testing.T) {
	var cases []config.Config
	for _, entry := range providers.Builtin() {
		if strings.TrimSpace(entry.BaseURL) != "" {
			continue
		}
		// Selected explicitly, and named only by the model's prefix.
		cases = append(cases,
			config.Config{LLMProvider: entry.ID, LLM: "my-model", APIKey: "k"},
			config.Config{LLM: entry.ID + "/my-model", APIKey: "k"},
		)
	}
	if len(cases) == 0 {
		t.Fatal("the built-in catalog has no provider without a base URL; this test needs one")
	}
	cases = append(cases,
		// Provider casing and whitespace.
		config.Config{LLMProvider: " Kilo ", LLM: "my-model", APIKey: "k"},
		// A catalog provider of another protocol, which the
		// chat-completions fallback cannot reach.
		config.Config{LLMProvider: "googlevertex", LLM: "my-model", APIKey: "k"},
		// A catalog vendor's prefix outranking a baseless or unknown
		// explicit provider gets no catalog base either.
		config.Config{LLMProvider: "kilo", LLM: "qwen/qwen3-max", APIKey: "k"},
		config.Config{LLMProvider: "my-gateway", LLM: "qwen/qwen3-max", APIKey: "k"},
		// The same-vendor exemption covers only a provider the operator
		// selected: under a different explicit provider the key is that
		// provider's, whatever the model's prefix.
		config.Config{LLMProvider: "kilo", LLM: "codex/my-model", APIKey: "k"},
		config.Config{LLMProvider: "custom", LLM: "codex/my-model", APIKey: "k"},
		config.Config{LLMProvider: "anthropic", LLM: "codex/my-model", APIKey: "k"},
		config.Config{LLMProvider: "my-gateway", LLM: "codex/my-model", APIKey: "k"},
	)

	for _, cfg := range cases {
		t.Run(cfgCaseName(cfg), func(t *testing.T) {
			for path, resolve := range endpointResolvers(t, &cfg) {
				ep, err := resolve()
				var ce *ConfigError
				if !errors.As(err, &ce) {
					t.Errorf("%s: resolve = (%q, %v), want *ConfigError", path, ep.URL, err)
					continue
				}
				if path != "composite" && !strings.Contains(ce.Msg, "XALGORIX_API_BASE") {
					t.Errorf("%s: error %q should name XALGORIX_API_BASE", path, ce.Msg)
				}
			}
		})
	}
}

// TestGenericDefaultHost_KeptForUnroutedModels pins the configurations that
// keep the pre-catalog default host on the client and legacy paths: a bare
// model with no provider, a provider whose vendor runs that host, and, for
// compatibility only, an explicit provider name the catalog does not know.
func TestGenericDefaultHost_KeptForUnroutedModels(t *testing.T) {
	const wantURL = "https://api.openai.com/v1/chat/completions"
	cases := []struct {
		name      string
		cfg       config.Config
		wantModel string
	}{
		{name: "bare model without provider", cfg: config.Config{LLM: "my-model", APIKey: "k"}, wantModel: "my-model"},
		{name: "same-vendor provider selected explicitly", cfg: config.Config{LLMProvider: "codex", LLM: "my-model", APIKey: "k"}, wantModel: "my-model"},
		{name: "same-vendor provider as the only prefix", cfg: config.Config{LLM: "codex/my-model", APIKey: "k"}, wantModel: "my-model"},
		{name: "unknown provider name (compatibility)", cfg: config.Config{LLMProvider: "unlisted-provider", LLM: "my-model", APIKey: "k"}, wantModel: "my-model"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for path, resolve := range endpointResolvers(t, &tc.cfg) {
				if path == "composite" {
					continue
				}
				ep, err := resolve()
				if err != nil {
					t.Errorf("%s: resolve error = %v, want %s", path, err, wantURL)
					continue
				}
				if ep.URL != wantURL || ep.Model != tc.wantModel {
					t.Errorf("%s: got (%q, %q), want (%q, %q)", path, ep.URL, ep.Model, wantURL, tc.wantModel)
				}
			}
		})
	}
}
