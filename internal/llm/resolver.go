// Package llm — composite Resolver wiring (rewritten in v4.4.22).
//
// v4.4.21 routed outbound LLM traffic through a runtime-editable
// catalog whose existence/emptiness drove the legacy/catalog
// branch decision. v4.4.22 replaces that with a compiled-in
// catalog plus an explicit "active credential" pointer
// (cfg.LLMProfile, "<provider>:<profileId>"). The composite
// resolver now dispatches purely off cfg.LLMProfile + cfg.APIKey.
//
// Decision order:
//
//  1. cfg.LLMProfile != "" AND maps to a real Profile_Store entry
//     AND that entry's Provider matches a Builtin() catalog id →
//     dispatch through catalogResolver.
//
//  2. Else cfg.LLM matches Legacy_Provider_Shape AND cfg.APIKey is
//     set → dispatch through legacyResolver. This preserves the
//     v4.4.21 path for operators upgrading without re-saving
//     credentials through the new UI.
//
//  3. Otherwise → return *ConfigError "no provider configured".
//
// The per-scan picker plumbed through WithCatalogPicker still
// overrides the active-credential lookup so a per-request
// ScanRequest.ProviderProfile can target a different stored
// profile without touching cfg.LLMProfile.
package llm

import (
	"context"
	"net/http"
	url2 "net/url"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// ConfigError is the typed error the composite resolver returns
// when neither the catalog branch nor the legacy fallback can
// supply an outbound endpoint. The HTTP layer pattern-matches on
// this type to render a "no provider configured" message rather
// than a generic 500.
type ConfigError struct {
	Msg string
}

// Error implements the error interface.
func (e *ConfigError) Error() string { return e.Msg }

// legacyProviderBases is the runtime-immutable map of legacy
// provider slugs → default API base URLs. Lifted verbatim from
// the v4.4.21 client.resolveEndpoint so the legacy resolver
// produces byte-identical URL results to the pre-feature path.
var legacyProviderBases = map[string]string{
	"openai":          "https://api.openai.com/v1",
	"anthropic":       "https://api.anthropic.com",
	"minimax":         "https://api.minimax.io/v1",
	"deepseek":        "https://api.deepseek.com/v1",
	"groq":            "https://api.groq.com/openai/v1",
	"ollama":          "http://localhost:11434/v1",
	"google":          "https://generativelanguage.googleapis.com",
	"gemini":          "https://generativelanguage.googleapis.com",
	"zai":             "https://api.z.ai/api/paas/v4",
	"zai-coding-plan": "https://api.z.ai/api/coding/paas/v4",
}

// LegacyProviderBaseURL returns the canonical legacy API base URL
// for the supplied provider slug (case-insensitive) and reports
// whether the slug is recognized.
func LegacyProviderBaseURL(provider string) (string, bool) {
	v, ok := legacyProviderBases[strings.ToLower(strings.TrimSpace(provider))]
	return v, ok
}

// legacyResolver reproduces v4.4.21 client.resolveEndpoint().
type legacyResolver struct {
	cfg *config.Config
}

// catalogPick bundles the catalog Entry and credential Profile
// the catalog branch should use for one outbound request.
type catalogPick struct {
	entry   providers.Entry
	profile auth.Profile
}

// catalogResolver pulls baseURL + headerStyle from the compiled-in
// catalog (looked up by provider slug) and the access credential
// from the chosen Profile.
type catalogResolver struct {
	cat  *providers.Service
	prof *auth.Store
	pick func(ctx context.Context) (catalogPick, error)
	// fallbackBase is the operator-configured base URL
	// (cfg.APIBase / XALGORIX_API_BASE) used when neither the
	// catalog Entry nor the credential Profile carries one — the
	// "custom" provider case, where Entry.BaseURL is empty by
	// design. Without it a custom provider with an empty profile
	// override would build a relative request path (issue #122).
	fallbackBase string
}

// compositeResolver dispatches between catalogResolver and
// legacyResolver per the precedence rules in the package doc.
type compositeResolver struct {
	cat  *providers.Service
	prof *auth.Store
	cfg  *config.Config
	pick func(ctx context.Context) (catalogPick, error)
}

// ResolverOption configures the compositeResolver.
type ResolverOption func(*compositeResolver)

// WithCatalog wires the read-only catalog and the profile store
// into the composite. Both arguments must be non-nil for the
// catalog branch to engage; the catalog itself is the compiled-in
// providers.Builtin() set so it never reports IsEmpty == true.
func WithCatalog(cat *providers.Service, prof *auth.Store) ResolverOption {
	return func(c *compositeResolver) {
		c.cat = cat
		c.prof = prof
	}
}

// WithLegacy wires the legacy *config.Config so the legacy
// fallback branch has access to cfg.LLM / cfg.APIKey / cfg.APIBase.
func WithLegacy(cfg *config.Config) ResolverOption {
	return func(c *compositeResolver) {
		c.cfg = cfg
	}
}

// WithCatalogPicker injects a custom per-scan picker. The default
// picker uses cfg.LLMProfile to look up a Profile_Store entry; the
// per-scan path in internal/web overrides this to honor a
// ScanRequest.ProviderProfile field.
func WithCatalogPicker(pick func(ctx context.Context) (catalogPick, error)) ResolverOption {
	return func(c *compositeResolver) {
		c.pick = pick
	}
}

// NewCompositeResolver builds a Resolver that dispatches between
// the catalog-driven path and the legacy fallback per the
// precedence rules documented at the top of this file.
func NewCompositeResolver(opts ...ResolverOption) Resolver {
	c := &compositeResolver{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.pick == nil {
		c.pick = defaultCatalogPick(c)
	}
	return c
}

// defaultCatalogPick reads cfg.LLMProfile, splits it into
// "<provider>:<profileId>", looks the matching profile up in the
// store, and looks the matching catalog entry up in Builtin(). An
// empty cfg.LLMProfile is signaled via *ConfigError so the
// composite falls through to the legacy branch.
func defaultCatalogPick(c *compositeResolver) func(ctx context.Context) (catalogPick, error) {
	return func(ctx context.Context) (catalogPick, error) {
		if c.cat == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: catalog service not wired"}
		}
		if c.prof == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: profile store not wired"}
		}
		if c.cfg == nil || strings.TrimSpace(c.cfg.LLMProfile) == "" {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: no active LLM profile (XALGORIX_LLM_PROFILE unset)"}
		}
		profile, ok, err := c.prof.Get(ctx, strings.TrimSpace(c.cfg.LLMProfile))
		if err != nil {
			return catalogPick{}, err
		}
		if !ok {
			return catalogPick{}, &ConfigError{
				Msg: "catalog resolver: profile " + c.cfg.LLMProfile + " not found",
			}
		}
		entry, ok, err := c.cat.Get(ctx, profile.Provider)
		if err != nil {
			return catalogPick{}, err
		}
		if !ok {
			return catalogPick{}, &ConfigError{
				Msg: "catalog resolver: provider " + profile.Provider + " not in builtin catalog",
			}
		}
		return catalogPick{entry: entry, profile: profile}, nil
	}
}

// Resolve implements Resolver. It evaluates the cfg.LLMProfile
// gate on every call so the choice tracks runtime mutations to
// the active credential pointer.
func (c *compositeResolver) Resolve(ctx context.Context) (Endpoint, error) {
	// Credential-free catalog providers are selected explicitly through
	// XALGORIX_LLM_PROVIDER. They do not need or create an Auth Profile, and
	// the model remains the provider's bare model ID.
	if c.cfg != nil && strings.TrimSpace(c.cfg.LLMProvider) != "" && strings.TrimSpace(c.cfg.LLMProfile) == "" && c.cat != nil {
		entry, ok, err := c.cat.Get(ctx, strings.TrimSpace(c.cfg.LLMProvider))
		if err != nil {
			return Endpoint{}, err
		}
		if ok && providerAllowsNoAuth(entry) {
			if strings.TrimSpace(c.cfg.APIBase) != "" {
				entry.BaseURL = strings.TrimSpace(c.cfg.APIBase)
			}
			return BuildCatalogEndpoint(entry, auth.Profile{}, modelForProvider(c.cfg.LLM, c.cfg.LLMProvider), c.cfg.APIBase)
		}
	}
	// Branch 1 — explicit active credential pointer wins.
	if c.cfg != nil && strings.TrimSpace(c.cfg.LLMProfile) != "" && c.cat != nil && c.prof != nil {
		cr := &catalogResolver{cat: c.cat, prof: c.prof, pick: c.pick, fallbackBase: c.cfg.APIBase}
		ep, err := cr.Resolve(ctx)
		if err == nil {
			// Custom Provider and LiteLLM catalog entries have
			// empty Models lists, so BuildCatalogEndpoint returns
			// an endpoint with Model="". Fall back to the
			// operator's configured model (XALGORIX_LLM), removing only
			// a matching legacy "provider/" prefix — mirrors the same logic
			// in scan_resolve.go legacyOrCatalogDefaultEndpoint
			// Branch 0.
			if ep.Model == "" && c.cfg.LLM != "" {
				provider := c.cfg.LLMProvider
				if provider == "" {
					provider, _, _ = strings.Cut(c.cfg.LLMProfile, ":")
				}
				ep.Model = modelForProvider(c.cfg.LLM, provider)
			}
			return ep, nil
		}
		// On catalog-branch failure (unknown profile, missing
		// catalog entry) return the typed error so the HTTP
		// layer surfaces "no provider configured" rather than
		// silently falling through to legacy.
		return Endpoint{}, err
	}

	// Branch 2 — legacy fallback. cfg.APIKey must also be set per
	// the new precedence rules so a stale cfg.LLM without
	// credentials does not produce a broken outbound request.
	if c.cfg != nil && LegacyProviderShape(c.cfg.LLM) && strings.TrimSpace(c.cfg.APIKey) != "" {
		lr := &legacyResolver{cfg: c.cfg}
		return lr.Resolve(ctx)
	}

	// Branch 3 — neither path is available.
	return Endpoint{}, &ConfigError{
		Msg: "no provider configured: set XALGORIX_LLM_PROFILE to a saved credential or set XALGORIX_LLM + XALGORIX_API_KEY",
	}
}

func providerAllowsNoAuth(entry providers.Entry) bool {
	for _, method := range entry.AuthMethods {
		if method == "none" {
			return true
		}
	}
	return false
}

func modelForProvider(model, provider string) string {
	model = strings.TrimSpace(model)
	prefix := strings.ToLower(strings.TrimSpace(provider)) + "/"
	if prefix != "/" && strings.HasPrefix(strings.ToLower(model), prefix) {
		return strings.TrimSpace(model[len(prefix):])
	}
	return model
}

// Resolve on legacyResolver reproduces v4.4.21
// Client.resolveEndpoint() step-for-step.
func (l *legacyResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if l.cfg == nil {
		return Endpoint{}, &ConfigError{Msg: "legacy resolver: nil config"}
	}

	apiBase := l.cfg.APIBase
	model := l.cfg.LLM

	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		candidate := strings.ToLower(model[:idx])
		if isKnownProvider(candidate) {
			provider = candidate
			model = model[idx+1:]
		}
	}
	if provider == "" && l.cfg != nil && strings.TrimSpace(l.cfg.LLMProvider) != "" {
		provider = strings.ToLower(strings.TrimSpace(l.cfg.LLMProvider))
	}
	if apiBase == "" {
		if knownBase, ok := legacyProviderBases[provider]; ok {
			apiBase = knownBase
		} else {
			apiBase = "https://api.openai.com/v1"
		}
	}
	apiBase = strings.TrimRight(apiBase, "/")

	url := apiBase
	switch {
	case provider == "anthropic" || isAnthropicAPIBase(apiBase):
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case isGeminiProvider(provider) || isGeminiAPIBase(apiBase):
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	default:
		url = providers.OpenAICompatibleURL(apiBase, "chat/completions")
	}
	model = normalizeEndpointModel(provider, url, model)

	return Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: legacyHeaderStyle(provider, apiBase),
		Auth:        AuthAPIKey,
		APIKey:      l.cfg.APIKey,
	}, nil
}

// legacyHeaderStyle maps a legacy slug + base URL to one of the
// three values the LLM client switch dispatches on.
func legacyHeaderStyle(provider, apiBase string) string {
	switch provider {
	case "openai", "minimax", "deepseek", "groq", "ollama", "zai", "zai-coding-plan":
		return "openai"
	case "anthropic":
		return "anthropic"
	case "google", "gemini":
		return "gemini"
	}
	if isAnthropicAPIBase(apiBase) {
		return "anthropic"
	}
	if isGeminiAPIBase(apiBase) {
		return "gemini"
	}
	return "openai"
}

// Resolve on catalogResolver pulls baseURL + headerStyle from the
// catalog Entry and credentials from the matching Profile.
func (cr *catalogResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if cr.cat == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil catalog"}
	}
	if cr.prof == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil profile store"}
	}
	if cr.pick == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil picker"}
	}

	pick, err := cr.pick(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	return BuildCatalogEndpoint(pick.entry, pick.profile, "", cr.fallbackBase)
}

// BuildCatalogEndpoint assembles the outbound Endpoint for one
// (catalog Entry, credential Profile) pair. It is the single source
// of truth for catalog-driven endpoint construction: both the
// composite resolver (catalogResolver.Resolve) and the per-scan
// resolver in internal/web/scan_resolve.go call it, so the URL
// shape, auth wiring, and vendor-specific headers can never diverge
// between the "default provider" path and the "per-scan profile"
// path (the divergence that previously sent Codex traffic to the
// wrong /v1/chat/completions path without the ChatGPT headers).
//
// preferModel overrides the catalog's default model (entry.Models[0])
// when non-empty — used by the active-profile path so the operator's
// typed model wins over the catalog default. An empty preferModel
// preserves the "first catalog model" behavior.
//
// fallbackBase is the operator-configured base URL (cfg.APIBase /
// XALGORIX_API_BASE) consulted only when neither the catalog Entry
// nor the credential Profile supplies one. This is what keeps the
// "custom" provider working: its catalog Entry.BaseURL is empty by
// design, so without this fallback a profile missing its
// APIBaseOverride would build a relative request path and the HTTP
// client would fail with `unsupported protocol scheme ""` (#122).
//
// An unrecognized HeaderStyle returns a *ConfigError so a corrupt
// catalog entry surfaces as "no provider configured" rather than
// silently POSTing to a guessed path. Likewise, a non-absolute
// final URL (missing scheme/host) returns a *ConfigError so a
// missing base URL fails fast as a config error instead of being
// retried as a transient provider failure.
func BuildCatalogEndpoint(entry providers.Entry, prof auth.Profile, preferModel, fallbackBase string) (Endpoint, error) {
	model := strings.TrimSpace(preferModel)
	if model == "" && len(entry.Models) > 0 {
		model = entry.Models[0]
	}
	apiBase := entry.BaseURL
	if prof.Type == auth.APIKey && prof.APIBaseOverride != "" {
		apiBase = prof.APIBaseOverride
	}
	if strings.TrimSpace(apiBase) == "" {
		// Neither the catalog entry nor the profile carry a base
		// URL (the "custom" provider shape). Fall back to the
		// operator-configured base so the request is never sent
		// with a relative path (#122).
		apiBase = strings.TrimSpace(fallbackBase)
	}
	apiBase = strings.TrimRight(apiBase, "/")

	url := apiBase
	switch entry.HeaderStyle {
	case "anthropic":
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case "gemini":
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	case "openai":
		url = providers.OpenAICompatibleURL(apiBase, "chat/completions")
	case "openai_responses":
		// OpenAI Responses API (Codex / ChatGPT subscription backend).
		// The base URL already encodes the backend root (e.g.
		// https://chatgpt.com/backend-api/codex or https://api.openai.com/v1);
		// append the /responses path when the base doesn't already end in it.
		if !strings.HasSuffix(strings.ToLower(url), "/responses") {
			url += "/responses"
		}
	default:
		return Endpoint{}, &ConfigError{
			Msg: "catalog resolver: unsupported headerStyle " + entry.HeaderStyle + " for entry " + entry.ID,
		}
	}
	model = normalizeEndpointModel(entry.ID, url, model)

	// Fail fast when the assembled URL is not absolute (missing
	// scheme or host). This is the deterministic config bug behind
	// #122: a "custom" provider with no base URL anywhere produces a
	// relative path like "/v1/chat/completions", which the HTTP
	// client rejects with `unsupported protocol scheme ""`. Surfacing
	// it as a *ConfigError here means the LLM retry loop treats it as
	// a non-retryable configuration error instead of hammering the
	// request 5 times.
	if parsed, perr := url2.Parse(url); perr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Endpoint{}, &ConfigError{
			Msg: "catalog resolver: provider " + entry.ID + " has no base URL — set the Base URL for the Custom Provider (or XALGORIX_API_BASE); built non-absolute request URL " + strconv.Quote(url),
		}
	}

	ep := Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: entry.HeaderStyle,
	}
	if prof.Type == auth.OAuth {
		ep.Auth = AuthOAuthBearer
		ep.AccessToken = prof.AccessToken
	} else {
		ep.Auth = AuthAPIKey
		ep.APIKey = prof.APIKey
	}

	// The Codex / ChatGPT subscription backend requires extra headers
	// beyond the bearer token: the account id and the Codex CLI
	// originator/beta markers. Attach them via VendorOverride so the
	// client's header switch stays provider-agnostic. These are only
	// meaningful for the openai_responses style; harmless otherwise.
	if entry.HeaderStyle == "openai_responses" {
		accountID := prof.AccountID
		ep.VendorOverride = func(req *http.Request) {
			if accountID != "" {
				req.Header.Set("chatgpt-account-id", accountID)
			}
			req.Header.Set("OpenAI-Beta", "responses=experimental")
			req.Header.Set("originator", "codex_cli_rs")
		}
	}
	return ep, nil
}

// Compile-time interface assertion.
var _ Resolver = (*compositeResolver)(nil)
