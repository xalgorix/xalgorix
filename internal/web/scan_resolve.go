// Package web — per-scan endpoint resolver (Wave E task 5.3).
//
// resolveScanCredentials translates a single ScanRequest into the
// effective llm.Endpoint the scan will POST to, applying the four
// precedence rules from Requirement 11:
//
//  1. R11.2: When ScanRequest.ProviderProfile is non-empty, look up
//     the matching Auth_Profile in Profile_Store and the matching
//     Catalog_Entry in Catalog_Service, build the URL via
//     buildEndpoint, and populate (Auth, APIKey | AccessToken)
//     from the profile.
//  2. R11.3: When ProviderProfile is empty, defer to
//     legacyOrCatalogDefaultEndpoint, which mirrors the existing
//     Settings free-text path (legacy resolver when the catalog is
//     empty AND XALGORIX_LLM matches Legacy_Provider_Shape;
//     otherwise the catalog's first-entry / first-profile default).
//  3. R11.4: Ad-hoc Model / APIKey / APIBase overrides take
//     precedence over whatever step 1 or 2 produced. APIKey
//     additionally forces Auth=AuthAPIKey so a pasted key never
//     gets sent as an OAuth bearer token by mistake.
//  4. R11.6: An unknown ProviderProfile (or profile referencing a
//     missing catalog entry, or an uninitialized store) returns
//     errUnknownProviderProfile so the /api/scan handler can map
//     it to HTTP 400 BEFORE any scan goroutine spawns.
//
// The /api/scan handler calls resolveScanCredentials early as a
// precondition check; the actual scan goroutine resolves through
// the LLM client's composite resolver as before, so this helper is
// not yet on the hot path of an in-flight request. Surfacing the
// 400 here is purely a fail-fast against a misspelled profile id.
//
// Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6.
package web

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// errAPIBaseNeedsKey is returned when a scan request moves LLM traffic to a
// host the operator did not configure without supplying its own api_key.
var errAPIBaseNeedsKey = errors.New("api_base points to a different host than the configured LLM endpoint; include api_key in the same request (stored provider credentials are never sent to a request-supplied host)")

// checkScanRequestDestinations validates the outbound destinations a scan
// request chooses — the notification webhook and the LLM api_base — before
// any scan state exists. Every wire entry point that starts a scan (POST
// /api/scan and the WebSocket scan message) must call it.
func (s *Server) checkScanRequestDestinations(ctx context.Context, req ScanRequest) error {
	if err := s.validateScanWebhook(req.DiscordWebhook); err != nil {
		return err
	}
	return s.checkScanAPIBaseOverride(ctx, req)
}

// applyScanLLMOverrides copies a request's ad-hoc LLM overrides into the
// per-scan config copy. A caller-supplied api_key replaces the stored
// credential set for this scan, including the rotation pool: otherwise the
// key rotator would swap the operator's pooled keys in on later requests to
// whatever api_base the caller chose.
func applyScanLLMOverrides(cfg *config.Config, req ScanRequest) {
	if req.Model != "" {
		cfg.LLM = req.Model
	}
	if req.APIKey != "" {
		cfg.APIKey = req.APIKey
		cfg.APIKeys = nil
	}
	if req.APIBase != "" {
		cfg.APIBase = req.APIBase
	}
}

// checkScanAPIBaseOverride guards the ad-hoc api_base override (R11.4).
// Stored credentials — the configured key or key pool, an auth profile's key
// or OAuth token — belong to the endpoint they resolve to. Machine API tokens
// are deliberately kept away from provider credentials (see
// machineTokenRouteDenylist), so a scan request may only point LLM traffic
// outside that endpoint when it brings its own api_key. An override is "the
// same endpoint" when it has the stored endpoint's origin and one path is a
// segment prefix of the other (so a path-scoped gateway tenant cannot be
// swapped for another). Installs that hold no stored credential are
// unaffected.
func (s *Server) checkScanAPIBaseOverride(ctx context.Context, req ScanRequest) error {
	base := strings.TrimSpace(req.APIBase)
	if base == "" || strings.TrimSpace(req.APIKey) != "" || s.cfg == nil {
		return nil
	}
	stored := req
	stored.APIBase = ""
	ep, err := s.resolveScanCredentials(ctx, stored, s.cfg)
	storedURL := s.cfg.APIBase
	if err == nil && ep.URL != "" {
		storedURL = ep.URL
	}
	if sameEndpointScope(base, storedURL) {
		return nil
	}
	hasStored := strings.TrimSpace(s.cfg.APIKey) != "" || len(s.cfg.APIKeys) > 0
	if err == nil {
		hasStored = hasStored || ep.APIKey != "" || ep.AccessToken != ""
	} else {
		// Could not resolve which credential applies: assume a configured
		// profile carries one.
		hasStored = hasStored || strings.TrimSpace(s.cfg.LLMProfile) != "" || strings.TrimSpace(req.ProviderProfile) != ""
	}
	if !hasStored {
		return nil
	}
	return errAPIBaseNeedsKey
}

// endpointOrigin returns the lower-cased scheme://host:port of an http(s) URL,
// or "" when raw is not an absolute http(s) URL.
func endpointOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return ""
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// sameEndpointScope reports whether override stays on the stored endpoint:
// same origin, the same query when the override sets one, and one cleaned
// path a segment prefix of the other. Paths are compared decoded and with dot
// segments resolved, so "/v1/../other" counts as "/other".
func sameEndpointScope(override, stored string) bool {
	origin := endpointOrigin(override)
	if origin == "" || origin != endpointOrigin(stored) {
		return false
	}
	o, err := url.Parse(strings.TrimSpace(override))
	if err != nil {
		return false
	}
	st, err := url.Parse(strings.TrimSpace(stored))
	if err != nil {
		return false
	}
	if o.RawQuery != "" && o.RawQuery != st.RawQuery {
		return false
	}
	// Some servers treat ";" path parameters (e.g. "..;") as dot segments;
	// path.Clean does not, so never count such an override as in scope.
	if strings.Contains(o.Path, ";") {
		return false
	}
	op, sp := cleanURLPath(o.Path), cleanURLPath(st.Path)
	return pathSegmentPrefix(op, sp) || pathSegmentPrefix(sp, op)
}

func cleanURLPath(p string) string {
	return strings.TrimRight(path.Clean("/"+p), "/")
}

// pathSegmentPrefix reports whether prefix is p or an ancestor of p on a
// segment boundary ("" is the root and prefixes everything).
func pathSegmentPrefix(prefix, p string) bool {
	return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

// errUnknownProviderProfile is returned by resolveScanCredentials
// whenever the supplied ProviderProfile cannot be mapped to a live
// (Catalog_Entry, Auth_Profile) tuple. The handler maps this to
// HTTP 400 with the canonical body "unknown provider profile" per
// Requirement 11.6. Declared as a sentinel (rather than ad-hoc
// fmt.Errorf) so test code and future callers can errors.Is on it.
var errUnknownProviderProfile = errors.New("unknown provider profile")

// resolveScanCredentials returns the effective LLM endpoint for one
// scan. The full precedence rule lives in the package doc above; in
// summary: profile lookup (R11.2) → catalog default fallback (R11.3)
// → ad-hoc override merge (R11.4). Unknown ProviderProfile values
// return errUnknownProviderProfile so the /api/scan handler can
// fail fast with HTTP 400 (R11.6).
//
// Validates: Requirements 11.2, 11.3, 11.4, 11.6.
func (s *Server) resolveScanCredentials(ctx context.Context, req ScanRequest, cfg *config.Config) (llm.Endpoint, error) {
	var ep llm.Endpoint

	if req.ProviderProfile != "" {
		// Profile-driven resolution requires both stores to be
		// live. A nil catalog or profile store on a request that
		// names a profile is indistinguishable from a "missing"
		// profile from the operator's point of view, so collapse
		// both to errUnknownProviderProfile rather than surfacing
		// a 503 — the dashboard shows one error envelope either
		// way and the operator's first remediation step is the
		// same: re-check the spelling of the profile key.
		if s.profiles == nil || s.catalog == nil {
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		prof, ok, err := s.profiles.Get(ctx, req.ProviderProfile)
		if err != nil {
			return llm.Endpoint{}, err
		}
		if !ok {
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		entry, ok, err := s.catalog.Get(ctx, prof.Provider)
		if err != nil {
			return llm.Endpoint{}, err
		}
		if !ok {
			// Profile references a catalog entry that no longer
			// exists. From the operator's point of view this is
			// the same failure mode as a missing profile — the
			// "<provider>:<profileId>" key cannot be resolved
			// to an outbound endpoint.
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		// Shared catalog endpoint builder (llm.BuildCatalogEndpoint)
		// — the single source of truth for URL shape, auth wiring,
		// and vendor headers. Using it here keeps the per-scan path
		// byte-identical to the composite resolver, including the
		// openai_responses (Codex / ChatGPT) path + its required
		// chatgpt-account-id / OpenAI-Beta / originator headers.
		built, berr := llm.BuildCatalogEndpoint(entry, prof, "", cfg.APIBase)
		if berr != nil {
			return llm.Endpoint{}, berr
		}
		ep = built
	} else {
		// No provider_profile → legacy / catalog-default path
		// (Requirement 11.3). The helper returns a zero Endpoint
		// when no provider is configured at all; we leave it
		// zero here so the ad-hoc overrides below can still
		// populate it (the operator may be supplying APIBase +
		// APIKey + Model directly).
		ep = s.legacyOrCatalogDefaultEndpoint(ctx, cfg)
	}

	// Ad-hoc override merge (Requirement 11.4). The same
	// authenticated-operator gate already enforced on /api/scan
	// admits the override path; this helper only merges values.
	//
	// Order matters: APIKey is processed before Model/APIBase so
	// the Auth flip to AuthAPIKey takes effect even on requests
	// that also override Model. APIKey also clears AccessToken so
	// a stale OAuth bearer never rides along on a request the
	// operator explicitly steered to API-key auth.
	if req.APIKey != "" {
		ep.Auth = llm.AuthAPIKey
		ep.APIKey = req.APIKey
		ep.AccessToken = ""
	}
	if req.Model != "" {
		ep.Model = req.Model
	}
	if req.APIBase != "" {
		// Best-effort override: callers historically pass the
		// full chat-completions / messages / generateContent
		// URL here, so we just trim the trailing slash and use
		// it verbatim. The legacy resolver behaved identically
		// (Client.resolveEndpoint set apiBase from cfg.APIBase
		// without re-deriving the version segment), so this
		// preserves the existing override semantics.
		ep.URL = strings.TrimRight(req.APIBase, "/")
	}
	return ep, nil
}

// scanLLMClientForRequest is the swallow-error wrapper around
// buildScanLLMClient used at scanSession construction. The
// /api/scan precondition has already short-circuited the
// errUnknownProviderProfile case so any error here is a transient
// "the underlying file lock contended" / "profile race-deleted"
// shape; logging and returning nil keeps the scan running with the
// agent's default client (and surfaces the credential gap at first
// chat call) rather than tearing down the scan goroutine.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func (s *Server) scanLLMClientForRequest(req ScanRequest, scanCfg *config.Config) *llm.Client {
	client, err := s.buildScanLLMClient(context.Background(), req, scanCfg)
	if err != nil {
		log.Printf("[scan] resolver wiring failed for instance=%q profile=%q: %v (falling back to default client)", req.InstanceID, req.ProviderProfile, err)
		return nil
	}
	return client
}

// buildScanLLMClient returns a *llm.Client primed with a fixed
// resolver that reflects this scan's resolved provider_profile (or
// the legacy / catalog-default fallback when ProviderProfile is
// empty). Callers thread the returned client into agent.NewAgent
// via agent.WithLLMClient so the scan goroutine's outbound LLM
// traffic carries the operator's chosen credentials — which closes
// the B1 gap where a per-scan provider_profile setting was silently
// ignored because runScanInstance only built llm.NewClient(cfg)
// with no resolver attached.
//
// The Endpoint baked into the resolver is whatever
// resolveScanCredentials produced: the same precedence-merged
// (URL, model, headerStyle, auth, credentials) the /api/scan
// precondition check already validated. We deliberately do NOT
// re-evaluate the catalog/legacy gate at chat-call time — doing so
// would let a mid-scan catalog edit silently retarget the in-flight
// scan, which is a worse property than freezing the endpoint at
// scan start.
//
// On any resolver error (errUnknownProviderProfile or otherwise)
// buildScanLLMClient surfaces the error to the caller so the scan
// never starts with a half-resolved client. The legacy "no
// configuration anywhere" fallback is preserved by handing back a
// no-resolver client when the resolver returned a zero Endpoint
// without an error — the LLM client's own composite resolver path
// then gets a chance to surface a *ConfigError at first chat call
// with the same message it always did.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func (s *Server) buildScanLLMClient(ctx context.Context, req ScanRequest, cfg *config.Config) (*llm.Client, error) {
	ep, err := s.resolveScanCredentials(ctx, req, cfg)
	if err != nil {
		return nil, err
	}
	if isZeroEndpoint(ep) {
		// No useful routing info → defer to the LLM client's
		// own composite resolver so legacy installs without any
		// provider configuration still get the canonical
		// *ConfigError at first chat call.
		return llm.NewClient(cfg), nil
	}
	return llm.NewClient(cfg, llm.WithResolver(llm.NewFixedResolver(ep))), nil
}

// isZeroEndpoint reports whether ep carries no useful routing
// information — used by buildScanLLMClient to decide whether to
// install a fixed resolver or to fall back to the LLM client's
// default resolver. A nonzero URL is the strongest signal of
// usefulness; APIKey / AccessToken alone (with no URL) means the
// operator pasted credentials but did not steer them anywhere, so
// the legacy resolver's providerBases-derived URL still applies.
func isZeroEndpoint(ep llm.Endpoint) bool {
	return ep.URL == "" && ep.Model == "" && ep.APIKey == "" && ep.AccessToken == ""
}

// modelForConfiguredProvider strips a matching legacy "<provider>/" prefix
// from XALGORIX_LLM while preserving provider-native IDs that contain a slash.
// Mirrors the legacy resolver's model derivation
// (internal/llm/resolver.go) so the active-profile path and the
// legacy path agree on the outbound model string. Returns "" when
// cfg.LLM is empty so callers fall back to the catalog default.
func modelForConfiguredProvider(llmValue, provider string) string {
	model := strings.TrimSpace(llmValue)
	prefix := strings.ToLower(strings.TrimSpace(provider)) + "/"
	if prefix != "/" && strings.HasPrefix(strings.ToLower(model), prefix) {
		model = model[len(prefix):]
	}
	return strings.TrimSpace(model)
}

// legacyOrCatalogDefaultEndpoint is the fallback resolver consulted
// when ScanRequest.ProviderProfile is empty. The selection order
// mirrors the LLM client's composite resolver (Wave D task 4.1):
//
//  1. Catalog non-empty → first catalog entry + first matching
//     profile, built via buildEndpoint. This is the "current default
//     provider" view the dashboard renders for the Settings page.
//  2. Catalog empty AND XALGORIX_LLM matches Legacy_Provider_Shape
//     → defer to llm.NewCompositeResolver(WithLegacy(cfg)) and
//     return its Resolve result. This is the Legacy_Fallback path
//     (Requirements 2.1, 2.3).
//  3. Otherwise → return a zero Endpoint. The caller may still
//     populate it through ad-hoc Model/APIKey/APIBase overrides
//     (Requirement 11.4). When even those are empty, the actual
//     LLM client call later in the scan will surface a *ConfigError
//     through its own Resolver path — there's no point producing a
//     duplicate "no provider configured" error here.
//
// Validates: Requirements 2.1, 2.2, 2.3, 11.3.
func (s *Server) legacyOrCatalogDefaultEndpoint(ctx context.Context, cfg *config.Config) llm.Endpoint {
	// Credential-free providers are persisted independently from model names.
	// Resolve them before profile-based routing so a previous cloud credential
	// can never override an explicitly selected local provider.
	if cfg != nil && strings.TrimSpace(cfg.LLMProvider) != "" && strings.TrimSpace(cfg.LLMProfile) == "" && s.catalog != nil {
		if entry, ok, err := s.catalog.Get(ctx, strings.TrimSpace(cfg.LLMProvider)); err == nil && ok {
			allowsNone := false
			for _, method := range entry.AuthMethods {
				if method == "none" {
					allowsNone = true
					break
				}
			}
			if allowsNone {
				if strings.TrimSpace(cfg.APIBase) != "" {
					entry.BaseURL = strings.TrimSpace(cfg.APIBase)
				}
				if ep, berr := llm.BuildCatalogEndpoint(entry, auth.Profile{}, modelForConfiguredProvider(cfg.LLM, cfg.LLMProvider), cfg.APIBase); berr == nil {
					return ep
				}
			}
		}
	}
	// Branch 0 — active credential pointer (cfg.LLMProfile) wins.
	// This mirrors the composite resolver's defaultCatalogPick
	// (internal/llm/resolver.go): when XALGORIX_LLM_PROFILE names a
	// "<provider>:<profileId>" that resolves to a live
	// (Auth_Profile, Catalog_Entry) pair, that profile's endpoint
	// is used directly rather than the catalog's first-entry
	// default. Without this branch a scan with no per-request
	// ProviderProfile but a configured active profile would
	// silently fall through to entries[0] (or the legacy path) and
	// drop the operator's chosen credentials.
	if cfg != nil && strings.TrimSpace(cfg.LLMProfile) != "" && s.catalog != nil && s.profiles != nil {
		key := strings.TrimSpace(cfg.LLMProfile)
		if prof, ok, err := s.profiles.Get(ctx, key); err == nil && ok {
			if entry, ok, err := s.catalog.Get(ctx, prof.Provider); err == nil && ok {
				// The operator's typed model (cfg.LLM, stripped of
				// any "<provider>/" prefix) wins over the catalog
				// default so XALGORIX_LLM=google/gemini-test-model
				// routes to gemini-test-model rather than the
				// catalog's first listed model.
				preferModel := modelForConfiguredProvider(cfg.LLM, prof.Provider)
				if ep, berr := llm.BuildCatalogEndpoint(entry, prof, preferModel, cfg.APIBase); berr == nil {
					return ep
				}
			}
		}
	}

	// Branch 1 — catalog default pick.
	if s.catalog != nil && !s.catalog.IsEmpty() {
		entries, err := s.catalog.List(ctx)
		if err == nil && len(entries) > 0 {
			entry := entries[0]
			if s.profiles != nil {
				profs, err := s.profiles.List(ctx)
				if err == nil {
					for _, p := range profs {
						if p.Provider != entry.ID {
							continue
						}
						if ep, berr := llm.BuildCatalogEndpoint(entry, p, "", cfg.APIBase); berr == nil {
							return ep
						}
					}
				}
			}
		}
	}

	// Branch 2 — Legacy_Fallback. Only engages when the operator's
	// XALGORIX_LLM names one of the eight known legacy slugs;
	// arbitrary custom values fall through to branch 3.
	if cfg != nil && llm.LegacyProviderShape(cfg.LLM) {
		r := llm.NewCompositeResolver(llm.WithLegacy(cfg))
		if ep, err := r.Resolve(ctx); err == nil {
			return ep
		}
	}

	// Branch 3 — neither a catalog default nor a legacy match.
	// Return a zero Endpoint and let the ad-hoc override merge
	// (or, ultimately, the LLM client's own resolver) decide what
	// to do. This avoids stamping a stale URL onto the request
	// when the operator is supplying APIBase/APIKey/Model fields
	// directly.
	return llm.Endpoint{}
}
