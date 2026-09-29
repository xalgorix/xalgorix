// Package agent - surface_observe.go is the single central path for black-box
// surface observation. Every request-capable tool funnels its concrete
// endpoint/method/content-type/parameter evidence through
// RecordSurfaceObservation, so the structured attack surface is enriched
// consistently no matter which tool produced the traffic (terminal curl,
// http_request/send_request, browser, verify_* probes, HAR/OpenAPI seeding).
// The structured surface - not free-form note text - is the authoritative
// source the applicability engine and the planner consume; the note inventory
// remains the human/model-facing mirror and a compatibility fallback.
package agent

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// SurfaceObservation is one machine-readable observation about the live
// surface: what was requested, how, and with which inputs.
type SurfaceObservation struct {
	Endpoint    string
	Method      string
	ContentType string
	Parameters  []SurfaceParameter
	Source      string // request | browser | crawler | js | api | forms | manual | context
	Promote     bool   // fold the endpoint into the discovered inventory
}

const (
	maxObservedParamsPerEndpoint = 24
	maxPromotedEndpoints         = 150
)

// RecordSurfaceObservation merges one observation into the structured
// surface. Method, content type, parameters, and provenance are recorded per
// endpoint; the endpoint itself enters the discovered inventory when the
// observation marks a discovery result. Recording is idempotent and
// deterministic: repeated observations of the same fact change nothing.
func RecordSurfaceObservation(state *ScanState, obs SurfaceObservation) {
	if state == nil {
		return
	}
	endpoint := strings.TrimSpace(obs.Endpoint)
	if endpoint == "" {
		return
	}
	// Probe-artifact URLs (OAST callbacks, attacker-legend origins from
	// payload headers) are scanner-side traffic, never target surface:
	// ingesting them pollutes the inventory and inflates obligations.
	if isScanArtifactURL(endpoint) {
		return
	}
	if m := strings.ToUpper(strings.TrimSpace(obs.Method)); m != "" {
		recordEndpointMethod(state, endpoint, m)
	}
	if ct := strings.TrimSpace(obs.ContentType); ct != "" {
		recordEndpointContentType(state, endpoint, ct)
	}
	if len(obs.Parameters) > 0 {
		recordEndpointParameters(state, endpoint, obs.Parameters)
	}
	if src := strings.TrimSpace(obs.Source); src != "" {
		recordEndpointProvenance(state, endpoint, src)
	}
	if obs.Promote {
		promoteDiscoveredEndpoint(state, endpoint)
	}
	// Auth-flow modeling: a live observation of an auth-family path both
	// discovers and maps that flow family.
	if f, ok := authFlowFamilyOfPath(endpoint); ok {
		markAuthFlowMapped(state, f)
	}
}

// recordEndpointParameters merges parameter observations for one endpoint,
// deduplicating on (name, location), sorting deterministically, and bounding
// the per-endpoint set.
func recordEndpointParameters(state *ScanState, endpoint string, params []SurfaceParameter) {
	if len(params) == 0 {
		return
	}
	if state.ObservedEndpointParameters == nil {
		state.ObservedEndpointParameters = make(map[string][]SurfaceParameter)
	}
	merged := append([]SurfaceParameter(nil), state.ObservedEndpointParameters[endpoint]...)
	seen := make(map[string]bool, len(merged)+len(params))
	for _, p := range merged {
		seen[p.Name+":"+p.Location] = true
	}
	for _, p := range params {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" || len(p.Name) > 64 {
			continue
		}
		if p.Location == "" {
			p.Location = "unknown"
		}
		key := p.Name + ":" + p.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, p)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Name != merged[j].Name {
			return merged[i].Name < merged[j].Name
		}
		return merged[i].Location < merged[j].Location
	})
	if len(merged) > maxObservedParamsPerEndpoint {
		merged = merged[:maxObservedParamsPerEndpoint]
	}
	state.ObservedEndpointParameters[endpoint] = merged
}

// recordEndpointProvenance records where an endpoint was observed. Multiple
// sources accumulate; reads sort for determinism.
func recordEndpointProvenance(state *ScanState, endpoint, source string) {
	if state.EndpointProvenance == nil {
		state.EndpointProvenance = make(map[string]map[string]bool)
	}
	set, ok := state.EndpointProvenance[endpoint]
	if !ok {
		set = make(map[string]bool)
		state.EndpointProvenance[endpoint] = set
	}
	set[source] = true
}

// endpointProvenance returns the sorted observation sources of an endpoint.
func endpointProvenance(state *ScanState, endpoint string) []string {
	if state == nil || state.EndpointProvenance == nil {
		return nil
	}
	set := state.EndpointProvenance[endpoint]
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// promoteDiscoveredEndpoint folds an observed endpoint into the discovered
// inventory (deduplicated via coverage aliases, bounded). The structured
// surface is authoritative: real observed traffic defines the attack surface.
func promoteDiscoveredEndpoint(state *ScanState, endpoint string) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || isScanArtifactURL(endpoint) || len(state.DiscoveredEndpoints) >= maxPromotedEndpoints {
		return
	}
	want := map[string]bool{}
	for _, a := range endpointCoverageAliases(endpoint) {
		want[a] = true
	}
	for _, existing := range state.DiscoveredEndpoints {
		if existing == endpoint {
			return
		}
		for _, a := range endpointCoverageAliases(existing) {
			if want[a] {
				return
			}
		}
	}
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, endpoint)
	sort.Strings(state.DiscoveredEndpoints)
}

// mergeDiscoveredEndpoints merges the notes-derived inventory (compatibility
// fallback) with the structured observations, deduplicating by coverage alias
// and keeping the result sorted and bounded.
func mergeDiscoveredEndpoints(state *ScanState, fromNotes []string) []string {
	if state == nil {
		return fromNotes
	}
	aliases := map[string]bool{}
	var out []string
	for _, ep := range append(append([]string(nil), state.DiscoveredEndpoints...), fromNotes...) {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		seen := false
		for _, a := range endpointCoverageAliases(ep) {
			if aliases[a] {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		for _, a := range endpointCoverageAliases(ep) {
			aliases[a] = true
		}
		out = append(out, ep)
		if len(out) >= maxPromotedEndpoints {
			break
		}
	}
	sort.Strings(out)
	return out
}

// ── Parameter extraction (black-box primary) ────────────────────────────────

// paramNameRe bounds a plausible parameter name.
var paramNameRe = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)

func validParamName(s string) bool { return paramNameRe.MatchString(s) }

// paramsFromURLQuery extracts query-parameter names from a URL string.
func paramsFromURLQuery(rawURL string) []SurfaceParameter {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(q))
	for name := range q {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []SurfaceParameter
	for _, n := range names {
		if validParamName(n) {
			out = append(out, SurfaceParameter{Name: n, Location: "query"})
		}
	}
	return out
}

// jsonKeyRe matches object keys in a JSON body (bounded to 8KB; any depth -
// parameter names are applicability signals, never proof).
var jsonKeyRe = regexp.MustCompile(`"([^"{}]{1,64})"\s*:`)

func topLevelJSONKeys(body string) []string {
	if len(body) > 8192 {
		body = body[:8192]
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range jsonKeyRe.FindAllStringSubmatch(body, maxObservedParamsPerEndpoint*2) {
		k := m[1]
		if !validParamName(k) || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= maxObservedParamsPerEndpoint {
			break
		}
	}
	sort.Strings(out)
	return out
}

// paramsFromRequestBody classifies a request body and extracts its input
// names: JSON keys, or form-encoded k=v pairs.
func paramsFromRequestBody(value string) []SurfaceParameter {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "{") {
		var out []SurfaceParameter
		for _, k := range topLevelJSONKeys(value) {
			out = append(out, SurfaceParameter{Name: k, Location: "body"})
		}
		return out
	}
	var out []SurfaceParameter
	for _, pair := range strings.Split(value, "&") {
		if idx := strings.Index(pair, "="); idx > 0 {
			name := pair[:idx]
			if validParamName(name) {
				out = append(out, SurfaceParameter{Name: name, Location: "form"})
			}
		}
	}
	return dedupeParams(out)
}

// curlDataRe/curlDFlagRe/curlFormRe match curl body/multipart flags with their
// values (--data, -d, --json, -F and variants).
var curlDataRe = regexp.MustCompile(`(?i)(?:--data(?:-(?:raw|binary|urlencode))?|--json)\s+(?:"([^"]*)"|'([^']*)'|(\S+))`)
var curlDFlagRe = regexp.MustCompile(`(?:^|[\s=])-d\s+(?:"([^"]*)"|'([^']*)'|(\S+))`)
var curlFormRe = regexp.MustCompile(`(?i)(?:-F|--form)\s+(?:"([^"]*)"|'([^']*)'|(\S+))`)

// paramsFromCommand extracts observed parameters from a curl-like command:
// query strings of embedded URLs, --data/-d bodies (form or JSON), and -F
// multipart field names.
func paramsFromCommand(cmd string) []SurfaceParameter {
	var out []SurfaceParameter
	for _, m := range absoluteHTTPURLPattern.FindAllString(cmd, 16) {
		out = append(out, paramsFromURLQuery(m)...)
	}
	for _, re := range []*regexp.Regexp{curlDataRe, curlDFlagRe} {
		for _, m := range re.FindAllStringSubmatch(cmd, 8) {
			value := firstNonEmpty(m[1:]...)
			out = append(out, paramsFromRequestBody(value)...)
		}
	}
	for _, m := range curlFormRe.FindAllStringSubmatch(cmd, 8) {
		value := firstNonEmpty(m[1:]...)
		if name := multipartFieldName(value); name != "" {
			out = append(out, SurfaceParameter{Name: name, Location: "multipart"})
		}
	}
	return dedupeParams(out)
}

// pyDictKeyRe matches data={...}/json={...}/params={...} dicts in python code.
var pyDictKeyRe = regexp.MustCompile(`(?i)(?:data|params|json)\s*=\s*\{([^}]*)\}`)

// paramsFromPythonCode extracts parameters from python request code: URLs
// with query strings plus data/json/params dict keys.
func paramsFromPythonCode(code string) []SurfaceParameter {
	var out []SurfaceParameter
	for _, m := range absoluteHTTPURLPattern.FindAllString(code, 16) {
		out = append(out, paramsFromURLQuery(m)...)
	}
	for _, m := range pyDictKeyRe.FindAllStringSubmatch(code, 8) {
		for _, k := range topLevelJSONKeys("{" + m[1] + "}") {
			if validParamName(k) {
				out = append(out, SurfaceParameter{Name: k, Location: "body"})
			}
		}
	}
	return dedupeParams(out)
}

// paramsFromToolArgs extracts parameters from http_request/send_request/
// browser tool args: the URL query string plus body/data/json payloads.
func paramsFromToolArgs(args map[string]string) []SurfaceParameter {
	var out []SurfaceParameter
	for _, key := range []string{"url", "target", "endpoint"} {
		if v := strings.TrimSpace(args[key]); v != "" {
			out = append(out, paramsFromURLQuery(v)...)
			break
		}
	}
	for _, key := range []string{"body", "data", "json", "payload", "post_data", "form_data", "request_body"} {
		if v := strings.TrimSpace(args[key]); v != "" {
			out = append(out, paramsFromRequestBody(v)...)
		}
	}
	return dedupeParams(out)
}

// multipartFieldName extracts the field name from a curl -F value
// (name=@file or name=value).
func multipartFieldName(value string) string {
	if idx := strings.Index(value, "="); idx > 0 {
		name := value[:idx]
		if validParamName(name) {
			return name
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func dedupeParams(in []SurfaceParameter) []SurfaceParameter {
	seen := map[string]bool{}
	out := make([]SurfaceParameter, 0, len(in))
	for _, p := range in {
		key := p.Name + ":" + p.Location
		if seen[key] || p.Name == "" {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// formBlockRe/formActionRe/formInputNameRe parse HTML form evidence from tool
// results so form fields become structured parameters on their action
// endpoint.
var formBlockRe = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
var formActionRe = regexp.MustCompile(`(?is)<form\b[^>]*?action\s*=\s*["']?([^"'\s>]+)`)
var formInputNameRe = regexp.MustCompile(`(?is)<(?:input|select|textarea)\b[^>]*?name\s*=\s*["']?([A-Za-z0-9_.\[\]-]+)`)

// recordFormsFromHTML extracts form fields and their action endpoints from an
// HTML tool result. Forms without an action attribute only flip
// FormsObserved (they cannot be attributed to an endpoint).
func recordFormsFromHTML(state *ScanState, html string) {
	if state == nil || !strings.Contains(strings.ToLower(html), "<form") {
		return
	}
	state.FormsObserved = true
	for _, block := range formBlockRe.FindAllString(html, 16) {
		action := ""
		if m := formActionRe.FindStringSubmatch(block); m != nil {
			action = strings.TrimSpace(m[1])
		}
		if action == "" {
			continue
		}
		endpoint := extractEndpointFromCmd(action)
		if endpoint == "" {
			endpoint = action
		}
		var params []SurfaceParameter
		for _, m := range formInputNameRe.FindAllStringSubmatch(block, maxObservedParamsPerEndpoint) {
			if validParamName(m[1]) {
				params = append(params, SurfaceParameter{Name: m[1], Location: "form"})
			}
		}
		if len(params) > 0 {
			RecordSurfaceObservation(state, SurfaceObservation{
				Endpoint:   endpoint,
				Parameters: params,
				Source:     "forms",
				Promote:    true,
			})
		}
	}
}

// ── Auth flow families ──────────────────────────────────────────────────────

// authFlowFamilies is the closed, deterministically ordered set of auth flow
// families the engine models. The engine first discovers which families exist
// on the target; it never demands mechanisms that were not observed.
var authFlowFamilies = []string{
	"password_reset",
	"registration",
	"logout",
	"oauth",
	"mfa",
	"token",
	"login",
}

var authFlowKeywords = map[string][]string{
	"password_reset": {"password-reset", "password_reset", "forgot-password", "forgot_password", "reset-password", "resetpass", "account-recovery", "recover"},
	"registration":   {"register", "signup", "sign-up", "registration"},
	"logout":         {"logout", "signout", "sign-out"},
	"oauth":          {"oauth", "oidc", "sso", "authorize"},
	"mfa":            {"mfa", "otp", "two-factor", "2fa", "one-time-password"},
	"token":          {"refresh-token", "access-token", "token-issue", "jwt"},
	"login":          {"login", "signin", "sign-in", "log-in", "auth", "session"},
}

// authFlowFamilyOfPath classifies an endpoint into an auth flow family.
// Earlier families win (password_reset before login; oauth before the
// auth-substring catch-all).
func authFlowFamilyOfPath(endpoint string) (string, bool) {
	l := strings.ToLower(endpoint)
	for _, family := range authFlowFamilies {
		if containsAnyKeyword(l, authFlowKeywords[family]) {
			return family, true
		}
	}
	return "", false
}

// authFlowsFromText reports the flow families referenced anywhere in a text
// (e.g. a validated auth-mapping result).
func authFlowsFromText(text string) []string {
	l := strings.ToLower(text)
	var out []string
	for _, family := range authFlowFamilies {
		if containsAnyKeyword(l, authFlowKeywords[family]) {
			out = append(out, family)
		}
	}
	return out
}

// authFlowsObservedForState derives the observed flow families from the
// discovered surface (deterministic order).
func authFlowsObservedForState(state *ScanState) []string {
	if state == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, ep := range state.DiscoveredEndpoints {
		if f, ok := authFlowFamilyOfPath(ep); ok {
			seen[f] = true
		}
	}
	for _, se := range state.SeededSurface {
		if f, ok := authFlowFamilyOfPath(se.Path); ok {
			seen[f] = true
		}
	}
	var out []string
	for _, family := range authFlowFamilies {
		if seen[family] {
			out = append(out, family)
		}
	}
	return out
}

// authFlowsUnmapped lists observed flow families without mapping evidence.
func authFlowsUnmapped(state *ScanState) []string {
	var out []string
	for _, family := range authFlowsObservedForState(state) {
		if !state.AuthFlowsMapped[family] {
			out = append(out, family)
		}
	}
	return out
}

// markAuthFlowMapped records mapping evidence for one auth flow family.
func markAuthFlowMapped(state *ScanState, family string) {
	if state == nil || family == "" {
		return
	}
	if state.AuthFlowsMapped == nil {
		state.AuthFlowsMapped = make(map[string]bool)
	}
	state.AuthFlowsMapped[family] = true
}
