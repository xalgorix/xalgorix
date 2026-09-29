// Package agent — recon_coverage.go gives ReconCoverage what it was missing:
// a REAL mutation path for N/A dispositions (NAMarked was only ever read —
// no code could set it) and per-application-host completion semantics so one
// wordlist pass on app.example.com cannot silently satisfy
// api.example.com/admin.example.com. The typed API is driven by update_plan
// disposition notes on the recon task; dispositions are bounded to a closed
// dimension set so the model cannot invent dimensions.
package agent

import (
	"fmt"
	"sort"
	"strings"
)

// reconDimensionAliases is the closed set of ReconCoverage dimensions that
// accept typed N/A dispositions, with the spellings models actually use.
var reconDimensionAliases = map[string]string{
	"dns":                 "dns",
	"dns_resolution":      "dns",
	"service_discovery":   "service_discovery",
	"services":            "service_discovery",
	"port_scan":           "service_discovery",
	"port_scanning":       "service_discovery",
	"tech_fingerprint":    "tech_fingerprint",
	"tech_fingerprinting": "tech_fingerprint",
	"technology":          "tech_fingerprint",
	"crawling":            "crawling",
	"crawl":               "crawling",
	"js_analysis":         "js_analysis",
	"javascript_analysis": "js_analysis",
	"api_surface":         "api_surface",
	"api_discovery":       "api_surface",
	"parameter_discovery": "parameter_discovery",
	"param_discovery":     "parameter_discovery",
	"input_discovery":     "parameter_discovery",
	"auth_mapping":        "auth_mapping",
	"subdomain_discovery": "subdomain_discovery",
	"subdomains":          "subdomain_discovery",
	"subdomain_enum":      "subdomain_discovery",
	"content_discovery":   "content_discovery",
	"historical":          "historical",
	"historical_urls":     "historical",
	"wayback":             "historical",
}

// reconDispositionValues are the accepted typed disposition values for
// recon dimensions. The disposition keyword must be EXPLICIT: "not_applicable"
// (with its common spellings) or "blocked" (with "unreachable" as a synonym).
// Anything else - "failed", "done", arbitrary prose - is not a disposition.
var reconDispositionValues = map[string]string{
	"not_applicable": "not_applicable",
	"not-applicable": "not_applicable",
	"na":             "not_applicable",
	"n/a":            "not_applicable",
	"blocked":        "blocked",
	"unreachable":    "blocked",
}

// markReconDisposition records a typed terminal disposition for a recon
// dimension after validating it against engine evidence. N/A is rejected
// when the engine already holds contradictory surface evidence (API routes
// exist, JS assets exist, an auth surface exists, a parameterized surface
// exists, or the configured scope makes the dimension apply). Blocked is
// distinct from N/A and always accepted as a terminal state: it records that
// the work was attempted and could not proceed, never that it did not apply.
// Returns an error string when the disposition is rejected.
func markReconDisposition(state *ScanState, dimension, value string) error {
	if state == nil {
		return fmt.Errorf("no scan state")
	}
	key, ok := reconDimensionAliases[strings.ToLower(strings.TrimSpace(dimension))]
	if !ok {
		return fmt.Errorf("unknown recon dimension %q", dimension)
	}
	mapped, ok := reconDispositionValues[strings.ToLower(strings.TrimSpace(value))]
	if !ok {
		return fmt.Errorf("unrecognized disposition %q (accepted: not_applicable | blocked)", value)
	}
	if mapped == "not_applicable" && reconNAContradicted(state, key) {
		return fmt.Errorf("not_applicable for %q is contradicted by observed surface evidence", key)
	}
	if state.ReconCoverage.Dispositions == nil {
		state.ReconCoverage.Dispositions = make(map[string]string)
	}
	state.ReconCoverage.Dispositions[key] = mapped
	if mapped == "not_applicable" {
		if state.ReconCoverage.NAMarked == nil {
			state.ReconCoverage.NAMarked = make(map[string]bool)
		}
		state.ReconCoverage.NAMarked[key] = true
	}
	return nil
}

// MarkReconDimensionNA records a typed not-applicable disposition. Returns
// false (and records nothing) when the dimension name is unknown, or engine
// evidence contradicts the N/A. The typed syntax in update_plan notes is
// "dimension: not_applicable \u2014 reason"; a bare "dimension: <prose>" line
// is NOT accepted.
func MarkReconDimensionNA(state *ScanState, dimension string) bool {
	return markReconDisposition(state, dimension, "not_applicable") == nil
}

// MarkReconDispositionBlocked records a typed blocked disposition
// ("dimension: blocked \u2014 reason").
func MarkReconDispositionBlocked(state *ScanState, dimension string) bool {
	return markReconDisposition(state, dimension, "blocked") == nil
}

// reconNAContradicted reports whether engine knowledge contradicts an N/A
// disposition for a dimension. The engine never blindly clears a requirement
// the surface itself disproves: API evidence blocks a false api_surface N/A,
// JS assets block a false js_analysis N/A, an auth surface blocks a false
// auth_mapping N/A, observed inputs block a false parameter_discovery N/A,
// and a domain/wildcard scope blocks dismissing subdomain enumeration merely
// because the model does not want to perform it.
func reconNAContradicted(state *ScanState, dim string) bool {
	switch dim {
	case "api_surface":
		return apiSignalsExist(state)
	case "js_analysis":
		return jsAnalysisApplicable(state)
	case "auth_mapping":
		return authSurfaceExists(state)
	case "parameter_discovery":
		return parameterizedSurfaceExists(state)
	case "subdomain_discovery":
		return subdomainScopeApplicable(state)
	}
	return false
}

// reconHostDispositionValues are the accepted per-host discovery dispositions.
var reconHostDispositionValues = map[string]string{
	"na":                        "not_applicable",
	"not_applicable":            "not_applicable",
	"not-applicable":            "not_applicable",
	"blocked":                   "blocked",
	"unreachable":               "blocked",
	"equivalent":                "covered_by_equivalent_app",
	"covered_by_equivalent":     "covered_by_equivalent_app",
	"covered_by_equivalent_app": "covered_by_equivalent_app",
	"same_app":                  "covered_by_equivalent_app",
}

// applyReconDispositions parses TYPED disposition lines from an update_plan
// note on a structural (non-coverage) task and applies them. The disposition
// keyword must be explicit:
//
//	"api_surface: not_applicable — no API/XHR/GraphQL evidence after crawl + JS analysis"
//	"service_discovery: blocked — network policy prevents port scanning"
//	"historical: not_applicable — private localhost fixture"
//	"host admin.example.com: blocked — unreachable after bounded retries"
//	"host api.example.com: covered_by_equivalent_app — identical deployment fingerprint"
//
// A line whose value is not a recognized disposition ("api_surface: failed",
// or arbitrary prose after the colon) is NOT applied - it is echoed back as
// rejected so the model can correct the syntax. N/A dispositions are
// validated against engine evidence; blocked and not_applicable are recorded
// as distinct typed states. This is the single real mutation path behind
// NAMarked / Dispositions.
func applyReconDispositions(state *ScanState, notes string) []string {
	if state == nil || strings.TrimSpace(notes) == "" {
		return nil
	}
	var applied []string
	for _, rawLine := range strings.FieldsFunc(notes, func(r rune) bool { return r == '\n' || r == ';' }) {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host ") {
			rest := strings.TrimSpace(line[len("host "):])
			colon := strings.Index(rest, ":")
			if colon <= 0 {
				continue
			}
			host := strings.ToLower(strings.TrimSpace(rest[:colon]))
			// The disposition is the first word after the colon; the rest of
			// the line is the evidence reason ("blocked - WAF blocks
			// enumeration").
			valueRest := strings.TrimSpace(rest[colon+1:])
			value := strings.ToLower(strings.Fields(valueRest)[0])
			mapped, ok := reconHostDispositionValues[value]
			if !ok || host == "" {
				applied = append(applied, "rejected: unrecognized host disposition — line: "+line)
				continue
			}
			if state.ReconHostDispositions == nil {
				state.ReconHostDispositions = make(map[string]string)
			}
			state.ReconHostDispositions[host] = mapped
			applied = append(applied, "host "+host+": "+mapped)
			continue
		}
		// Dimension disposition line: "dimension: <disposition> — reason".
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		dim := strings.TrimSpace(line[:colon])
		valueRest := strings.TrimSpace(line[colon+1:])
		if valueRest == "" {
			continue
		}
		value := strings.Fields(valueRest)[0]
		if err := markReconDisposition(state, dim, value); err != nil {
			applied = append(applied, "rejected: "+err.Error()+" — line: "+line)
			continue
		}
		mapped := reconDispositionValues[strings.ToLower(value)]
		applied = append(applied, "recon dimension "+reconDimensionAliases[strings.ToLower(strings.TrimSpace(dim))]+": "+mapped)
	}
	sort.Strings(applied)
	return applied
}

// maxReconHostRequirement bounds per-host content-discovery enforcement: the
// first distinct hosts from the inventory are required (or must be
// dispositioned); anything beyond that is advisory — a large host set is
// dispositioned, never blindly brute-forced.
const maxReconHostRequirement = 4

// distinctApplicationHosts returns the host-qualified applications surfaced by
// the surface (bounded, DETERMINISTIC). All candidates are gathered FIRST,
// then ranked: hosts with meaningful web-application signals (admin/api/auth/
// app/files/workflow roles) outrank arbitrary names, live-traffic evidence
// adds weight, and ties break alphabetically - never by Go map iteration
// order. The same input produces the same required hosts every run.
func distinctApplicationHosts(state *ScanState) []string {
	if state == nil {
		return nil
	}
	seen := make(map[string]bool)
	candidates := make([]string, 0, len(state.DiscoveredEndpoints)+len(state.DiscoveredHosts))
	add := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		candidates = append(candidates, host)
	}
	for _, ep := range state.DiscoveredEndpoints {
		add(hostOfEndpoint(ep))
	}
	// Bare hostnames surfaced by DNS/subdomain/crawl results (they may never
	// appear as full URLs inside the inventory) still owe content-discovery
	// dispositions — losing them was silently untested surface.
	for host := range state.DiscoveredHosts {
		add(host)
	}
	type rankedHost struct {
		host  string
		score int
	}
	ranked := make([]rankedHost, 0, len(candidates))
	for _, host := range candidates {
		ranked = append(ranked, rankedHost{host: host, score: applicationHostScore(state, host)})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].host < ranked[j].host
	})
	hosts := make([]string, 0, maxReconHostRequirement)
	for _, r := range ranked {
		if len(hosts) >= maxReconHostRequirement {
			break
		}
		hosts = append(hosts, r.host)
	}
	return hosts
}

// applicationHostScore ranks a candidate application host. Role signals
// provide the professional priority (admin/api/auth/app/files before
// workflow/payment, before other names); hosts that appeared inside live
// observed traffic get a bonus; hostname text alone is the weakest signal.
func applicationHostScore(state *ScanState, host string) int {
	l := strings.ToLower(host)
	score := 0
	switch {
	case strings.Contains(l, "admin"):
		score += 60
	case strings.Contains(l, "api"):
		score += 55
	case strings.Contains(l, "auth"), strings.Contains(l, "sso"):
		score += 50
	case strings.Contains(l, "app"), strings.Contains(l, "portal"):
		score += 45
	case strings.Contains(l, "files"), strings.Contains(l, "static"), strings.Contains(l, "upload"):
		score += 40
	case strings.Contains(l, "pay"), strings.Contains(l, "shop"), strings.Contains(l, "checkout"),
		strings.Contains(l, "billing"), strings.Contains(l, "workflow"):
		score += 35
	}
	if state != nil {
		for _, ep := range state.DiscoveredEndpoints {
			if hostOfEndpoint(ep) == l {
				score += 10 // surfaced inside live observed traffic
				break
			}
		}
	}
	return score
}

// hostOfEndpoint extracts a hostname from an inventory endpoint, or "" for
// path-only entries.
func hostOfEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.HasPrefix(endpoint, "/") {
		return ""
	}
	rest := endpoint
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rest, prefix) {
			rest = rest[len(prefix):]
			break
		}
	}
	if cut := strings.IndexAny(rest, "/?#"); cut > 0 {
		rest = rest[:cut]
	}
	if rest == "" || !strings.ContainsAny(rest, ".:") {
		return ""
	}
	return strings.ToLower(rest)
}

// reconHostDispositioned reports whether a host carries a typed discovery
// disposition (not_applicable, blocked, or covered-by-equivalent-app).
func reconHostDispositioned(state *ScanState, host string) bool {
	if state == nil {
		return false
	}
	return state.ReconHostDispositions[host] != ""
}

// apiSignalsExist reports observed API-surface signals: an artifact-seeded API
// surface, an /api/ or /graphql path in the inventory, or GraphQL tech
// detection. When these exist, API-surface discovery becomes a required recon
// dimension (unless dispositioned N/A).
func apiSignalsExist(state *ScanState) bool {
	if state == nil {
		return false
	}
	if state.ReconCoverage.APISurfaceDiscovered {
		return true
	}
	if state.DetectedTechs["graphql"] {
		return true
	}
	for _, se := range state.SeededSurface {
		if strings.Contains(strings.ToLower(se.Path), "/api/") || isGraphQLPath(se.Path) {
			return true
		}
	}
	for _, ep := range state.DiscoveredEndpoints {
		if strings.Contains(strings.ToLower(ep), "/api/") || isGraphQLPath(ep) {
			return true
		}
	}
	return false
}

// authSurfaceExists reports an observed authentication surface: auth-keyword
// inventory paths, a captured session, or an already-mapped auth state. When
// one exists, auth mapping becomes a required recon dimension.
func authSurfaceExists(state *ScanState) bool {
	if state == nil {
		return false
	}
	if state.ReconCoverage.AuthMapped != "" {
		return true
	}
	if state.AuthContextAvailable {
		return true
	}
	for _, ep := range state.DiscoveredEndpoints {
		if containsAnyKeyword(ep, authPathKeywords) {
			return true
		}
	}
	return false
}

// parameterizedSurfaceExists reports observed input-bearing surface.
// Applicability activates from MORE than already-observed state-changing
// methods: HTML forms, query-string links, seeded parameters (OpenAPI/HAR/
// Postman, GraphQL variables), and route templates all make input discovery
// an obligation — a /search route in the inventory owes parameter discovery
// even before any POST has been seen.
func parameterizedSurfaceExists(state *ScanState) bool {
	if state == nil {
		return false
	}
	if state.ReconCoverage.ParamDiscovered {
		return true
	}
	if state.FormsObserved {
		return true
	}
	for _, se := range state.SeededSurface {
		if len(se.Params) > 0 {
			return true
		}
	}
	for _, methods := range state.ObservedEndpointMethods {
		for m := range methods {
			switch m {
			case "POST", "PUT", "PATCH", "DELETE":
				return true
			}
		}
	}
	// Runtime black-box parameter observations count the same way: an
	// endpoint that carries observed inputs owes input discovery.
	for _, params := range state.ObservedEndpointParameters {
		if len(params) > 0 {
			return true
		}
	}
	for _, ep := range state.DiscoveredEndpoints {
		if strings.Contains(ep, "?") {
			return true
		}
	}
	return false
}
