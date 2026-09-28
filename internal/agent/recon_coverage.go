// Package agent — recon_coverage.go gives ReconCoverage what it was missing:
// a REAL mutation path for N/A dispositions (NAMarked was only ever read —
// no code could set it) and per-application-host completion semantics so one
// wordlist pass on app.example.com cannot silently satisfy
// api.example.com/admin.example.com. The typed API is driven by update_plan
// disposition notes on the recon task; dispositions are bounded to a closed
// dimension set so the model cannot invent dimensions.
package agent

import (
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
	"content_discovery":   "content_discovery",
	"historical":          "historical",
	"historical_urls":     "historical",
	"wayback":             "historical",
}

// MarkReconDimensionNA records a typed not-applicable disposition for a recon
// dimension. Only dimensions in the closed set are accepted; an unknown name
// is rejected (returns false) so dispositions stay auditable.
func MarkReconDimensionNA(state *ScanState, dimension string) bool {
	if state == nil {
		return false
	}
	key, ok := reconDimensionAliases[strings.ToLower(strings.TrimSpace(dimension))]
	if !ok {
		return false
	}
	if state.ReconCoverage.NAMarked == nil {
		state.ReconCoverage.NAMarked = make(map[string]bool)
	}
	state.ReconCoverage.NAMarked[key] = true
	return true
}

// reconHostDispositionValues are the accepted per-host discovery dispositions.
var reconHostDispositionValues = map[string]string{
	"na":                    "not_applicable",
	"not_applicable":        "not_applicable",
	"not-applicable":        "not_applicable",
	"blocked":               "blocked",
	"unreachable":           "blocked",
	"equivalent":            "covered_by_equivalent_app",
	"covered_by_equivalent": "covered_by_equivalent_app",
	"same_app":              "covered_by_equivalent_app",
}

// applyReconDispositions parses typed disposition lines from an update_plan
// note on a structural (non-coverage) task and applies them:
//
//	"service_discovery: raw IP target, no ports beyond HTTP"   → NAMarked
//	"host api.example.com: covered_by_equivalent_app"          → host disposition
//
// Only closed-set dimension names and disposition values are accepted; every
// applied line is echoed back so the tool result shows exactly what the engine
// recorded. This is the single real mutation path behind NAMarked.
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
				continue
			}
			if state.ReconHostDispositions == nil {
				state.ReconHostDispositions = make(map[string]string)
			}
			state.ReconHostDispositions[host] = mapped
			applied = append(applied, "host "+host+": "+mapped)
			continue
		}
		// Dimension N/A line: "dimension: reason"
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		dim := strings.TrimSpace(line[:colon])
		if MarkReconDimensionNA(state, dim) {
			applied = append(applied, "recon dimension "+reconDimensionAliases[strings.ToLower(dim)]+": not_applicable")
		}
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
// the endpoint inventory (bounded). Path-only inventory entries carry no host
// and are skipped.
func distinctApplicationHosts(state *ScanState) []string {
	if state == nil {
		return nil
	}
	seen := make(map[string]bool)
	var hosts []string
	for _, ep := range state.DiscoveredEndpoints {
		host := hostOfEndpoint(ep)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
		if len(hosts) >= maxReconHostRequirement {
			break
		}
	}
	sort.Strings(hosts)
	return hosts
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

// parameterizedSurfaceExists reports observed input-bearing surface: seeded
// parameters, or any observed state-changing method. When one exists,
// parameter/input discovery becomes a required recon dimension.
func parameterizedSurfaceExists(state *ScanState) bool {
	if state == nil {
		return false
	}
	if state.ReconCoverage.ParamDiscovered {
		return true
	}
	for _, se := range state.SeededSurface {
		if len(se.Params) > 0 {
			return true
		}
	}
	for _, method := range state.ObservedEndpointMethods {
		switch method {
		case "POST", "PUT", "PATCH", "DELETE":
			return true
		}
	}
	return false
}
