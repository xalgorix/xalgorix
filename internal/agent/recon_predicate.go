package agent

// recon_predicate.go holds THE authoritative comprehensive-recon predicate.
// Before this file existed, four different definitions of "recon complete"
// coexisted and disagreed: the legacy ReconDone boolean (set the moment a
// recon-looking COMMAND was merely executed), the "recon" plan task
// (reconcilePlan completed it from the same boolean), reconPhaseComplete()
// (the wave gate), and the professional finish gate (three ad-hoc flag
// checks). Every consumer now derives from ComprehensiveReconComplete /
// ComprehensiveReconMissing below, so one definition governs the recon plan
// task, the specialist wave, the claim lane, and the finish contract.
//
// The predicate is a function of ScanState ONLY — it never consults the
// specialist configuration. With every specialist disabled the required
// reconnaissance is byte-for-byte identical to the wave-enabled scan:
// specialists may accelerate the work, they can never define it.

import (
	"fmt"
	"sort"
	"strings"
)

// ComprehensiveReconComplete reports whether every APPLICABLE recon
// dimension is settled: completed with a VALIDATED result (a real run, not a
// failed command string), or explicitly dispositioned not_applicable /
// blocked via the typed update_plan path. It is the single source of truth
// used by reconcilePlan, reconPhaseComplete, and the professional finish
// gate.
func ComprehensiveReconComplete(state *ScanState) bool {
	return len(ComprehensiveReconMissing(state)) == 0
}

// ComprehensiveReconMissing lists the reconnaissance dimensions still owed,
// using one authoritative reason generator for plan reconciliation, wave
// deferral, and the finish contract. Each entry is a concrete, actionable
// obligation; applicability is evidence-driven (surface signals, configured
// scope, depth mode), so nothing is demanded that the target cannot owe.
func ComprehensiveReconMissing(state *ScanState) []string {
	if state == nil {
		return nil
	}
	s := state
	rc := s.ReconCoverage
	var missing []string
	add := func(format string, args ...any) {
		missing = append(missing, fmt.Sprintf(format, args...))
	}

	// ── Baseline floor (legacy booleans, now result-validated) ──
	if !s.ReconDone {
		add("recon baseline: HTTP fingerprinting of the live surface (curl -sI / whatweb / httpx)")
	}
	if !s.EndpointInventorySaved {
		add("an Endpoint Inventory note listing every live route")
	}
	if !s.DirBustingDone {
		add("content discovery with a real wordlist on the primary host (ffuf/gobuster/dirsearch, -maxtime bounded)")
	}
	if s.DirBustingDone && !s.DirBustingUsedWordlist && !rc.NAMarked["content_discovery"] {
		add("content discovery must run a REAL wordlist pass (ffuf -w common.txt / gobuster -w, bounded -maxtime; a few targeted probes are not content discovery)")
	}
	if len(s.DetectedTechs) == 0 {
		add("technology stack detection (whatweb / server headers)")
	}

	// ── Per-dimension requirements ──
	if !rc.HTTPProbed {
		add("HTTP probing of the live web surface (confirm status, title, redirects)")
	}
	if !rc.TechFingerprinted && !rc.NAMarked["tech_fingerprint"] {
		add("deliberate technology fingerprinting (whatweb / wappalyzer, not just a Server header)")
	}
	if !rc.Crawled && !rc.NAMarked["crawling"] {
		add("web crawling (katana/gospider/sitemap/robots or browser navigation)")
	}
	if len(rc.ContentDiscoveredHosts) == 0 && !rc.NAMarked["content_discovery"] {
		add("content discovery with a real wordlist on the primary host")
	}
	// Per-application coverage: every distinct host the surface surfaced
	// (bounded) must be content-discovered with a validated result or carry a
	// typed disposition. One pass on app.example.com never satisfies
	// api/admin/files.example.com.
	for _, host := range distinctApplicationHosts(s) {
		if rc.ContentDiscoveredHosts[host] || reconHostDispositioned(s, host) {
			continue
		}
		add("content discovery on %s (or a typed disposition via update_plan: \"host %s: blocked/na/covered_by_equivalent\" after bounded retries)", host, host)
	}
	// First-party JS analysis is CONDITIONAL BUT REAL: crawling alone no
	// longer satisfies a surface that ships meaningful client JS.
	if jsAnalysisApplicable(s) && !rc.JSAnalyzed && !rc.NAMarked["js_analysis"] {
		add("JavaScript analysis of first-party bundles (routes, API paths, parameters, WebSocket/GraphQL URLs, source maps, secrets)")
	}
	// API mapping must represent actual discovery, not a 404 probe.
	if apiSignalsExist(s) && !rc.APISurfaceDiscovered && !rc.NAMarked["api_surface"] {
		add("API-surface mapping from real evidence (OpenAPI/Swagger parsed, GraphQL schema examined, or routes extracted from JS/traffic)")
	}
	// Auth SURFACE mapping is separate from credential availability: it can
	// complete without credentials; authenticated testing blocks separately.
	if authSurfaceExists(s) && rc.AuthMapped != "complete" && !rc.NAMarked["auth_mapping"] {
		add("auth surface mapping (login/registration/password-reset/logout/MFA/OAuth/token endpoints, session cookies)")
	}
	// Parameter discovery activates from forms, query strings, seeded
	// parameters, and state-changing methods — not only from POSTs already
	// observed.
	if parameterizedSurfaceExists(s) && !rc.ParamDiscovered && !rc.NAMarked["parameter_discovery"] {
		add("parameter/input discovery (arjun/x8, HTML forms, query strings)")
	}
	// Scope-aware DNS/subdomain discovery: a bare-domain or wildcard scope
	// owes enumeration; a single explicit host does not.
	if subdomainScopeApplicable(s) {
		if !rc.DNSResolved && !rc.NAMarked["dns"] {
			add("DNS resolution of the in-scope domain (dig/nslookup/host)")
		}
		if !rc.SubdomainEnumerated && !rc.NAMarked["subdomain_discovery"] {
			add("subdomain enumeration for the domain scope (subfinder/crt.sh/assetfinder) + live-host probing (httpx)")
		}
	}
	// Historical URLs only for deep scans against public targets: local
	// fixtures and private IPs owe nothing (and may record N/A).
	if historicalApplicable(s) && !rc.HistoricalChecked && !rc.NAMarked["historical"] {
		add("historical URL discovery (gau/waybackurls) for the public target")
	}
	// Deep mode expects additional breadth; standard mode does not inherit
	// deep obligations. Derived from ScanDepth, never from specialists.
	if s.DeepReconRequired {
		if !rc.ServicesProbed && !rc.NAMarked["service_discovery"] {
			add("service/port enumeration (nmap/naabu) — deep mode")
		}
		if !rc.ParamDiscovered && !rc.NAMarked["parameter_discovery"] {
			add("parameter/input discovery — deep mode (arjun/x8, forms, query strings)")
		}
	}
	return missing
}

// jsAnalysisApplicable reports whether the surfaced evidence includes
// meaningful first-party JavaScript: inventory/seeded paths ending in .js/
// .mjs/.map or bundle/chunk/runtime-style assets. When applicable, JS
// analysis is owed before recon can complete (unless dispositioned N/A).
func jsAnalysisApplicable(state *ScanState) bool {
	if state == nil {
		return false
	}
	for _, ep := range state.DiscoveredEndpoints {
		if jsAssetPath(ep) {
			return true
		}
	}
	for _, se := range state.SeededSurface {
		if jsAssetPath(se.Path) {
			return true
		}
	}
	return false
}

// jsAssetPath reports whether a path references a first-party JavaScript or
// source-map asset. SPA bundles, webpack chunks, and .map files all qualify.
func jsAssetPath(path string) bool {
	l := strings.ToLower(strings.TrimSpace(path))
	if l == "" {
		return false
	}
	if strings.HasSuffix(l, ".js") || strings.HasSuffix(l, ".mjs") ||
		strings.HasSuffix(l, ".map") || strings.Contains(l, ".js?") ||
		strings.Contains(l, "bundle") || strings.Contains(l, "chunk") ||
		strings.Contains(l, "runtime.js") {
		return true
	}
	return false
}

// subdomainScopeApplicable reports whether the configured assessment scope
// covers a domain or wildcard rather than a single explicit host. A target of
// https://app.example.com owes nothing; example.com or *.example.com owes
// DNS + enumeration + live-host probing. Targets are not invented: when the
// scope is unknown (no ScanTargets recorded), no obligation is demanded.
func subdomainScopeApplicable(state *ScanState) bool {
	if state == nil {
		return false
	}
	for _, t := range state.ScanTargets {
		raw := strings.TrimSpace(strings.ToLower(t))
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "*.") || strings.HasPrefix(raw, "domain:") {
			return true
		}
		host := hostnameOfTarget(raw)
		if host != "" && isBareDomain(host) {
			return true
		}
	}
	return false
}

// hostnameOfTarget strips scheme, port, path, and wildcard prefix from a
// configured target and returns the bare hostname.
func hostnameOfTarget(raw string) string {
	host := raw
	for _, prefix := range []string{"https://", "http://", "*.", "domain:"} {
		host = strings.TrimPrefix(host, prefix)
	}
	if i := strings.IndexAny(host, "/?#"); i > 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return strings.TrimSpace(host)
}

// isBareDomain reports whether a host is a registrable-domain-level scope
// ("example.com") rather than a single named host ("app.example.com").
// Two labels is the practical convention; deeper public suffixes are treated
// as explicit hosts, which is the conservative direction (no forced
// organization-wide enumeration).
func isBareDomain(host string) bool {
	if host == "" {
		return false
	}
	if netIsIPOrLocal(host) {
		return false
	}
	return strings.Count(host, ".") == 1
}

// historicalApplicable reports whether historical URL discovery is owed:
// deep mode AND at least one public (non-local/private) configured target.
// Private/local targets (loopback, RFC1918, *.local, fixtures) owe nothing.
func historicalApplicable(state *ScanState) bool {
	if state == nil || !state.DeepReconRequired {
		return false
	}
	for _, t := range state.ScanTargets {
		host := hostnameOfTarget(strings.ToLower(strings.TrimSpace(t)))
		if host == "" {
			continue
		}
		if netIsIPOrLocal(host) {
			continue
		}
		return true
	}
	return false
}

// netIsIPOrLocal reports whether a host is an IP literal or a local/private
// name: loopback, RFC1918, link-local, or a *.local/internal style host.
func netIsIPOrLocal(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".localhost") {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		octet := func(s string) int {
			n := 0
			for _, c := range s {
				if c < '0' || c > '9' {
					return -1
				}
				n = n*10 + int(c-'0')
			}
			return n
		}
		a, b := octet(parts[0]), octet(parts[1])
		valid := true
		for _, p := range parts {
			if octet(p) < 0 || octet(p) > 255 {
				valid = false
				break
			}
		}
		if valid {
			if a == 127 || a == 10 || a == 0 {
				return true
			}
			if a == 192 && b == 168 {
				return true
			}
			if a == 172 && b >= 16 && b <= 31 {
				return true
			}
			if a == 169 && b == 254 {
				return true
			}
		}
	}
	switch strings.TrimSuffix(host, ".") {
	case "localhost", "::1":
		return true
	}
	return false
}

// ReconDimensionChecklist renders the applicability-aware per-dimension
// status of reconnaissance (Part 20): the plan brief shows exactly what
// remains instead of an opaque "recon done" flag.
func ReconDimensionChecklist(state *ScanState) []string {
	if state == nil {
		return nil
	}
	s := state
	rc := s.ReconCoverage
	type dim struct {
		name string
		done bool
		// nil = always applicable
		applicable func(*ScanState) bool
		naKey      string
	}
	dims := []dim{
		{"HTTP probe", rc.HTTPProbed, nil, ""},
		{"tech fingerprint", rc.TechFingerprinted, nil, "tech_fingerprint"},
		{"crawl", rc.Crawled, nil, "crawling"},
		{"content discovery", len(rc.ContentDiscoveredHosts) > 0, nil, "content_discovery"},
		{"JS analysis", rc.JSAnalyzed, jsAnalysisApplicable, "js_analysis"},
		{"API mapping", rc.APISurfaceDiscovered, apiSignalsExist, "api_surface"},
		{"auth mapping", rc.AuthMapped == "complete", authSurfaceExists, "auth_mapping"},
		{"parameter mapping", rc.ParamDiscovered, parameterizedSurfaceExists, "parameter_discovery"},
		{"subdomain enumeration", rc.SubdomainEnumerated, subdomainScopeApplicable, "subdomain_discovery"},
		{"service discovery", rc.ServicesProbed, func(*ScanState) bool { return s.DeepReconRequired }, "service_discovery"},
		{"historical URLs", rc.HistoricalChecked, historicalApplicable, "historical"},
	}
	var lines []string
	for _, d := range dims {
		if d.applicable != nil && !d.applicable(s) {
			continue
		}
		if d.done {
			lines = append(lines, "  \u2713 "+d.name)
			continue
		}
		if d.naKey != "" && rc.NAMarked[d.naKey] {
			lines = append(lines, "  \u2713 "+d.name+" (not applicable)")
			continue
		}
		lines = append(lines, "  \u2717 "+d.name)
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{"recon dimensions:"}, lines...)
}

// surfaceRevision fingerprints the structured attack surface so the planner
// can detect that recon has expanded it since the engine-owned plan was last
// built. A revision change — not a delegation event — is the trigger for a
// plan refresh, keeping plan completeness identical with zero specialists.
func surfaceRevision(state *ScanState) string {
	if state == nil {
		return ""
	}
	eps := append([]string(nil), state.DiscoveredEndpoints...)
	sort.Strings(eps)
	seeded := make([]string, 0, len(state.SeededSurface))
	for _, se := range state.SeededSurface {
		seeded = append(seeded, se.Path)
	}
	sort.Strings(seeded)
	techs := make([]string, 0, len(state.DetectedTechs))
	for t := range state.DetectedTechs {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	hosts := make([]string, 0, len(state.DiscoveredHosts))
	for h := range state.DiscoveredHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return fmt.Sprintf("ep=%d:%s|seed=%d:%s|tech=%d:%s|hosts=%d:%s",
		len(eps), strings.Join(eps, ","),
		len(seeded), strings.Join(seeded, ","),
		len(techs), strings.Join(techs, ","),
		len(hosts), strings.Join(hosts, ","))
}

// ── Root-owned deep recon duties ──────────────────────────────────────────
//
// The old recon-discovery specialist carried a deep-recon playbook that
// existed nowhere else: extension-based content discovery, backup/.git/.env
// hunting, source maps, parameter mining, CMS/plugin fingerprinting, mail
// security, CNAME takeover. With the specialist disabled, those obligations
// vanished. hookDeepReconDirector restores them to the ROOT execution path
// WITHOUT copying the giant specialist prompt: each missing dimension from
// the canonical predicate gets a short, concrete directive naming the
// technique, applicability-driven (the predicate only demands what THIS
// target owes). Specialists accelerate the same work; the obligations exist
// with zero specialists.

// deepReconGuidance maps a missing-dimension reason (from
// ComprehensiveReconMissing) to the concrete root technique that settles it.
func deepReconGuidance(missing string) string {
	l := strings.ToLower(missing)
	switch {
	case strings.Contains(l, "javascript analysis"):
		return "- first-party JS: download bundles, then grep for routes, API paths, dynamic route patterns, parameter names, WebSocket/GraphQL URLs, cloud/service endpoints, hardcoded secrets/tokens, and sourceMappingURL (.map) files"
	case strings.Contains(l, "api-surface"):
		return "- API mapping: fetch /swagger.json, /openapi.json, /api-docs; GraphQL -> run introspection (__schema) and read query/mutation signatures; extract /api/ routes from JS and observed traffic (a 404 probe alone is only an attempt)"
	case strings.Contains(l, "auth surface"):
		return "- auth mapping (no credentials needed): enumerate login/registration/password-reset/logout/MFA/OTP/OAuth/token endpoints and session cookie attributes; authenticated testing blocks separately on credentials"
	case strings.Contains(l, "subdomain"):
		return "- domain-scope enumeration: subfinder/crt.sh/assetfinder, then httpx for live hosts; check CNAME takeover on dangling records; fold live hosts into the host inventory"
	case strings.Contains(l, "dns resolution"):
		return "- DNS: dig/nslookup the in-scope domain (A/CNAME/MX records; SPF/DKIM/DMARC only if mail security is in scope)"
	case strings.Contains(l, "historical"):
		return "- historical URLs: gau/waybackurls for archived paths and parameters"
	case strings.Contains(l, "service/port"):
		return "- service enumeration: nmap -sV top ports (or naabu for speed) against the target"
	case strings.Contains(l, "parameter/input"):
		return "- parameter mining: arjun/x8; harvest names from HTML forms, query strings, JS fetch/XHR calls, and OpenAPI/GraphQL documents"
	case strings.Contains(l, "content discovery"):
		return "- content discovery: ONE bounded wordlist pass per distinct app host; additionally probe .git/, .env, *.bak, debug consoles, config/backup files, and source maps; inspect the saved output and fold live routes into the inventory"
	case strings.Contains(l, "real wordlist"):
		return "- wordlist pass: ffuf -w <common wordlist> -e php,html,bak,old,txt,zip -maxtime 120 per distinct app host"
	case strings.Contains(l, "crawling"):
		return "- crawl: katana/gospider or sitemap.xml/robots.txt; extract links, forms, and query strings"
	case strings.Contains(l, "technology"):
		return "- fingerprinting: whatweb/wappalyzer; if a CMS is detected, fingerprint its version and installed plugins/extensions"
	case strings.Contains(l, "http probing"):
		return "- HTTP probe: httpx/curl each live host for status, title, and redirect chain"
	case strings.Contains(l, "endpoint inventory"):
		return "- save the Endpoint Inventory note listing every live route observed so far"
	case strings.Contains(l, "recon baseline"):
		return "- baseline: curl -sI the root and key routes; save the responses"
	}
	return ""
}

// hookDeepReconDirector (OnIterationStart) emits the root-owned deep-recon
// duties while the comprehensive-recon contract has outstanding dimensions.
// Bounded by the predicate itself: it stops the moment recon is settled, and
// its dedupe key lets other planner directives win the composition when they
// matter more.
func hookDeepReconDirector(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.ReconOnlyMode || state.DelegatedAgent || state.DiscoveryMode {
		return HookResult{}
	}
	if state.Iteration < 5 {
		return HookResult{}
	}
	missing := ComprehensiveReconMissing(state)
	if len(missing) == 0 {
		return HookResult{}
	}
	seen := make(map[string]bool)
	var lines []string
	for _, m := range missing {
		g := deepReconGuidance(m)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		lines = append(lines, g)
	}
	if len(lines) == 0 {
		return HookResult{}
	}
	content := "RECON DIRECTIVE (root-owned; specialists are optional acceleration) — the comprehensive-recon contract still owes:\n" +
		strings.Join(lines, "\n") +
		"\nA failed command does not count as coverage: rerun tools that errored (check missing binaries/wordlists), and record a typed disposition via update_plan only for dimensions that genuinely do not apply."
	return HookResult{Directives: []Directive{{
		Priority:  DirectivePriorityPlanner,
		Category:  "recon",
		DedupeKey: "deep-recon-duties",
		Content:   content,
	}}}
}
