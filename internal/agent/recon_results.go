package agent

// recon_results.go moves recon COMPLETION attribution from command strings
// (OnToolExecute) to validated tool results (OnToolResult). Previously,
// merely attempting "ffuf", "nmap", "arjun", or "curl /login" flipped the
// corresponding coverage flag before anything was known about the outcome:
// attempted == complete. A binary that did not exist, a DNS failure, a
// timeout, or a 404 on /swagger.json all silently satisfied coverage. Now
// the execute path only records ATTEMPTS (ReconCoverage.Attempted /
// ContentDiscoveryAttempts) and this layer completes a dimension only when
// the result is a valid execution — where "valid negative" results (an
// empty but genuinely completed scan) count, and failed attempts never do.

import (
	"regexp"
	"sort"
	"strings"
)

// Canonical recon dimension identifiers. They deliberately match the closed
// alias set in recon_coverage.go so typed N/A dispositions and result
// attribution address the same dimension.
const (
	reconDimDNS        = "dns"
	reconDimSubdomains = "subdomain_discovery"
	reconDimServices   = "service_discovery"
	reconDimHTTP       = "http_probe"
	reconDimTech       = "tech_fingerprint"
	reconDimCrawl      = "crawling"
	reconDimJS         = "js_analysis"
	reconDimAPI        = "api_surface"
	reconDimParams     = "parameter_discovery"
	reconDimAuth       = "auth_mapping"
	reconDimHistorical = "historical"
	reconDimContent    = "content_discovery"
)

// reconDimensionsForCommand maps a (lowercased) terminal command to the
// recon dimensions it ATTEMPTS. Pure detection: no completion flags are set
// here. Detection runs identically at execute time (attempt recording) and
// result time (validated completion), so a dimension can never be completed
// by a command its detection does not cover.
func reconDimensionsForCommand(cmd string) []string {
	var dims []string
	add := func(dim string) { dims = append(dims, dim) }
	switch {
	case strings.Contains(cmd, "dig ") || strings.Contains(cmd, "nslookup ") || strings.Contains(cmd, "host "):
		add(reconDimDNS)
	}
	if strings.Contains(cmd, "subfinder") || strings.Contains(cmd, "assetfinder") ||
		strings.Contains(cmd, "findomain") || strings.Contains(cmd, "crt.sh") ||
		strings.Contains(cmd, "amass") || strings.Contains(cmd, "shuffledns") ||
		strings.Contains(cmd, "sublist3r") || strings.Contains(cmd, "oneforall") {
		add(reconDimSubdomains)
	}
	if strings.Contains(cmd, "nmap") || strings.Contains(cmd, "naabu") ||
		strings.Contains(cmd, "masscan") || strings.Contains(cmd, "-p ") ||
		(strings.Contains(cmd, "port") && strings.Contains(cmd, "curl")) {
		add(reconDimServices)
	}
	if strings.Contains(cmd, "curl") || strings.Contains(cmd, "httpx") {
		add(reconDimHTTP)
	}
	if techFingerprintCommand(cmd) {
		add(reconDimTech)
	}
	if strings.Contains(cmd, "katana") || strings.Contains(cmd, "gospider") ||
		strings.Contains(cmd, "sitemap") || strings.Contains(cmd, "robots.txt") ||
		strings.Contains(cmd, "discover_client_routes") ||
		(strings.Contains(cmd, "grep") && strings.Contains(cmd, "href")) {
		add(reconDimCrawl)
	}
	if jsAnalysisCommand(cmd) {
		add(reconDimJS)
	}
	if strings.Contains(cmd, "swagger") || strings.Contains(cmd, "openapi") ||
		strings.Contains(cmd, "graphql") || strings.Contains(cmd, "api-docs") ||
		strings.Contains(cmd, "/api/") || strings.Contains(cmd, "introspection") {
		add(reconDimAPI)
	}
	if strings.Contains(cmd, "arjun") || strings.Contains(cmd, "x8 ") ||
		strings.Contains(cmd, "paramspider") || strings.Contains(cmd, "parameth") ||
		(strings.Contains(cmd, "grep") && strings.Contains(cmd, "param")) ||
		strings.Contains(cmd, "form") {
		add(reconDimParams)
	}
	if strings.Contains(cmd, "login") || strings.Contains(cmd, "/auth") ||
		strings.Contains(cmd, "session") || strings.Contains(cmd, "signup") ||
		strings.Contains(cmd, "register") {
		add(reconDimAuth)
	}
	if strings.Contains(cmd, "wayback") || strings.Contains(cmd, "gau") ||
		strings.Contains(cmd, "web.archive.org") || strings.Contains(cmd, "common crawl") ||
		strings.Contains(cmd, "commoncrawl") {
		add(reconDimHistorical)
	}
	if strings.Contains(cmd, "ffuf") || strings.Contains(cmd, "gobuster") ||
		strings.Contains(cmd, "dirsearch") || strings.Contains(cmd, "feroxbuster") ||
		strings.Contains(cmd, "dirb ") {
		add(reconDimContent)
	}
	return dims
}

// dimInCommand reports whether a command attempts the given dimension.
func dimInCommand(cmd, dim string) bool {
	for _, d := range reconDimensionsForCommand(cmd) {
		if d == dim {
			return true
		}
	}
	return false
}

// reconToolFailureMarkers identifies failed EXECUTIONS in tool-log outputs:
// missing binaries, DNS failures, unreachable networks, invalid flags,
// missing wordlists, crashes. Responses to HTTP requests are data, not
// errors, so these markers are only applied to scanner-tool outputs.
var reconToolFailureMarkers = []string{
	"command not found",
	"no such file or directory",
	"could not resolve", "temporary failure in name resolution",
	"resolution failed", "nodename nor servname", "name or service not known",
	"connection refused", "connection reset by peer", "network is unreachable",
	"no route to host",
	"timed out", "operation timed out", "context deadline exceeded",
	"deadline exceeded", "request timeout",
	"flag provided but not defined", "unknown shorthand flag",
	"flag needs an argument", "unrecognized option", "unknown option",
	"wordlist file", "could not load",
	"invalid url", "unparseable url", "malformed url",
	"segmentation fault", "core dumped", "panic:",
	"fatal error:",
	"usage:",
	"ssl certificate problem", "certificate verify failed",
}

// reconHTTPLikeFailureMarkers applies to outputs of HTTP-client commands
// (curl/httpx against web servers): response bodies are arbitrary web data
// and must never be misread as tool errors, so only client-side errors
// (the "curl: (" error format, missing helpers) mark failure.
var reconHTTPLikeFailureMarkers = []string{
	"command not found",
	"no such file or directory",
	"curl: (", "httpx: error", "jq: error",
	"python: ", "traceback (most recent call last)",
}

// reconRunFailed classifies a tool result as a failed attempt. curlLike
// narrows the marker set because HTTP response bodies are data.
func reconRunFailed(out string, curlLike bool) bool {
	l := strings.ToLower(out)
	markers := reconToolFailureMarkers
	if curlLike {
		markers = reconHTTPLikeFailureMarkers
	}
	for _, m := range markers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// isCurlLikeCommand reports whether the command's primary output is raw
// HTTP response data (curl/httpx requests), whose bodies are web data.
func isCurlLikeCommand(cmd string, dims []string) bool {
	if strings.Contains(cmd, "ffuf") || strings.Contains(cmd, "nmap") ||
		strings.Contains(cmd, "gobuster") || strings.Contains(cmd, "naabu") ||
		strings.Contains(cmd, "masscan") || strings.Contains(cmd, "dig") ||
		strings.Contains(cmd, "nslookup") || strings.Contains(cmd, "subfinder") ||
		strings.Contains(cmd, "assetfinder") || strings.Contains(cmd, "arjun") {
		return false
	}
	for _, d := range dims {
		if d == reconDimServices || d == reconDimContent || d == reconDimDNS ||
			d == reconDimSubdomains || d == reconDimParams {
			return false
		}
	}
	return true
}

// reconDimEvidenceSatisfied performs the per-dimension content validation
// for a result that executed without a tool error. Dimensions without
// specific markers accept valid negatives: a genuinely completed scan with
// zero findings is complete (Part 25).
func reconDimEvidenceSatisfied(dim, cmd, out string) bool {
	switch dim {
	case reconDimServices:
		return serviceScanEvidence(out, cmd)
	case reconDimAPI:
		return apiSurfaceEvidence(out)
	case reconDimAuth:
		return authSurfaceEvidence(out)
	case reconDimCrawl:
		return crawlEvidence(out, cmd)
	case reconDimTech:
		return techFingerprintEvidence(out, cmd)
	case reconDimJS:
		return jsAnalysisEvidence(out, cmd)
	default:
		return true
	}
}

// serviceScanEvidence: a valid port scan shows a scan report or discovered
// ports; "host seems down" without -Pn is inconclusive, not coverage.
func serviceScanEvidence(out, cmd string) bool {
	l := strings.ToLower(out)
	if strings.Contains(cmd, "naabu") || strings.Contains(cmd, "masscan") {
		// These tools print only port lists; an empty valid scan is a valid
		// negative. Any non-error output counts.
		return true
	}
	for _, m := range []string{"scan report", "nmap done", "host is up",
		"discovered open port", "port state", "service ", "ports:"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// apiSurfaceEvidence: API mapping completes from real discovery evidence —
// an OpenAPI/Swagger document, a GraphQL schema/introspection response, or
// extracted API route listings. A 404 on /swagger.json is only an attempt.
func apiSurfaceEvidence(out string) bool {
	l := strings.ToLower(out)
	for _, m := range []string{"openapi", "swagger", "\"paths\"", "paths:",
		"operationid", "__schema", "graphqlschema", "apis:"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	if strings.Contains(l, "graphql") {
		for _, m := range []string{"schema", "query", "mutation", "introspection", "__type"} {
			if strings.Contains(l, m) {
				return true
			}
		}
	}
	if strings.Contains(l, "get /api/") || strings.Contains(l, "post /api/") {
		return true
	}
	return false
}

// authSurfaceEvidence: auth mapping completes when an authentication-related
// endpoint demonstrably responded (status line of a live auth area, a
// session cookie, or a login form). A 404 body is only an attempt.
func authSurfaceEvidence(out string) bool {
	l := strings.ToLower(out)
	for _, m := range []string{
		"http/1.1 200", "http/1.1 201", "http/1.1 204", "http/1.1 301",
		"http/1.1 302", "http/1.1 401", "http/1.1 403",
		"http/2 200", "http/2 301", "http/2 302",
		"set-cookie", "<form", "location:",
	} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// techFingerprintCommand reports whether a command is a DELIBERATE
// technology-fingerprinting action: a dedicated fingerprint tool, or a
// header-fetching request (curl -I/-i/-sI/--head) whose output the evidence
// layer can validate. A random command that merely contains "server:" or
// "x-powered-by" in its text is not fingerprinting.
var techHeaderFlagRe = regexp.MustCompile(`(?:^|[\s=])(?:-si|-i|--head|--include)(?:\s|$)`)

func techFingerprintCommand(cmd string) bool {
	if strings.Contains(cmd, "whatweb") || strings.Contains(cmd, "wappalyzer") ||
		strings.Contains(cmd, "wafw00f") {
		return true
	}
	if (strings.Contains(cmd, "curl") || strings.Contains(cmd, "httpx")) &&
		techHeaderFlagRe.MatchString(cmd) {
		return true
	}
	return false
}

// jsAnalysisCommand reports whether a command attempts first-party JS
// analysis: fetching a script asset (curl/wget of a .js/.mjs/.map/bundle/
// chunk URL), OR analyzing an ALREADY-DOWNLOADED JS artifact with bounded
// local tools (rg/grep/jq/cat/sed/python). The download-then-grep workflow is
// the primary real-world pattern - curl -o saves the file, the analysis runs
// on the artifact, and the curl result alone carries little JS.
func jsAnalysisCommand(cmd string) bool {
	jsAsset := strings.Contains(cmd, ".js") || strings.Contains(cmd, ".mjs") ||
		strings.Contains(cmd, ".map") || strings.Contains(cmd, "bundle") ||
		strings.Contains(cmd, "chunk")
	if !jsAsset {
		return false
	}
	if strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget") {
		return true
	}
	for _, tool := range []string{"rg ", "grep ", "jq ", "cat ", "sed ", "python"} {
		if strings.Contains(cmd, tool) {
			return true
		}
	}
	return false
}

// httpNotFoundMarker reports 404-class responses in curl-like output: an
// error page is data about the request, never evidence the recon dimension
// completed.
func httpNotFoundMarker(l string) bool {
	for _, m := range []string{"404 not found", "http/1.1 404", "http/2 404", "http/1.0 404", "status: 404"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// crawlEvidence validates a crawling result. A 404 on robots.txt (or any
// error-page fetch) is only an attempt. Real coverage comes from a dedicated
// crawler run (any non-error output, including the VALID NEGATIVE "crawler
// processed the application, zero additional routes"), useful robots/sitemap
// content, link extraction from a real document, or browser navigation.
func crawlEvidence(out, cmd string) bool {
	l := strings.ToLower(out)
	// Dedicated crawlers: a non-error run is valid; an empty result is a
	// valid negative (the crawler really processed the application).
	if strings.Contains(cmd, "katana") || strings.Contains(cmd, "gospider") ||
		strings.Contains(cmd, "hakrawler") || strings.Contains(cmd, "discover_client_routes") ||
		strings.Contains(cmd, "page_agent") {
		return true
	}
	// robots.txt fetch: only useful content counts, never a 404/error body.
	if strings.Contains(cmd, "robots.txt") {
		return strings.Contains(l, "user-agent") || strings.Contains(l, "disallow") ||
			strings.Contains(l, "allow:") || strings.Contains(l, "sitemap")
	}
	// sitemap fetch: useful content only.
	if strings.Contains(cmd, "sitemap") {
		return strings.Contains(l, "<urlset") || strings.Contains(l, "<loc") ||
			strings.Contains(l, "<sitemap")
	}
	// link/route extraction from a real document.
	if (strings.Contains(l, "href") || strings.Contains(l, "<a ") || strings.Contains(l, "routes found")) &&
		!httpNotFoundMarker(l) {
		return true
	}
	// explicit valid negative from a real crawler pass.
	for _, m := range []string{"0 urls", "no urls found", "no results", "no links found", "found 0", "no routes", "no endpoints"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// techFingerprintEvidence validates deliberate technology fingerprinting: a
// dedicated tool that ran without error, or a real HTTP response carrying
// useful technology headers (Server, X-Powered-By, Set-Cookie, framework
// banners). A bare 200 body without those headers is only an attempt.
func techFingerprintEvidence(out, cmd string) bool {
	if strings.Contains(cmd, "whatweb") || strings.Contains(cmd, "wappalyzer") ||
		strings.Contains(cmd, "wafw00f") {
		return true
	}
	l := strings.ToLower(out)
	return strings.Contains(l, "server:") || strings.Contains(l, "x-powered-by") ||
		strings.Contains(l, "set-cookie")
}

// jsAnalysisEvidence validates a JS-analysis result. A dedicated local
// analysis of a downloaded JS artifact (rg/grep/jq/...) is valid even with
// zero interesting routes - a real JS file with no routes is a VALID
// NEGATIVE analysis, not a missing dimension. A raw script fetch counts only
// when actual JavaScript content came back (real JS tokens, not a 404 page
// or an HTML fallback).
func jsAnalysisEvidence(out, cmd string) bool {
	l := strings.ToLower(out)
	// Local artifact analysis: the artifact was fetched separately; a
	// no-match grep is a valid negative analysis result.
	for _, tool := range []string{"rg ", "grep ", "jq ", "cat "} {
		if strings.Contains(cmd, tool) {
			return true
		}
	}
	if strings.Contains(cmd, "discover_client_routes") {
		return true
	}
	if httpNotFoundMarker(l) {
		return false
	}
	// HTML fallback pages are not scripts.
	if strings.Contains(l, "<!doctype html") || strings.Contains(l, "<html") {
		return false
	}
	for _, m := range []string{
		"sourcemap", "sourcemappingurl", "webpack", "webpackjsonp",
		"fetch(", "xmlhttprequest", "require(", "module.exports",
		"function", "=>", "var ", "let ", "const ",
	} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// markReconDimensionComplete sets the completion flag for a dimension whose
// result was validated. Any validated recon run also satisfies the legacy
// baseline (ReconDone): the scan demonstrably executed real reconnaissance.
func markReconDimensionComplete(state *ScanState, dim string) {
	if state == nil {
		return
	}
	rc := &state.ReconCoverage
	switch dim {
	case reconDimDNS:
		rc.DNSResolved = true
	case reconDimSubdomains:
		rc.SubdomainEnumerated = true
	case reconDimServices:
		rc.ServicesProbed = true
	case reconDimHTTP:
		rc.HTTPProbed = true
	case reconDimTech:
		rc.TechFingerprinted = true
	case reconDimCrawl:
		rc.Crawled = true
	case reconDimJS:
		rc.JSAnalyzed = true
	case reconDimAPI:
		rc.APISurfaceDiscovered = true
	case reconDimParams:
		rc.ParamDiscovered = true
	case reconDimAuth:
		// Auth SURFACE mapping completes only when no OBSERVED flow family
		// remains unmapped: one live /login response maps the login flow,
		// not the password-reset or OAuth flows the inventory carries.
		// Credential availability is tracked separately (AuthContextAvailable);
		// authenticated testing blocks separately (auth_coverage.go).
		if unmapped := authFlowsUnmapped(state); len(unmapped) == 0 {
			rc.AuthMapped = "complete"
		}
	case reconDimHistorical:
		rc.HistoricalChecked = true
	case reconDimContent:
		// Handled by the per-host block in hookReconResultTracker.
	default:
		return
	}
	state.ReconDone = true
}

// hookReconResultTracker (OnToolResult) is the single completion path for
// reconnaissance dimensions: a dimension completes only when its command
// executed and the result passes the failure/evidence checks. Failed runs
// increment FailedAttempts so bounded retries can guide a typed "blocked"
// disposition instead of either infinite re-running or silent satisfaction.
func hookReconResultTracker(state *ScanState, args map[string]string) HookResult {
	if state == nil {
		return HookResult{}
	}
	toolName := args["tool_name"]
	errStr := strings.TrimSpace(args["error"])
	out := args["output"]

	// discover_client_routes processes first-party JS and extracts client
	// routes: a clean run completes crawling, and completes JS analysis when
	// the surface ships JS assets. A valid negative (zero routes found after
	// successful processing) is still real coverage.
	if toolName == "discover_client_routes" {
		if errStr == "" {
			markReconDimensionComplete(state, reconDimCrawl)
			if jsAnalysisApplicable(state) {
				markReconDimensionComplete(state, reconDimJS)
			}
		}
		return HookResult{}
	}
	if toolName != "terminal_execute" {
		return HookResult{}
	}
	cmd := strings.ToLower(strings.TrimSpace(args["command"]))
	if cmd == "" {
		return HookResult{}
	}
	dims := reconDimensionsForCommand(cmd)
	if len(dims) == 0 {
		return HookResult{}
	}
	if state.ReconCoverage.FailedAttempts == nil {
		state.ReconCoverage.FailedAttempts = make(map[string]int)
	}
	failed := errStr != "" || reconRunFailed(out, isCurlLikeCommand(cmd, dims))
	for _, dim := range dims {
		if failed {
			state.ReconCoverage.FailedAttempts[dim]++
			continue
		}
		if !reconDimEvidenceSatisfied(dim, cmd, out) {
			continue
		}
		if dim == reconDimAuth {
			// Flow-family mapping: a validated auth result maps every flow
			// family it covers; the dimension completes only when no
			// OBSERVED family remains unmapped.
			for _, f := range authFlowsFromText(out) {
				markAuthFlowMapped(state, f)
			}
		}
		markReconDimensionComplete(state, dim)
	}
	if failed {
		return HookResult{}
	}
	// Content-discovery specifics: a validated pass completes per-host
	// coverage and the wordlist depth signal.
	if dimInCommand(cmd, reconDimContent) {
		if host := extractHostFromCmd(cmd); host != "" {
			state.DirBustingHosts[host] = true
			state.ReconCoverage.ContentDiscoveredHosts[host] = true
		}
		state.DirBustingDone = true
		state.ReconDone = true
		if strings.Contains(cmd, " -w ") || strings.Contains(cmd, "--wordlist") || strings.Contains(cmd, "-w=") {
			state.DirBustingUsedWordlist = true
		}
	}
	// HTML form evidence activates parameter discovery AND becomes
	// structured surface: fields attach to the form action endpoint.
	recordFormsFromHTML(state, out)
	// JS analysis enriches the structured surface: routes, API paths,
	// GraphQL/WebSocket URLs from a VALIDATED JS result fold in with
	// provenance "js" (bounded, confidence-anchored; a valid negative adds
	// nothing).
	if dimInCommand(cmd, reconDimJS) {
		maybeRecordJSRoutes(state, out)
	}
	// API discovery enriches the structured surface: OpenAPI paths and
	// GraphQL operations from a validated result enter the inventory with
	// provenance "api".
	if dimInCommand(cmd, reconDimAPI) {
		maybeRecordAPIRoutes(state, out)
	}
	// Parameter discovery enriches the structured surface: names found by
	// arjun/x8/etc. attach to the probed endpoint.
	if dimInCommand(cmd, reconDimParams) {
		maybeRecordDiscoveredParams(state, cmd, out)
	}
	// Structured host inventory: bare hostnames from DNS/subdomain results.
	maybeRecordDiscoveredHosts(state, cmd, out)
	return HookResult{}
}

// maxRoutesFromResult bounds per-result route extraction.
const maxRoutesFromResult = 20

// jsRouteMarkerKeywords anchor route candidates found in JS analysis output
// to confident route-bearing lines (fetch/axios/XHR/router definitions,
// API/GraphQL/WebSocket references).
var jsRouteMarkerKeywords = []string{
	"fetch", "axios", "xhr", "router", "route", "api", "graphql", "websocket", "ws://", "wss://",
}

// maybeRecordJSRoutes folds route candidates from a validated JS analysis
// result into the structured surface with provenance "js". Only
// marker-anchored lines contribute; arbitrary string literals in bundle text
// are not promoted.
func maybeRecordJSRoutes(state *ScanState, out string) {
	if state == nil {
		return
	}
	l := strings.ToLower(out)
	confident := false
	for _, k := range jsRouteMarkerKeywords {
		if strings.Contains(l, k) {
			confident = true
			break
		}
	}
	if !confident {
		return
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if count >= maxRoutesFromResult {
			break
		}
		ll := strings.ToLower(line)
		if !containsAnyKeyword(ll, jsRouteMarkerKeywords) {
			continue
		}
		for _, ep := range extractPaths(line) {
			if count >= maxRoutesFromResult {
				break
			}
			RecordSurfaceObservation(state, SurfaceObservation{
				Endpoint: ep,
				Source:   "js",
				Promote:  true,
			})
			count++
		}
	}
}

// maybeRecordAPIRoutes folds paths from a validated API-discovery result
// (OpenAPI/GraphQL documents, extracted /api/ listings) into the structured
// surface with provenance "api". Bounded; idempotent via promotion dedupe.
func maybeRecordAPIRoutes(state *ScanState, out string) {
	if state == nil {
		return
	}
	eps := extractPaths(out)
	if len(eps) > maxRoutesFromResult {
		eps = eps[:maxRoutesFromResult]
	}
	for _, ep := range eps {
		RecordSurfaceObservation(state, SurfaceObservation{
			Endpoint: ep,
			Source:   "api",
			Promote:  true,
		})
	}
}

// paramDiscoveryNameRe matches parameter-name listings in arjun/x8-style
// output ("valid parameters: q, sort").
var paramDiscoveryNameRe = regexp.MustCompile(`(?i)(?:valid\s+parameters?\s*:?|parameters?\s*found\s*:?|parameters?\s*:|params?\s*:)\s*(.{1,200})`)

// maybeRecordDiscoveredParams attaches parameter names found by a validated
// parameter-discovery run to the probed endpoint, so the discovery enriches
// the structured surface (and applicability) instead of only flipping a
// boolean.
func maybeRecordDiscoveredParams(state *ScanState, cmd, out string) {
	if state == nil {
		return
	}
	endpoint := extractEndpointFromCmd(cmd)
	if endpoint == "" {
		return
	}
	seen := map[string]bool{}
	var params []SurfaceParameter
	for _, m := range paramDiscoveryNameRe.FindAllStringSubmatch(out, 8) {
		for _, tok := range strings.FieldsFunc(m[1], func(r rune) bool {
			return r == ',' || r == '|' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '&'
		}) {
			tok = strings.Trim(tok, ":\"'-")
			if !validParamName(tok) || seen[tok] {
				continue
			}
			seen[tok] = true
			params = append(params, SurfaceParameter{Name: tok, Location: "query"})
			if len(params) >= maxObservedParamsPerEndpoint {
				break
			}
		}
		if len(params) >= maxObservedParamsPerEndpoint {
			break
		}
	}
	if len(params) > 0 {
		RecordSurfaceObservation(state, SurfaceObservation{
			Endpoint:   endpoint,
			Parameters: params,
			Source:     "param-mining",
		})
	}
}

// maxDiscoveredHosts bounds the structured host inventory.
const maxDiscoveredHosts = 50

// maybeRecordDiscoveredHosts folds bare hostnames from validated DNS/
// subdomain results into DiscoveredHosts. Only hostnames UNDER a configured
// scope domain are accepted — subdomain enumerators occasionally print
// resolver or infrastructure names that must never become assessment
// obligations.
func maybeRecordDiscoveredHosts(state *ScanState, cmd, out string) {
	if state == nil || len(state.DiscoveredHosts) >= maxDiscoveredHosts {
		return
	}
	if !dimInCommand(cmd, reconDimSubdomains) && !dimInCommand(cmd, reconDimDNS) {
		return
	}
	suffixes := scopeDomainSuffixes(state)
	if len(suffixes) == 0 {
		return
	}
	l := strings.ToLower(out)
	for _, suffix := range suffixes {
		re, err := regexp.Compile(`\b([a-z0-9][a-z0-9-]*\.)+` + regexp.QuoteMeta(suffix) + `\b`)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllString(l, 64) {
			host := strings.Trim(m, ".")
			if host == "" || netIsIPOrLocal(host) {
				continue
			}
			if len(state.DiscoveredHosts) >= maxDiscoveredHosts {
				return
			}
			state.DiscoveredHosts[host] = true
		}
	}
}

// scopeDomainSuffixes extracts the registrable-domain suffixes of the
// configured targets via the Public Suffix List, so subdomain results can be
// filtered to in-scope names. *.example.co.uk scopes to example.co.uk, NEVER
// to co.uk - deriving the suffix from the last two labels broadened
// enumeration to the entire public suffix. IP/local targets contribute
// nothing.
func scopeDomainSuffixes(state *ScanState) []string {
	if state == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, t := range state.ScanTargets {
		host := hostnameOfTarget(strings.ToLower(strings.TrimSpace(t)))
		if host == "" || netIsIPOrLocal(host) {
			continue
		}
		suffix := registrableDomain(host)
		if suffix == "" {
			continue
		}
		if !seen[suffix] {
			seen[suffix] = true
			out = append(out, suffix)
		}
	}
	sort.Strings(out)
	return out
}
