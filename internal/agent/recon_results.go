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
	if strings.Contains(cmd, "whatweb") || strings.Contains(cmd, "wappalyzer") ||
		strings.Contains(cmd, "wafw00f") || strings.Contains(cmd, "server:") ||
		strings.Contains(cmd, "x-powered-by") {
		add(reconDimTech)
	}
	if strings.Contains(cmd, "katana") || strings.Contains(cmd, "gospider") ||
		strings.Contains(cmd, "sitemap") || strings.Contains(cmd, "robots.txt") ||
		strings.Contains(cmd, "discover_client_routes") ||
		(strings.Contains(cmd, "grep") && strings.Contains(cmd, "href")) {
		add(reconDimCrawl)
	}
	if (strings.Contains(cmd, ".js") || strings.Contains(cmd, "bundle") ||
		strings.Contains(cmd, "chunk")) && strings.Contains(cmd, "curl") {
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
	case reconDimJS:
		return jsAnalysisEvidence(out)
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

// jsAnalysisEvidence: JavaScript analysis completes when actual script
// content was retrieved (bundle/source-map markers), not a 404 fallback page.
func jsAnalysisEvidence(out string) bool {
	l := strings.ToLower(out)
	for _, m := range []string{
		"sourcemap", "sourcemappingurl", "webpack", "webpackjsonp",
		"fetch(", "xmlhttprequest", "require(", "module.exports",
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
		// Auth SURFACE mapping is complete on evidence; credential
		// availability is tracked separately (AuthContextAvailable) and
		// authenticated testing blocks separately (auth_coverage.go).
		rc.AuthMapped = "complete"
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

	// Non-terminal recon-capable tools: a clean result completes crawling.
	if toolName == "discover_client_routes" {
		if errStr == "" && strings.TrimSpace(out) != "" {
			markReconDimensionComplete(state, reconDimCrawl)
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
	// HTML form evidence activates parameter discovery.
	if strings.Contains(strings.ToLower(out), "<form") {
		state.FormsObserved = true
	}
	// Structured host inventory: bare hostnames from DNS/subdomain results.
	maybeRecordDiscoveredHosts(state, cmd, out)
	return HookResult{}
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
// configured targets (last two labels), so subdomain results can be filtered
// to in-scope names. IP/local targets contribute nothing.
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
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		if len(labels) < 2 {
			continue
		}
		suffix := strings.Join(labels[len(labels)-2:], ".")
		if !seen[suffix] {
			seen[suffix] = true
			out = append(out, suffix)
		}
	}
	sort.Strings(out)
	return out
}
