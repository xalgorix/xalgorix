package agent

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// shouldBlockForMissingAuthPrerequisites prevents an anonymous assessment from
// turning a leaked password hash into an unbounded cracking attack. A concrete
// leaked hash is already impact evidence for its root cause; cracking it adds
// risk and routinely starves unrelated black-box lanes. The guard is lifted
// when the operator supplied (or the scan ingested) a legitimate session, where
// authenticated replay and role comparison are expected.
//
// Deliberately NOT blocked: testing default credentials (admin:admin,
// root:root) on discovered login forms. Default credential testing is a core
// OWASP methodology step (WSTG-ATHN-02) and one of the highest-yield
// anonymous techniques on misconfigured services — blocking it prevented
// the agent from finding authentication vulnerabilities entirely on
// targets where no operator-supplied account exists.
func (a *Agent) shouldBlockForMissingAuthPrerequisites(toolName string, toolArgs map[string]string) (bool, string) {
	if a == nil || a.state == nil || !a.state.AuthContextKnown || a.state.AuthContextAvailable {
		return false, ""
	}
	var material string
	switch toolName {
	case "terminal_execute":
		material = toolArgs["command"]
	case "python_action":
		material = toolArgs["code"] + " " + toolArgs["script"]
	default:
		return false, ""
	}
	lower := strings.ToLower(material)
	for _, marker := range []string{
		"hashcat", "rockyou", "pbkdf2", "bcrypt", "passlib",
		"password cracking", "password crack", "crack password", "dictionary attack",
		" john ", "john-the-ripper",
	} {
		if strings.Contains(" "+lower+" ", marker) {
			return true, "No operator-supplied account or session is available. Preserve a leaked credential hash as impact evidence, but do not crack it; continue anonymous testing and skip role-dependent lanes with that prerequisite."
		}
	}
	return false, ""
}

func (a *Agent) shouldUsePassiveReconGuard() bool {
	return normalizeActivityMode(a.reconMode) == activityModePassive &&
		normalizeActivityMode(a.scanIntensity) == activityModeActive &&
		!a.discoveryMode &&
		!isReconReportOnlyPhaseSelection(a.allowedPhases)
}

func (a *Agent) refreshPassiveReconGuard() {
	if a.shouldUsePassiveReconGuard() {
		a.passiveReconGuardActive = !a.passiveReconGuardDone
	} else {
		a.passiveReconGuardActive = false
	}
	a.syncPassiveReconGuardState()
}

func (a *Agent) resetPassiveReconGuardForRun() {
	if a.executionRestored && a.state != nil {
		a.passiveReconGuardDone = a.state.PassiveReconGuardDone
		a.passiveReconPassiveLookups = a.state.PassiveReconPassiveLookups
		a.passiveReconBlockedActive = a.state.PassiveReconBlockedActive
		a.passiveReconSourceKeys = a.state.PassiveReconSourceKeys
		a.refreshPassiveReconGuard()
		return
	}
	a.passiveReconGuardDone = false
	a.passiveReconPassiveLookups = 0
	a.passiveReconBlockedActive = 0
	a.passiveReconSourceKeys = make(map[string]bool)
	a.refreshPassiveReconGuard()
}

func (a *Agent) syncPassiveReconGuardState() {
	if a.state == nil {
		return
	}
	a.state.PassiveReconGuardActive = a.passiveReconGuardActive
	a.state.PassiveReconGuardDone = a.passiveReconGuardDone
	a.state.PassiveReconSourceKeys = a.passiveReconSourceKeys
	a.state.PassiveReconPassiveLookups = a.passiveReconPassiveLookups
	a.state.PassiveReconBlockedActive = a.passiveReconBlockedActive
}

func (a *Agent) recordPassiveReconLookup(toolName string, toolArgs map[string]string) {
	if !a.passiveReconGuardActive {
		return
	}
	if a.passiveReconSourceKeys == nil {
		a.passiveReconSourceKeys = make(map[string]bool)
	}
	a.passiveReconPassiveLookups++
	a.passiveReconSourceKeys[classifyPassiveReconSource(toolName, toolArgs)] = true
	a.syncPassiveReconGuardState()
}

func (a *Agent) recordPassiveReconBlock() {
	if !a.passiveReconGuardActive {
		return
	}
	a.passiveReconBlockedActive++
	a.syncPassiveReconGuardState()
}

func (a *Agent) finishPassiveReconGuard() {
	a.passiveReconGuardActive = false
	a.passiveReconGuardDone = true
	a.syncPassiveReconGuardState()
}

func (a *Agent) maybeCompletePassiveReconGuardAtIterationStart(iter int) string {
	if !a.passiveReconGuardActive || !a.shouldUsePassiveReconGuard() || iter == 0 || !a.passiveReconGuardSatisfied() {
		return ""
	}
	a.finishPassiveReconGuard()
	return "Passive reconnaissance guard complete: passive evidence has been collected. Active testing is now allowed because scan intensity is active."
}

func (a *Agent) passiveReconGuardSatisfied() bool {
	if a.passiveReconPassiveLookups < passiveReconMinLookups {
		return false
	}
	if len(a.passiveReconSourceKeys) >= passiveReconMinSourceKinds {
		return true
	}
	return a.passiveReconPassiveLookups >= passiveReconFallbackLookups
}

func classifyPassiveReconSource(toolName string, toolArgs map[string]string) string {
	combined := strings.ToLower(toolName)
	for _, value := range toolArgs {
		combined += " " + strings.ToLower(value)
	}
	switch {
	case isAllowedLocalArtifactAnalysis(strings.ToLower(toolName), toolArgs):
		return "local_artifact"
	case strings.Contains(combined, "crt.sh") ||
		strings.Contains(combined, "certspotter") ||
		strings.Contains(combined, "certificate transparency") ||
		strings.Contains(combined, "ct log") ||
		strings.Contains(combined, "certstream"):
		return "certificate_transparency"
	case strings.Contains(combined, "web.archive.org") ||
		strings.Contains(combined, "wayback") ||
		strings.Contains(combined, "urlscan") ||
		strings.Contains(combined, "commoncrawl"):
		return "public_archive"
	case strings.Contains(combined, "shodan") ||
		strings.Contains(combined, "censys") ||
		strings.Contains(combined, "securitytrails") ||
		strings.Contains(combined, "virustotal") ||
		strings.Contains(combined, "alienvault") ||
		strings.Contains(combined, "binaryedge") ||
		strings.Contains(combined, "fofa") ||
		strings.Contains(combined, "zoomeye"):
		return "third_party_intel"
	case strings.Contains(combined, "whois") || strings.Contains(combined, "rdap"):
		return "registry"
	case strings.Contains(combined, "dig ") ||
		strings.Contains(combined, "nslookup") ||
		strings.Contains(combined, "dnsdumpster") ||
		strings.Contains(combined, "dnsx"):
		return "dns_records"
	case strings.Contains(combined, "github.com") ||
		strings.Contains(combined, "gitlab.com") ||
		strings.Contains(combined, "sourcegraph") ||
		strings.Contains(combined, "grep.app"):
		return "source_code"
	case strings.EqualFold(toolName, "web_search"):
		return "web_search"
	default:
		return "passive_lookup"
	}
}

func normalizeActivityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case activityModePassive:
		return activityModePassive
	default:
		return activityModeActive
	}
}

func normalizeActivityHosts(targets []string) []string {
	seen := make(map[string]bool)
	var hosts []string
	var add func(string)
	add = func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimPrefix(host, ".")
		host = strings.TrimSuffix(host, ".")
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		hosts = append(hosts, host)
		if strings.HasPrefix(host, "www.") {
			add(strings.TrimPrefix(host, "www."))
		}
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			add(strings.Join(parts[len(parts)-2:], "."))
		}
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if strings.Contains(target, "://") {
			if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
				add(parsed.Hostname())
				continue
			}
		}
		raw := strings.TrimPrefix(target, "http://")
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.Split(raw, "/")[0]
		raw = strings.Split(raw, "?")[0]
		raw = strings.Split(raw, "#")[0]
		if strings.Contains(raw, ":") {
			if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
				raw = parsed.Hostname()
			}
		}
		add(raw)
	}
	return hosts
}

func isReconReportOnlyPhaseSelection(phases []int) bool {
	if len(phases) == 0 {
		return false
	}
	for _, phase := range phases {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}

// firstClassToolClass maps first-class deterministic tools to the canonical
// vulnerability class they exercise. The plan/applicability layer is the
// PRIMARY phase enforcement (excluded phases generate no obligations); this
// map is only the backstop for tools the model can invoke directly.
var firstClassToolClass = map[string]string{
	"verify_sqli":           "sqli",
	"verify_ssti":           "ssti",
	"verify_xss":            "xss",
	"verify_path_traversal": "path_traversal",
	"verify_csrf":           "csrf",
	"verify_xxe":            "xxe",
	"authz_matrix":          "idor",
}

func (a *Agent) shouldBlockForPhaseRestriction(toolName string, toolArgs map[string]string) (bool, string) {
	if len(a.allowedPhases) == 0 {
		return false, ""
	}

	// Recon/report-only scans keep their stricter historical contract.
	if isReconReportOnlyPhaseSelection(a.allowedPhases) {
		lowerTool := strings.ToLower(toolName)
		if lowerTool == "report_vulnerability" {
			return true, "report_vulnerability is out of scope for a reconnaissance/report-only scan. Record recon findings in notes and finish with a recon-focused summary instead."
		}

		combined := lowerTool
		for _, value := range toolArgs {
			combined += " " + strings.ToLower(value)
		}

		blockedPatterns := []string{
			"sqlmap", "dalfox", "nuclei", "nikto", "xsstrike", "commix",
			"tplmap", "ssrfmap", "msfconsole", "metasploit", "searchsploit",
			"exploit-db", "wpscan", "joomscan",
			"union select", "<script", "alert(", "sleep(", "pg_sleep",
			"waitfor delay", "../etc/passwd", "/etc/passwd", "169.254.169.254",
			"__proto__", "%0d%0a", "jndi:", "burp collaborator",
		}
		for _, pattern := range blockedPatterns {
			if strings.Contains(combined, pattern) {
				return true, fmt.Sprintf("Blocked %q because this scan is limited to reconnaissance and reporting. Allowed recon includes DNS records, IP resolution, ports, services, HTTP metadata, technologies, URLs, and non-exploit evidence collection.", pattern)
			}
		}
		return false, ""
	}

	// General phase-restriction backstop: a first-class tool whose class
	// belongs to an excluded methodology phase does not run. Terminal
	// commands are deliberately NOT classified here — the plan is the
	// main authority and a payload-regex wall would be brittle.
	lowerTool := strings.ToLower(toolName)
	toolClass := ""
	switch lowerTool {
	case "verify_oob", "verify_timing", "probe_hypothesis":
		toolClass = strings.TrimSpace(toolArgs["vuln_class"])
		if toolClass == "" {
			toolClass = strings.TrimSpace(toolArgs["class"])
		}
	default:
		toolClass = firstClassToolClass[lowerTool]
	}
	if toolClass == "" {
		return false, ""
	}
	def, ok := LookupVulnClass(toolClass)
	if !ok {
		return false, ""
	}
	if methodology.Allows(a.allowedPhases, def.Phase) {
		return false, ""
	}
	return true, fmt.Sprintf("%s exercises the %s lane (methodology phase %d), which is not part of this scan's selected phases. Do not run excluded-phase methodology: work the selected phases or record the excluded lane's disposition.", toolName, def.ID, def.Phase)
}

func (a *Agent) shouldBlockForActivityPolicy(toolName string, toolArgs map[string]string) (bool, string) {
	passiveScan := normalizeActivityMode(a.scanIntensity) == activityModePassive
	passiveReconGuard := a.passiveReconGuardActive && a.shouldUsePassiveReconGuard()
	passiveRecon := normalizeActivityMode(a.reconMode) == activityModePassive && (a.discoveryMode || isReconReportOnlyPhaseSelection(a.allowedPhases) || passiveReconGuard)
	if !passiveScan && !passiveRecon {
		return false, ""
	}

	lowerTool := strings.ToLower(toolName)
	if lowerTool == "web_search" {
		if passiveReconGuard {
			a.recordPassiveReconLookup(toolName, toolArgs)
		}
		return false, ""
	}
	switch lowerTool {
	case "add_note", "read_notes", "finish", "list_skills", "read_skill", "report_vulnerability", "agentmail":
		return false, ""
	case "browser_action", "page_agent":
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}

	combined := lowerTool
	for _, value := range toolArgs {
		combined += " " + strings.ToLower(value)
	}
	if isAllowedPassiveLookup(combined, a.activityHosts) {
		if passiveReconGuard {
			a.recordPassiveReconLookup(toolName, toolArgs)
		}
		return false, ""
	}
	if containsActiveAccessPattern(combined) {
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}
	if referencesActivityTarget(combined, a.activityHosts) {
		if isAllowedLocalArtifactAnalysis(lowerTool, toolArgs) {
			if passiveReconGuard {
				a.recordPassiveReconLookup(toolName, toolArgs)
			}
			return false, ""
		}
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}
	return false, ""
}

// shouldBlockForOutOfScope rejects Gated_Tool calls whose arguments
// reference the operator's own machine or local network — loopback,
// RFC1918, link-local, ULA, unspecified, hostnames that resolve to
// any of those, or the dashboard's own bind:port listener. Runs
// unconditionally — even in active mode — so the agent cannot pivot
// into the operator's box from a Gated_Tool.
//
// Tools subject to this gate (Gated_Tools):
//
//   - terminal_execute, python_action, browser_action, page_agent,
//     pageagent — anything that can hit a network target.
//   - report_vulnerability — files findings; the explicit
//     target/endpoint arguments are checked too.
//   - http_request, send_request — only the request's destination (the
//     url argument) is checked, not hosts named in its query, headers or
//     body: those are payloads aimed at the target (an SSRF probe such as
//     ?url=http://127.0.0.1/ is the target's business, not ours). Redirect
//     hops are checked by checkHTTPHop, which the tools call before
//     following each one.
//
// All other tools (notes, finish, web_search, agentmail, list_skills,
// read_skill, etc.) bypass this gate entirely — they are exempt
// because they don't probe targets.
//
// Activity_Hosts (a.activityHosts) is intentionally NOT consulted
// here. Engagement-scope policing is no longer the agent guard's
// job; this function only protects the operator's machine and
// listener (per design.md → "Open Question: Requirement 3.7"). The
// Local_Or_Listener_Host check fires regardless of whether scope is
// populated.
//
// Returns (false, "") when:
//
//   - the tool is not in the gated list,
//   - the args don't reference any host-shaped token,
//   - none of the referenced hosts are Local_Or_Listener_Hosts.
func (a *Agent) shouldBlockForOutOfScope(toolName string, toolArgs map[string]string) (bool, string) {
	lowerTool := strings.ToLower(toolName)
	switch lowerTool {
	case "http_request", "send_request":
		// A call without parameter tags arrives as _raw, which the registry
		// copies into url before running the tool: check both.
		for _, raw := range []string{toolArgs["url"], toolArgs["_raw"]} {
			for _, dest := range httpToolDestinations(raw) {
				if scopeguard.IsLocalOrListener(a.localGuard, dest) {
					return true, fmt.Sprintf(
						"%q points at the operator's machine or local network. "+
							"Refusing to send an HTTP request to localhost / this machine / "+
							"the dashboard's listener.", dest,
					)
				}
			}
		}
		return false, ""
	case "terminal_execute", "python_action", "browser_action", "page_agent", "pageagent",
		"report_vulnerability", "authz_matrix", "probe_hypothesis":
		// gated
	default:
		return false, ""
	}

	// Pull every host-looking token from the args. An empty result
	// just means no host was named (e.g. hostless local-artifact
	// commands like grep/awk/jq) — let those flow through.
	hosts := extractHostsFromArgs(toolArgs)
	for _, h := range hosts {
		if scopeguard.IsLocalOrListener(a.localGuard, h) {
			return true, fmt.Sprintf(
				"%q points at the operator's machine or local network. "+
					"Refusing to probe localhost / RFC1918 / the dashboard's "+
					"listener from a Gated_Tool.", h,
			)
		}
	}

	// Belt-and-braces leg for report_vulnerability: validate the
	// explicit `target` and `endpoint` arguments directly against
	// the Local_Or_Listener_Host classifier. The findings handler
	// must not file a report against the operator's own machine
	// even if extractHostsFromArgs missed the token shape.
	// Activity_Hosts is NOT consulted here — engagement-scope
	// policing is no longer this guard's job.
	if lowerTool == "report_vulnerability" {
		rawTarget := strings.TrimSpace(toolArgs["target"])
		rawEndpoint := strings.TrimSpace(toolArgs["endpoint"])
		for _, raw := range []string{rawTarget, rawEndpoint} {
			if raw == "" {
				continue
			}
			if scopeguard.IsLocalOrListener(a.localGuard, raw) {
				return true, fmt.Sprintf(
					"report_vulnerability target/endpoint %q points at the operator's machine or local network. "+
						"Refusing to probe localhost / RFC1918 / the dashboard's "+
						"listener from a Gated_Tool.", raw,
				)
			}
		}
	}

	return false, ""
}

// httpToolDestinations returns the forms of an http_request / send_request
// url argument to classify: the value as given and, when it has no http(s)://
// prefix, the https:// form http_request actually sends ("localhost/x" is a
// path to url.Parse but a request to localhost once prefixed).
func httpToolDestinations(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := []string{raw}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		out = append(out, "https://"+raw)
	}
	return out
}

// checkHTTPHop is the request guard the agent installs on its tool
// registries (tools.Registry.SetRequestGuard). http_request and send_request
// call it for every redirect hop before following it, so a redirect cannot
// reach what a direct request is refused: the operator's machine or listener
// (shouldBlockForOutOfScope) or another port of a port-pinned target
// (shouldBlockForTargetScope).
func (a *Agent) checkHTTPHop(rawURL string) error {
	if scopeguard.IsLocalOrListener(a.localGuard, rawURL) {
		return fmt.Errorf("it points at the operator's machine or the dashboard's listener")
	}
	if pins := pinnedTargetPorts(a.targets); len(pins) > 0 {
		if host, port := referenceHostPort(rawURL); outsidePinnedPort(pins, host, port) {
			return fmt.Errorf("%s is in scope only on port %s, the port the scan target names",
				host, pinnedPortList(pins[host]))
		}
	}
	return nil
}

// extractHostsFromArgs scans every value in toolArgs for URL/host
// tokens and returns the lowercased hostnames found. Tokens with no
// host are dropped. Used by shouldBlockForOutOfScope.
func extractHostsFromArgs(toolArgs map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, raw := range toolArgs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// LLM tool arguments are already capped at 32 KB upstream
		// before reaching this guard, so no per-value truncation is
		// performed here. The tokenizer runs over the raw value.
		for _, span := range extractEmbeddedURLs(raw) {
			add(extractHostFromTokenForScope(span))
		}
		for _, tok := range scopeHostTokens(raw) {
			if h := bareIPv6Host(raw, tok); h != "" {
				add(h)
				continue
			}
			add(extractHostFromTokenForScope(tok.text))
			for _, h := range colonListHosts(tok.text) {
				add(h)
			}
		}
		for _, h := range extractBracketedURLHosts(raw) {
			add(h)
		}
		// Browsers and Python's urllib drop tabs and newlines inside a URL,
		// and Python source can spell them as escapes ("http://loc\talhost/").
		// The separator pass splits on them, so also read the URLs of the
		// value with those characters removed. Removing them also joins
		// ordinary lines, so only hosts written as addresses are kept here.
		if stripped := stripURLControls(raw); stripped != raw {
			candidates := extractEmbeddedURLs(stripped)
			for _, tok := range scopeHostTokenSplit(stripped) {
				if webSchemeToken(tok) {
					candidates = append(candidates, tok)
				}
			}
			for _, c := range candidates {
				if h := extractHostFromTokenForScope(c); readsAsAddress(h) {
					add(h)
				}
			}
		}
	}
	return out
}

// scopeToken is a token from scopeHostTokens and its offset in the
// original string.
type scopeToken struct {
	text  string
	start int
}

// scopeHostTokens splits s like scopeHostTokenSplit and keeps each token's
// offset, so a caller can tell "data[::1]" from "nc ::1 80".
func scopeHostTokens(s string) []scopeToken {
	var out []scopeToken
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		out = append(out, scopeToken{text: s[start:end], start: start})
		start = -1
	}
	for i, r := range s {
		if scopeTokenSeparator(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(s))
	return out
}

// bareIPv6Host returns tok as a host when it is an IPv6 literal, written
// bare ("nc ::1 9137", "('::ffff:127.0.0.1', 80)") or in brackets outside a
// URL ("curl -g '[::1]:9137/'", "--resolve h:443:[::1]", "TCP6:[::1]:80").
// The usual path trims ':' from token edges, which turns "::1" into "1".
// A literal inside a subscript such as data[::1] or arr[0, ::] is skipped.
func bareIPv6Host(s string, tok scopeToken) string {
	t := strings.Trim(tok.text, ".,;?!(){}\"'`<>")
	if !strings.Contains(t, ":") || strings.Contains(t, "/") {
		return ""
	}
	addr := t
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	if net.ParseIP(addr) == nil || inSubscript(s, tok.start) {
		return ""
	}
	return strings.ToLower(t)
}

// inSubscript reports whether offset pos of s is inside a bracket that
// follows an identifier, "]" or ")" — an index or slice such as x[::1] —
// rather than a bracketed address.
func inSubscript(s string, pos int) bool {
	depth := 0
	for i := pos - 1; i >= 0 && pos-i <= 256; i-- {
		switch s[i] {
		case ']':
			depth++
		case '[':
			if depth > 0 {
				depth--
				continue
			}
			if i == 0 {
				return false
			}
			c := s[i-1]
			return c == '_' || c == ']' || c == ')' ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		case '\n':
			return false
		}
	}
	return false
}

// colonListHosts returns the address fields of a token with several colons
// that is not an IPv6 literal, such as curl's "--resolve host:443:127.0.0.1"
// and "--connect-to host:443:2130706433:9137" or socat's "TCP:127.0.0.1:80",
// where the whole token is otherwise classified as one unresolvable name.
// Dotted addresses and localhost names count in any field; a number without
// dots counts only as the address of curl's name:port:address form, so
// slices such as data[0x0:0x10:2] and PCI addresses such as 0000:00:1f.3
// are left alone.
func colonListHosts(token string) []string {
	token = strings.Trim(token, ".,;:?!(){}\"'`<>")
	if strings.Count(token, ":") < 2 || strings.Contains(token, "://") || strings.ContainsAny(token, "/[]") {
		return nil
	}
	if i := strings.IndexByte(token, '%'); net.ParseIP(token) != nil || (i >= 0 && net.ParseIP(token[:i]) != nil) {
		return nil
	}
	parts := strings.Split(token, ":")
	curlForm := !scopeguard.LooksNumericIPv4(parts[0]) && isDecimalPort(parts[1])
	var out []string
	for i, part := range parts {
		if !isAddressShaped(part) {
			continue
		}
		if scopeguard.LooksNumericIPv4(part) && !strings.Contains(part, ".") && (!curlForm || i != 2) {
			continue
		}
		out = append(out, strings.ToLower(part))
	}
	return out
}

// urlControlEscapes matches the ways Python and shell source spell a tab,
// newline or carriage return inside a string literal.
var urlControlEscapes = regexp.MustCompile(`(?i)\\(?:[tnr]|x0[9ad]|u000[9ad]|u0000000[9ad]|0?1[12]|0?15)`)

// stripURLControls removes tabs, newlines and carriage returns, written
// literally or as escapes.
func stripURLControls(s string) string {
	s = urlControlEscapes.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

// webSchemeToken reports whether token starts with a network URL scheme
// followed by something ("http:/h", "https:\\h", "gopher:/h:70/"). Browsers
// and curl accept those spellings; net/url reads them as having no host.
func webSchemeToken(token string) bool {
	i := strings.IndexByte(token, ':')
	if i <= 0 || !scopeguard.IsNetworkURLScheme(token[:i]) {
		return false
	}
	return strings.TrimLeft(token[i+1:], `/\`) != ""
}

// isAddressShaped reports whether h is written as an address rather than a
// name: an IP literal, localhost or *.localhost, or a numeric IPv4 form
// curl and glibc accept. Numbers that are rarely addresses in practice (see
// isNonAddressNumber) and two- or three-part decimals such as "127.1", which
// are far more often floats or versions, are excluded.
func isAddressShaped(h string) bool {
	l := strings.ToLower(h)
	if l == "localhost" || strings.HasSuffix(l, ".localhost") {
		return true
	}
	if net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(l, "["), "]")) != nil {
		return true
	}
	if !scopeguard.LooksNumericIPv4(l) || isNonAddressNumber(l) {
		return false
	}
	return !isVersionLike(l) || strings.Count(l, ".") == 3
}

// readsAsAddress reports whether h (a host, or a whole URL handed on to the
// classifier) names its host as an address: h itself, or any host the
// classifier would read out of it.
func readsAsAddress(h string) bool {
	if h == "" {
		return false
	}
	if isAddressShaped(h) {
		return true
	}
	for _, rh := range scopeguard.ReadingHosts(h) {
		if isAddressShaped(rh) {
			return true
		}
	}
	return false
}

// isDecimalPort reports whether p is a port number curl and the other
// clients accept: 1-65535 in decimal.
func isDecimalPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strings.Trim(p, "0123456789") == ""
}

// extractBracketedURLHosts returns the IPv6 literals written as URL hosts
// ("http://[::1]:8080/", "http://user@[::ffff:127.0.0.1]/"). The separator
// pass splits on '[' and ']', so without this the address inside the
// brackets is never classified. Only a bracket that directly follows "//"
// or "@" counts, so Python slices such as data[::1] are left alone.
func extractBracketedURLHosts(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '[' || i == 0 {
			continue
		}
		if s[i-1] != '@' && (i < 2 || s[i-2:i] != "//") {
			continue
		}
		j := strings.IndexByte(s[i+1:], ']')
		if j <= 0 {
			continue
		}
		inner := s[i+1 : i+1+j]
		if strings.ContainsAny(inner, " \t\r\n[") {
			continue
		}
		if !strings.Contains(inner, ":") {
			continue
		}
		out = append(out, strings.ToLower(inner))
		i += j + 1
	}
	return out
}

// scopeHostTokenSplit splits a free-form string into tokens that are
// candidates for host extraction. Splits on whitespace and common
// shell metacharacters so URLs inside curl/python invocations are
// still found. The separator set is owned by scopeTokenSeparator so
// extractEmbeddedURLs and the tokenizer pass agree on token edges.
func scopeHostTokenSplit(s string) []string {
	return strings.FieldsFunc(s, scopeTokenSeparator)
}

// extractHostFromTokenForScope pulls a hostname out of a token, or
// returns "" if the token is not host-shaped. Accepts:
//
//   - http(s)://host[:port]/path
//   - host:port
//   - bare host (must contain a dot or be a literal IP)
//   - [ipv6]
func extractHostFromTokenForScope(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	// Strip trailing punctuation, but NOT brackets — `[ipv6]:port`
	// needs them preserved for net.SplitHostPort to recognize the
	// shape.
	token = strings.Trim(token, ".,;:?!(){}\"'`<>")

	if webSchemeToken(token) {
		// Browsers and curl also open "http:/host", "http:\\host" and
		// "http://a\@host", which net/url reads differently or refuses.
		// Hand anything but a plain URL to the classifier, which reads it
		// the way those clients do.
		if u, err := url.Parse(token); err == nil && u.Host != "" && !strings.Contains(token, `\`) {
			return strings.ToLower(u.Hostname())
		}
		return strings.ToLower(token)
	}
	if strings.Contains(token, "://") {
		u, err := url.Parse(token)
		if err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
		if err != nil && !strings.HasPrefix(token, "://") {
			// net/url refuses some URLs (an unescaped space or escape in
			// the host). Hand the whole URL to the classifier, which reads
			// its authority directly.
			return strings.ToLower(token)
		}
	}

	// host:port, optionally followed by a path ("127.0.0.1:9137/api").
	hostPort := token
	if i := strings.IndexByte(hostPort, '/'); i > 0 {
		hostPort = hostPort[:i]
	}
	if h, p, err := net.SplitHostPort(hostPort); err == nil && h != "" {
		// SplitHostPort keeps brackets around the host for [ipv6]:port,
		// so peel them and accept the inner IP literal.
		h = strings.TrimPrefix(h, "[")
		h = strings.TrimSuffix(h, "]")
		// A number before a colon is an address only with a real port
		// after it: "data[0x0:0x10]" and "08:30" are not hosts. A dotted
		// IPv4 literal is always one ("root@127.0.0.1:/tmp/" for scp).
		if scopeguard.LooksNumericIPv4(h) && net.ParseIP(h) == nil && (!isDecimalPort(p) || isNonAddressNumber(h)) {
			return ""
		}
		return strings.ToLower(h)
	}

	if ip := net.ParseIP(token); ip != nil {
		return strings.ToLower(token)
	}
	// A four-part numeric form ("0177.0.0.1", "127.000.000.001") is an
	// address to curl, Python and glibc even though net.ParseIP rejects it;
	// classify it instead of dropping it as a version string below.
	if strings.Count(token, ".") == 3 && isAddressShaped(token) {
		return strings.ToLower(token)
	}
	// "127.0.0.1/", "localhost/api": curl and wget take a schemeless host
	// followed by a path. Classify the head when it is written as a dotted
	// address or a localhost name; other x/y tokens are file paths or
	// arithmetic ("2147483647/2"). "0.0.0.0/0" and "::/0" mean "any
	// address" in firewall rules, not this machine.
	if i := strings.IndexByte(token, '/'); i > 0 {
		head, rest := token[:i], token[i+1:]
		anyNetwork := false
		if ip := net.ParseIP(head); ip != nil && ip.IsUnspecified() {
			anyNetwork = rest != "" && len(rest) <= 3 && strings.Trim(rest, "0123456789") == ""
		}
		dotlessNumber := scopeguard.LooksNumericIPv4(head) && !strings.Contains(head, ".")
		if !anyNetwork && !dotlessNumber && isAddressShaped(head) {
			return strings.ToLower(head)
		}
	}
	if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
		inner := token[1 : len(token)-1]
		if net.ParseIP(inner) != nil {
			return strings.ToLower(inner)
		}
	}
	if strings.Contains(token, ".") && !strings.ContainsAny(token, " /\\") {
		if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") || strings.HasPrefix(token, "/") {
			return ""
		}
		if isVersionLike(token) {
			return ""
		}
		// Filter file-name shaped tokens (notes.json, scan.txt,
		// recon.csv) so local artifact analysis isn't blocked.
		if looksLikeFilename(token) {
			return ""
		}
		return strings.ToLower(token)
	}
	return ""
}

// isNonAddressNumber reports a number in host:port position that is not an
// address in practice: a one- to three-digit decimal ("0:10" in a Python
// slice, "08:30", "16:9"), or a numeric form that no IPv4 parser accepts
// ("4294967296"). The classifier would read "0" as 0.0.0.0 and refuse
// numeric forms it cannot parse, which would block ordinary code and times.
// Addresses written as URLs ("http://0:9137/") are still classified.
func isNonAddressNumber(h string) bool {
	if !scopeguard.LooksNumericIPv4(h) {
		return false
	}
	if len(h) <= 3 && !strings.Contains(h, ".") && !strings.ContainsAny(h, "xX") {
		return true
	}
	_, ok := scopeguard.ParseIPv4Loose(h)
	return !ok
}

// looksLikeFilename returns true when token has the shape <name>.<ext>
// with a recognized extension. Used by extractHostFromTokenForScope to
// avoid treating filenames as hostnames. The extension list is short
// — TLDs that overlap with extensions (e.g. ".sh" for Saint Helena)
// are uncommon and real URLs usually have at least one label before
// the TLD anyway.
func looksLikeFilename(token string) bool {
	idx := strings.LastIndex(token, ".")
	if idx <= 0 || idx == len(token)-1 {
		return false
	}
	ext := strings.ToLower(token[idx+1:])
	switch ext {
	case "txt", "json", "csv", "log", "yaml", "yml", "xml", "html", "htm",
		"md", "sh", "py", "js", "ts", "tsx", "jsx", "go", "rs", "rb",
		"php", "java", "cpp", "tar", "gz", "zip", "tgz",
		"pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
		"sql", "db", "sqlite", "pem", "key", "crt", "pcap", "har":
		return true
	}
	return false
}

// isVersionLike returns true for strings that are entirely digits +
// dots ("1.2.3", "10.0", "v1.0.0"). Used by
// extractHostFromTokenForScope to skip CLI version arguments.
func isVersionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// extractEmbeddedURLs scans s for case-insensitive "http://" and
// "https://" substrings and returns each contiguous URL span. Each
// span starts at a scheme-prefix occurrence and ends at the first
// scopeHostTokenSplit separator rune or the end of s, whichever
// comes first. The helper lets the host-extraction path see URLs
// embedded inside query-parameter redirects, userinfo wrappers, and
// other key=value forms before scopeHostTokenSplit's separator pass
// runs over the same value. When a span cannot be parsed as a URL
// later, extractHostFromTokenForScope drops it silently and the
// separator pass still recovers any bare host.
func extractEmbeddedURLs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	n := len(s)
	for i := 0; i < n; {
		prefixLen := 0
		switch {
		case i+7 <= n && strings.EqualFold(s[i:i+7], "http://"):
			prefixLen = 7
		case i+8 <= n && strings.EqualFold(s[i:i+8], "https://"):
			prefixLen = 8
		}
		if prefixLen == 0 {
			i++
			continue
		}
		end := i + prefixLen
	span:
		for end < n {
			r, size := utf8.DecodeRuneInString(s[end:])
			if size == 0 {
				size = 1
			}
			if scopeTokenSeparator(r) {
				break span
			}
			end += size
		}
		out = append(out, s[i:end])
		i = end
	}
	return out
}

// scopeTokenSeparator reports whether r is one of the runes
// scopeHostTokenSplit treats as a token boundary. Kept in lockstep
// with that function's switch so the URL sweep and the separator-pass
// tokenizer agree on token edges.
func scopeTokenSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r',
		'"', '\'', '`',
		'(', ')', '{', '}', '[', ']',
		',', ';', '|', '&', '<', '>',
		'=', '?', '#', '@':
		return true
	}
	return false
}

func passivePolicyBlockReason(passiveScan bool) string {
	if passiveScan {
		return "Passive scanning is enabled, so direct target access and active probes are blocked. Use web_search, public passive datasets, existing notes, or already collected artifacts instead."
	}
	return "Passive reconnaissance is enabled for this phase, so direct target access and active recon probes are blocked. Use web_search, public passive datasets, existing notes, or already collected artifacts instead."
}

func referencesActivityTarget(text string, hosts []string) bool {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if strings.Contains(text, host) {
			return true
		}
	}
	return false
}

func isAllowedLocalArtifactAnalysis(toolName string, toolArgs map[string]string) bool {
	switch toolName {
	case "terminal_execute":
		cmd := strings.TrimSpace(strings.ToLower(toolArgs["command"]))
		if cmd == "" {
			return false
		}
		if containsActiveAccessPattern(cmd) || containsPassiveLookupBreaker(cmd) {
			return false
		}
		readOnlyPrefixes := []string{
			"cat ", "grep ", "egrep ", "fgrep ", "rg ", "jq ", "sed ", "awk ",
			"sort ", "uniq ", "wc ", "head ", "tail ", "cut ", "tr ", "find ",
			"ls ", "stat ", "file ",
		}
		for _, prefix := range readOnlyPrefixes {
			if strings.HasPrefix(cmd, prefix) {
				return true
			}
		}
		return false
	case "python_action":
		code := strings.ToLower(toolArgs["code"] + " " + toolArgs["script"])
		if code == "" || containsActiveAccessPattern(code) {
			return false
		}
		networkMarkers := []string{"requests", "urllib", "http.client", "socket", "subprocess", "os.system", "popen("}
		for _, marker := range networkMarkers {
			if strings.Contains(code, marker) {
				return false
			}
		}
		return strings.Contains(code, "open(") || strings.Contains(code, "pathlib") || strings.Contains(code, "json.load")
	default:
		return false
	}
}

func isAllowedPassiveLookup(text string, hosts []string) bool {
	passiveSources := []string{
		"crt.sh", "web.archive.org", "dns.bufferover.run", "urlscan.io",
		"otx.alienvault.com", "alienvault.com", "censys.io", "shodan.io",
		"rapiddns.io", "certspotter.com", "securitytrails.com", "virustotal.com",
		"github.com", "google.com/search", "bing.com/search",
	}
	for _, source := range passiveSources {
		if strings.Contains(text, source) && !containsDirectTargetURL(text, hosts) && !containsPassiveLookupBreaker(text) {
			return true
		}
	}
	if strings.Contains(text, "subfinder ") || strings.Contains(text, " subfinder") ||
		strings.Contains(text, "assetfinder ") || strings.Contains(text, " assetfinder") ||
		strings.Contains(text, "findomain ") || strings.Contains(text, " findomain") ||
		strings.Contains(text, "amass enum -passive") {
		blockers := []string{" -active", " dnsx", " httpx", " nmap", " naabu", " masscan", " puredns", " shuffledns"}
		for _, blocker := range blockers {
			if strings.Contains(text, blocker) {
				return false
			}
		}
		return true
	}
	return false
}

func containsPassiveLookupBreaker(text string) bool {
	breakers := []string{
		"nmap", "masscan", "naabu", "httpx", "ffuf", "gobuster", "feroxbuster",
		"dirsearch", "katana", "gospider", "nuclei", "sqlmap", "dalfox", "nikto",
		"wpscan", "whatweb", "dnsx", "massdns", "puredns", "shuffledns",
	}
	for _, breaker := range breakers {
		if strings.Contains(text, breaker) {
			return true
		}
	}
	return false
}

func containsDirectTargetURL(text string, hosts []string) bool {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if strings.Contains(text, "http://"+host) || strings.Contains(text, "https://"+host) ||
			strings.Contains(text, "http://www."+host) || strings.Contains(text, "https://www."+host) {
			return true
		}
	}
	return false
}

func containsActiveAccessPattern(text string) bool {
	patterns := []string{
		"browser_action", "page_agent",
		"curl ", " wget ", "httpx", "nmap", "masscan", "naabu",
		"ffuf", "gobuster", "feroxbuster", "dirsearch", "katana", "gospider", "hakrawler",
		"nuclei", "sqlmap", "dalfox", "nikto", "wpscan", "joomscan", "whatweb", "wafw00f",
		"dnsx", "massdns", "puredns", "shuffledns", " dig ", " host ", "nslookup",
		"ping ", "traceroute", "openssl s_client", " nc ", "netcat", "telnet ",
		"<script", "alert(", "sleep(", "pg_sleep", "waitfor delay", "../etc/passwd", "/etc/passwd",
		"169.254.169.254", "burp collaborator",
	}
	padded := " " + text + " "
	for _, pattern := range patterns {
		if strings.Contains(padded, pattern) {
			return true
		}
	}
	return false
}
