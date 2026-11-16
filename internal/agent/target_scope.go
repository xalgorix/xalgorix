package agent

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Target boundaries the operator expressed through the scan request itself,
// enforced alongside the local-machine guard in agent_guard.go:
//
//   - Port pin: a target URL that names a port pins its host to that port.
//     Other ports on the same host are different services the operator did
//     not include. A host also given without a port is not pinned.
//   - Single-host scope: a single-target scan covers that host only. The
//     operator chose it over a wildcard scan, so subdomains are neither
//     enumerated nor owed coverage.

// pinnedTargetPorts maps each target host whose every target names an
// explicit port to the set of those ports.
func pinnedTargetPorts(targets []string) map[string]map[string]bool {
	pins := make(map[string]map[string]bool)
	unpinned := make(map[string]bool)
	for _, t := range targets {
		host, port := targetHostPort(t)
		if host == "" {
			continue
		}
		if port == "" {
			unpinned[host] = true
			continue
		}
		if pins[host] == nil {
			pins[host] = make(map[string]bool)
		}
		pins[host][port] = true
	}
	for host := range unpinned {
		delete(pins, host)
	}
	return pins
}

// targetHostPort returns a configured target's host and the port it names
// explicitly ("" when none). Domain scopes (*.example.com, domain:) never pin.
func targetHostPort(raw string) (host, port string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || strings.HasPrefix(raw, "*.") || strings.HasPrefix(raw, "domain:") {
		return "", ""
	}
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	return strings.TrimSuffix(u.Hostname(), "."), u.Port()
}

// referenceHostPort returns the host and effective port of a URL or
// host:port reference. The port is the explicit one, else the scheme's
// default; "" when neither is known (a bare host or path).
func referenceHostPort(raw string) (host, port string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "/") {
		return "", ""
	}
	scheme := ""
	if i := strings.Index(raw, "://"); i > 0 {
		scheme = strings.ToLower(raw[:i])
	} else {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port = u.Port()
	if port == "" {
		switch scheme {
		case "http", "ws":
			port = "80"
		case "https", "wss":
			port = "443"
		}
	}
	return host, port
}

// outsidePinnedPort reports whether a reference names a pinned host on a
// port the targets did not include.
func outsidePinnedPort(pins map[string]map[string]bool, host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	ports, pinned := pins[host]
	return pinned && !ports[port]
}

func pinnedPortList(ports map[string]bool) string {
	out := make([]string, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// sameSiteHost treats a host and its www. form as one site: an apex target
// that redirects to www (or the reverse) is still the configured host.
func sameSiteHost(a, b string) bool {
	return strings.TrimPrefix(a, "www.") == strings.TrimPrefix(b, "www.")
}

// isSiblingSubdomain reports whether host belongs to a target's registrable
// domain without being a target host itself.
func isSiblingSubdomain(targets []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	family := registrableDomain(host)
	if family == "" {
		return false
	}
	sibling := false
	for _, t := range targets {
		th, _ := targetHostPort(t)
		if th == "" || net.ParseIP(th) != nil {
			continue
		}
		if sameSiteHost(th, host) {
			return false
		}
		if registrableDomain(th) == family {
			sibling = true
		}
	}
	return sibling
}

// hostInTargetBoundary reports whether an inventoried host ("host" or
// "host:port") lies inside the operator's target boundaries.
func hostInTargetBoundary(state *ScanState, host string) bool {
	if state == nil {
		return true
	}
	h, port := referenceHostPort(host)
	if outsidePinnedPort(pinnedTargetPorts(state.ScanTargets), h, port) {
		return false
	}
	return !state.SingleHostScope || !isSiblingSubdomain(state.ScanTargets, h)
}

// endpointInTargetBoundary is hostInTargetBoundary for an endpoint, counting
// the port its scheme implies.
func endpointInTargetBoundary(state *ScanState, endpoint string) bool {
	if state == nil {
		return true
	}
	h, port := referenceHostPort(endpoint)
	if h == "" {
		return true // relative path: on the target
	}
	if outsidePinnedPort(pinnedTargetPorts(state.ScanTargets), h, port) {
		return false
	}
	return !state.SingleHostScope || !isSiblingSubdomain(state.ScanTargets, h)
}

// Tools that never reach the network; the target-scope guard skips them so
// notes and plans can still mention excluded services.
var targetScopeExemptTools = map[string]bool{
	"add_note": true, "read_notes": true, "finish": true, "update_plan": true,
	"list_skills": true, "read_skill": true, "search_skills": true,
	"web_search": true, "cve_search": true, "exploit_search": true,
	"str_replace_editor": true, "list_files": true, "search_files": true,
	"code_search": true, "list_requests": true, "agentmail": true,
	"spawn_agent": true, "create_agent": true, "check_agent": true, "wait_agent": true,
}

var scopeURLPattern = regexp.MustCompile(`(?i)\b(?:https?|wss?)://[^\s"'<>\x60(){}\[\]|\\^]+`)

// Port-scanning commands and how they take an explicit port list.
var (
	portScannerPattern  = regexp.MustCompile(`(?i)(?:^|[\s;&|(/])(nmap|naabu|masscan|rustscan)(?:\s|$)`)
	scannerPortsPattern = regexp.MustCompile(`(?i)(?:^|\s)(?:-p|--ports?|-port)(?:=|\s+)?([0-9][0-9,\-]*)`)
	scannerWideOption   = regexp.MustCompile(`(?i)(?:^|\s)(?:--top-ports|-top-ports|-F|--range|-r)(?:\s|=|$)`)
)

// Subdomain discovery tooling, refused in single-host scans.
var subdomainEnumPattern = regexp.MustCompile(`(?i)\b(?:subfinder|amass|assetfinder|findomain|sublist3r|knockpy|shuffledns|puredns|crt\.sh|gobuster\s+dns)\b`)

// Network tools whose arguments name a request destination, checked against
// the single-host boundary below.
var fetchDestinationTools = map[string]bool{
	"terminal_execute": true, "python_action": true, "http_request": true,
	"send_request": true, "browser_action": true, "page_agent": true, "pageagent": true,
}

// shouldBlockForTargetScope refuses tool calls that leave the operator's
// target boundaries: another port of a port-pinned host, a port scan of
// such a host beyond its pinned ports, subdomain discovery in a single-host
// scan, or — in a single-host scan — a request to another organization's
// domain (a third-party API, CDN, or partner backend found in the target's
// pages).
func (a *Agent) shouldBlockForTargetScope(toolName string, toolArgs map[string]string) (bool, string) {
	lowerTool := strings.ToLower(toolName)
	if targetScopeExemptTools[lowerTool] {
		return false, ""
	}
	pins := pinnedTargetPorts(a.targets)
	if len(pins) == 0 && !a.singleHostScope {
		return false, ""
	}
	fetchTool := a.singleHostScope && fetchDestinationTools[lowerTool]
	keys := make([]string, 0, len(toolArgs))
	for k := range toolArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := toolArgs[k]
		if v == "" {
			continue
		}
		if len(pins) > 0 {
			if blocked, reason := pinnedPortViolation(pins, v); blocked {
				return true, reason
			}
		}
		if a.singleHostScope && subdomainEnumPattern.MatchString(v) {
			return true, "This is a single-host scan: subdomains are outside it, so subdomain discovery " +
				"does not run. Keep testing the configured host; a wildcard scan covers subdomains."
		}
		if fetchTool {
			for _, h := range fetchDestinationHosts(v) {
				if a.otherOrganizationHost(h) {
					return true, fmt.Sprintf(
						"%s belongs to a different organization than the scan target. This is a single-host "+
							"scan of the configured target: third-party APIs, CDNs, and partner backends you "+
							"find in its pages, redirects, or JavaScript are outside this engagement — note them "+
							"if useful, but do not fetch, scan, or report them. The target's own subdomains (for "+
							"example its API or login host) are fine. Hosts used only as payloads (SSRF, "+
							"open-redirect, OOB callbacks) are fine too.", h)
				}
			}
		}
	}
	return false, ""
}

// plainHostPattern accepts a literal DNS host name. A host that carries shell
// or format syntax ("site.com$path", "$h", "%s", "{host}") is a template, not
// a destination: the real host is unknown until the shell expands it, so it is
// never treated as off-target.
var plainHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// numericHostPattern matches IP-literal spellings that net.ParseIP rejects
// (octal "0177.0.0.1", short "127.1", hex "0x7f.0.0.1"); SSRF payloads use them.
var numericHostPattern = regexp.MustCompile(`^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$`)

// fetchDestinationHosts returns the literal DNS host names of http(s)/ws(s)
// URLs in a command that read as REQUEST DESTINATIONS. It deliberately misses
// rather than over-matches, because a false block silently drops coverage:
//   - a URL preceded (past one quote and spaces) by '=' or ':' is a payload
//     value — a query parameter, form field, header, or JSON/dict value;
//   - templated hosts (shell variables, format strings) are skipped;
//   - IP literals are skipped: SSRF payloads use them, and the target is often
//     tested by its own IP.
func fetchDestinationHosts(value string) []string {
	var out []string
	for _, loc := range scopeURLPattern.FindAllStringIndex(value, -1) {
		if isPayloadURLContext(value, loc[0]) {
			continue
		}
		tok := strings.TrimRight(value[loc[0]:loc[1]], ";,)'\"`")
		h, _ := referenceHostPort(tok)
		if h == "" || net.ParseIP(h) != nil || numericHostPattern.MatchString(h) || !plainHostPattern.MatchString(h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// isPayloadURLContext reports whether the URL starting at urlStart is a value
// inside a larger expression rather than a standalone fetch target. Looking back
// past one opening quote and any spaces, the URL is a payload when it follows:
//   - '=' or ':' — an assignment, query/form value, header, or JSON/dict value;
//   - '{'        — XML Clark notation ("{http://ns}tag");
//   - '+'        — string concatenation, or a URL inside a User-Agent string
//     ("(compatible; bot/2.0; +http://…)").
//
// '(', '[' and ',' are deliberately NOT payload context. requests.get("https://…")
// is a real destination, and replaying real scan traffic showed that URLs held
// in lists and tuples (["https://a","https://b"], ("case","https://…")) are
// fetched by the loop that follows about as often as they are payloads, so
// treating them as payloads let genuine other-organization fetches through.
func isPayloadURLContext(s string, urlStart int) bool {
	i := urlStart - 1
	if i >= 0 && (s[i] == '\'' || s[i] == '"' || s[i] == '`') {
		i--
	}
	for i >= 0 && (s[i] == ' ' || s[i] == '\t') {
		i--
	}
	if i < 0 {
		return false
	}
	switch s[i] {
	case '=', ':', '{', '+':
		return true
	}
	return false
}

// payloadTestDomains are names that stand for "an attacker-controlled or
// external host" in test payloads, or are callback/catch services that the
// scanner polls directly. They are never a third party's production service.
var payloadTestDomains = map[string]bool{
	"example.com": true, "example.net": true, "example.org": true,
	"evil.com": true, "evil.net": true, "evil.org": true,
	"attacker.com": true, "attacker.net": true, "malicious.com": true,
	"webhook.site": true, "oastify.com": true, "burpcollaborator.net": true,
	"requestbin.net": true, "pipedream.net": true, "canarytokens.com": true,
	"interact.sh": true, "dnslog.cn": true, "ceye.io": true,
	// interactsh's public servers. The scanner polls them directly, and SSRF
	// payload lists name them bare ("https://oast.pro/"), which the
	// "<token>.oast.*" callback pattern does not cover.
	"oast.pro": true, "oast.fun": true, "oast.live": true, "oast.site": true, "oast.online": true, "oast.me": true,
	// Echo and egress-check services used to verify outbound requests.
	"httpbin.org": true, "httpbingo.org": true, "ipify.org": true, "ifconfig.me": true, "ipinfo.io": true,
	"jsonplaceholder.typicode.com": true, "icanhazip.com": true, "neverssl.com": true, "nghttp2.org": true,
	// Wildcard-DNS / rebinding names that resolve to internal addresses: SSRF payloads.
	"nip.io": true, "sslip.io": true, "xip.io": true, "localtest.me": true, "lvh.me": true,
	"1u.ms": true, "rbndr.us": true,
	// Disposable inboxes used to create test accounts for authenticated testing.
	"mail.tm": true, "mail.gw": true, "guerrillamail.com": true, "1secmail.com": true,
	// The usual open-redirect payload destination.
	"google.com": true,
	// DNS-over-HTTPS resolvers, used to resolve the target itself.
	"cloudflare-dns.com": true, "dns.google": true,
}

// namespaceDomains host XML/SOAP/schema namespace URIs ("http://www.w3.org/2000/svg",
// "http://schemas.xmlsoap.org/wsdl/"). In payloads and parsing code these are
// identifiers, not fetch targets, and they belong to no scanned organization.
var namespaceDomains = map[string]bool{
	"w3.org": true, "xmlsoap.org": true, "purl.org": true, "oasis-open.org": true,
	"openxmlformats.org": true, "schemas.microsoft.com": true, "schemas.android.com": true,
	"maven.apache.org": true, "springframework.org": true,
}

// researchServiceDomains are public references the agent reads (exploit PoCs,
// advisories, archives, package metadata). Reading them is research, not a
// scan of another organization.
var researchServiceDomains = map[string]bool{
	"github.com": true, "githubusercontent.com": true, "github.io": true, "gitlab.com": true,
	"archive.org": true, "packetstormsecurity.com": true, "exploit-db.com": true,
	"nist.gov": true, "mitre.org": true, "cve.org": true, "maven.org": true,
	"npmjs.org": true, "npmjs.com": true, "pypi.org": true, "rubygems.org": true,
	"pkg.go.dev": true, "go.dev": true, "osv.dev": true, "rdap.org": true,
	// Vulnerability databases, mailing-list archives, code and web search.
	"vuldb.com": true, "seclists.org": true, "msrc.microsoft.com": true,
	"grep.app": true, "duckduckgo.com": true,
	// Package CDNs, read to inspect the exact library version a target ships.
	"unpkg.com": true, "jsdelivr.net": true, "cdnjs.cloudflare.com": true,
}

// inDomainSet reports whether host or any parent domain of it is in set. It
// matches by suffix rather than registrable domain, because some listed names
// (githubusercontent.com, nip.io) are public suffixes themselves.
func inDomainSet(host string, set map[string]bool) bool {
	for h := host; h != ""; {
		if set[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}

// unmanagedTLDHost reports whether host ends in a label that is not a real,
// ICANN-managed top-level domain. That covers the RFC 2606/6761 names (.test,
// .example, .invalid, .localhost, .local), cluster and internal names
// (kubernetes.default.svc, metadata.google.internal), and the placeholders
// agents write into payloads (attacker.tld, app.target, a.b). No other
// organization can own such a name on the public internet.
func unmanagedTLDHost(host string) bool {
	tld := host[strings.LastIndexByte(host, '.')+1:]
	if tld == "" {
		return false
	}
	_, icann := publicsuffix.PublicSuffix(tld)
	return !icann
}

// payloadLabelPattern matches registrable domains that announce themselves as
// attacker-controlled stand-ins in payloads ("attacker-domain.xyz",
// "evil-site.net"), beyond the exact names in payloadTestDomains.
var payloadLabelPattern = regexp.MustCompile(`^(?:attacker|evil|malicious)`)

// otherOrganizationHost reports whether a request destination belongs to a
// different organization than every scan target: a registrable domain (eTLD+1)
// that no target shares. The target host, its www./apex form, and its own
// subdomains are the same organization. OOB callback hosts and payload test
// domains are never "another organization". An unresolvable registrable
// domain is treated as same-organization, so ambiguity never blocks.
func (a *Agent) otherOrganizationHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || oastHostPattern.MatchString(host) || unmanagedTLDHost(host) {
		return false
	}
	if inDomainSet(host, payloadTestDomains) || inDomainSet(host, researchServiceDomains) ||
		inDomainSet(host, namespaceDomains) ||
		strings.HasPrefix(host, "rdap.") || strings.HasPrefix(host, "whois.") {
		return false
	}
	fam := registrableDomain(host)
	if fam == "" || payloadLabelPattern.MatchString(fam) {
		return false
	}
	known := false
	for _, t := range a.targets {
		th, _ := targetHostPort(t)
		if th == "" {
			continue
		}
		if sameSiteHost(th, host) {
			return false
		}
		tf := registrableDomain(th)
		if tf == "" {
			continue
		}
		known = true
		if tf == fam {
			return false
		}
		// A domain that embeds the target's brand label ("sso-target.com",
		// "xtarget.com" for target.com) is either the same organization or a
		// crafted allowlist-bypass payload for open-redirect/CORS testing —
		// never an unrelated third party.
		if label := strings.SplitN(tf, ".", 2)[0]; len(label) >= 4 && strings.Contains(fam, label) {
			return false
		}
		// The target's whole domain with an attacker suffix ("target.com.evil.net",
		// "target.comevil.net") is a suffix-confusion bypass payload.
		if strings.HasPrefix(host, tf) || strings.Contains(host, "."+tf) {
			return false
		}
	}
	// No target with a resolvable registrable domain (e.g. an IP target): do
	// not guess what "another organization" means.
	return known
}

// pinnedPortViolation inspects one argument value for references to a
// pinned host outside its ports.
func pinnedPortViolation(pins map[string]map[string]bool, value string) (bool, string) {
	refuse := func(host string) (bool, string) {
		ports := pinnedPortList(pins[host])
		return true, fmt.Sprintf(
			"%s is in scope only on port %s, the port the scan target names. Other ports on this host "+
				"are separate services outside this engagement: do not request, scan, or report them. "+
				"Continue on %s:%s.", host, ports, host, ports)
	}
	for _, m := range scopeURLPattern.FindAllString(value, -1) {
		if h, p := referenceHostPort(m); outsidePinnedPort(pins, h, p) {
			return refuse(h)
		}
	}
	lower := strings.ToLower(value)
	hosts := make([]string, 0, len(pins))
	for h := range pins {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		re := regexp.MustCompile(`(?:^|[^a-z0-9.-])` + regexp.QuoteMeta(h) + `:([0-9]{1,5})\b`)
		for _, m := range re.FindAllStringSubmatch(lower, -1) {
			if !pins[h][m[1]] {
				return refuse(h)
			}
		}
		if portScannerPattern.MatchString(lower) && mentionsHost(lower, h) && !scanStaysOnPorts(lower, pins[h]) {
			return refuse(h)
		}
	}
	return false, ""
}

func mentionsHost(text, host string) bool {
	return regexp.MustCompile(`(?:^|[^a-z0-9.-])` + regexp.QuoteMeta(host) + `(?:[^a-z0-9.-]|$)`).MatchString(text)
}

// scanStaysOnPorts reports whether a port-scan command lists its ports
// explicitly and every one of them is pinned.
func scanStaysOnPorts(cmd string, ports map[string]bool) bool {
	if scannerWideOption.MatchString(cmd) {
		return false
	}
	specs := scannerPortsPattern.FindAllStringSubmatch(cmd, -1)
	if len(specs) == 0 {
		return false
	}
	for _, spec := range specs {
		for _, item := range strings.Split(spec[1], ",") {
			if item == "" {
				continue
			}
			lo, hi, ok := strings.Cut(item, "-")
			if !ok {
				hi = lo
			}
			from, err1 := strconv.Atoi(lo)
			to, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || from != to || !ports[strconv.Itoa(from)] {
				return false
			}
		}
	}
	return true
}

// targetBoundaryPromptSection states the operator's target boundaries for the
// system prompt; "" when the scan has none.
func (a *Agent) targetBoundaryPromptSection(targets []string) string {
	pins := pinnedTargetPorts(targets)
	if len(pins) == 0 && !a.singleHostScope {
		return ""
	}
	var b strings.Builder
	b.WriteString("## SCAN BOUNDARY — CONFIGURED BY THE OPERATOR\n\n")
	hosts := make([]string, 0, len(pins))
	for h := range pins {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		ports := pinnedPortList(pins[h])
		fmt.Fprintf(&b, "- %s is in scope ONLY on port %s, the port the target URL names. Other ports on this host are separate services outside this engagement: do not request, scan, or report them. Service/port enumeration of this host must name only port %s (for example `-p %s`).\n", h, ports, ports, ports)
	}
	if a.singleHostScope {
		b.WriteString("- This is a single-host scan. Do not enumerate subdomains (no subdomain discovery tools or certificate-transparency lookups); subdomains belong to wildcard scans. This narrows the generic scope rules above, which mention subdomains.\n")
		b.WriteString("- Hosts on other organizations' domains that you find in the target's responses, redirects, or JavaScript (third-party APIs, CDNs, partner backends) are outside this scan: record them as notes if useful, but do not fetch, probe, or report them. The target's own subdomains that the application itself calls (such as its API or login host) may be tested. Hosts named only as payloads (SSRF, open-redirect, OOB callbacks) are fine; they test the target.\n")
	}
	b.WriteString("These boundaries are enforced: tool calls that cross them are refused.")
	return b.String()
}
