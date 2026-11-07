package agent

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

// shouldBlockForTargetScope refuses tool calls that leave the operator's
// target boundaries: another port of a port-pinned host, a port scan of
// such a host beyond its pinned ports, or subdomain discovery in a
// single-host scan.
func (a *Agent) shouldBlockForTargetScope(toolName string, toolArgs map[string]string) (bool, string) {
	if targetScopeExemptTools[strings.ToLower(toolName)] {
		return false, ""
	}
	pins := pinnedTargetPorts(a.targets)
	if len(pins) == 0 && !a.singleHostScope {
		return false, ""
	}
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
	}
	return false, ""
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
	}
	b.WriteString("These boundaries are enforced: tool calls that cross them are refused.")
	return b.String()
}
