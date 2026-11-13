// Package scopeguard owns the authoritative definition of
// "Local_Or_Listener_Host" — the host classification both the web-side
// fetcher (internal/web/server.go) and the agent-side gate
// (internal/agent/agent.go) consult.
//
// The package is intentionally a leaf: it imports nothing from the
// xalgorix tree so the agent can take a dependency on it without
// pulling in the web package. Its single semantic entry point is
// IsLocalOrListener, which classifies a target string (bare host,
// host:port, scheme://host[:port][/path], or [ipv6][:port]) against
// the operator's listener identity (Config) and the machine's actual
// network interfaces.
//
// DESIGN PRINCIPLE: only block IPs that provably belong to the
// operator's own machine. Do NOT blanket-block entire private ranges
// (RFC1918, link-local) — the agent is a security scanner that needs
// to test SSRF payloads like 169.254.169.254 (cloud metadata) and
// internal IPs that belong to the TARGET, not the operator.
//
// What we block:
//   - Loopback addresses (127.0.0.0/8, ::1) — always self
//   - Unspecified addresses (0.0.0.0, ::) — always self
//   - "localhost" hostname — always self
//   - IPs matching any local network interface — the operator's machine
//   - Self-listener textual match (bind addr + port)
//
// What we ALLOW (that the old code incorrectly blocked):
//   - RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) — unless
//     they match a local interface
//   - Link-local (169.254.0.0/16) including 169.254.169.254 cloud
//     metadata — unless they match a local interface
//   - IPv6 ULA (fc00::/7) and link-local (fe80::/10) — unless they
//     match a local interface
package scopeguard

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/net/idna"
)

// Config carries the operator's listener identity. Callers set
// BindAddr to the configured XALGORIX_BIND value and Port to the
// listener port. An empty BindAddr is treated as "127.0.0.1" — the
// same default the web server applies when no bind override is
// provided.
type Config struct {
	BindAddr string
	Port     int

	// AllowLoopbackPorts is a per-scan allowlist of loopback ports the
	// caller has deliberately stood a target up on — used by "provision"
	// code scans (Option 2), where the agent builds the target's source
	// and runs it on 127.0.0.1:<port>, then pentests it. Only loopback
	// hosts on exactly these ports are exempted from the "self" verdict;
	// the dashboard's own listener port is NEVER exempted (even if it
	// somehow appears here), and the operator's real interface addresses
	// remain blocked. Empty (the default) preserves the strict behavior:
	// all loopback is treated as self.
	AllowLoopbackPorts []int

	// AllowLocalTargets is a GLOBAL opt-in for self-hosted installs that want
	// to scan a locally-hosted app (loopback, localhost, or one of the
	// machine's own interface IPs) — e.g. a demo/staging environment on the
	// same box. Default false. It NEVER exposes the dashboard's own listener:
	// the self-listener fast-path still blocks the exact bind host:port, and
	// any local target on the dashboard's Port is refused regardless, so this
	// can't be turned into a self-scan loop. The unspecified address
	// (0.0.0.0 / ::) is always blocked. Must remain off on multi-tenant /
	// hosted deployments (it would let a user reach the operator's machine).
	AllowLocalTargets bool
}

// localTargetsAllowed reports whether the global self-hosted local-scan opt-in
// applies to a target on the given port. Gated so the dashboard's own listener
// port is never in scope, even via a different local address.
func (c Config) localTargetsAllowed(hostPort string) bool {
	if !c.AllowLocalTargets {
		return false
	}
	if hostPort == "" {
		return true
	}
	pn, err := strconv.Atoi(hostPort)
	// Never scan the dashboard's own port, on any local address; a port that
	// is not a number cannot be told apart from it.
	return err == nil && pn != c.Port
}

// loopbackPortAllowed reports whether hostPort (a decimal port string) is in
// the per-scan loopback allowlist. The dashboard listener port is never
// allowed, so a provisioned target can never be pointed at the dashboard.
func (c Config) loopbackPortAllowed(hostPort string) bool {
	if hostPort == "" || len(c.AllowLoopbackPorts) == 0 {
		return false
	}
	pn, err := strconv.Atoi(hostPort)
	if err != nil || pn == c.Port {
		return false
	}
	for _, ap := range c.AllowLoopbackPorts {
		if ap == pn {
			return true
		}
	}
	return false
}

// schemeDefaultPort returns the well-known default port for a URL scheme, so a
// scheme://host URL with no explicit port is still compared against the
// dashboard's listener port. Returns "" for schemes with no port convention we
// should assume.
func schemeDefaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	default:
		return ""
	}
}

// lookupHostSig is the resolver indirection signature: it mirrors
// net.LookupHost so production and test stubs are interchangeable.
type lookupHostSig = func(host string) ([]string, error)

// activeLookupHost holds the resolver behind an atomic pointer. The read
// side (lookupHost, called from IsLocalOrListener) and the write side
// (SetLookupHost, used by tests) both go through atomic load/swap, so an
// in-flight scan goroutine classifying a target never data-races a test
// swapping the resolver. Production installs net.LookupHost once at init
// and never changes it.
var activeLookupHost atomic.Pointer[lookupHostSig]

func init() {
	def := net.LookupHost
	activeLookupHost.Store(&def)
}

// lookupHost resolves host using the currently installed resolver. Single
// call site (inside IsLocalOrListener).
func lookupHost(host string) ([]string, error) {
	return (*activeLookupHost.Load())(host)
}

// SetLookupHost atomically installs fn as the resolver used by
// IsLocalOrListener and returns the resolver it replaced, so callers can
// restore it (the swap/restore pattern tests rely on). A nil fn resets to
// net.LookupHost. The atomic swap pairs with the atomic load in lookupHost,
// so installing a stub never races a concurrent classification.
func SetLookupHost(fn func(host string) ([]string, error)) func(host string) ([]string, error) {
	if fn == nil {
		fn = net.LookupHost
	}
	prev := activeLookupHost.Swap(&fn)
	if prev == nil {
		return net.LookupHost
	}
	return *prev
}

// LookupHost resolves host with the same resolver IsLocalOrListener uses, so
// callers that need the addresses themselves see the same answers (and the
// same test stubs installed via SetLookupHost).
func LookupHost(host string) ([]string, error) {
	return lookupHost(host)
}

// IsLocalOrListener returns true when target — a bare host,
// host:port, scheme://host[:port][/path], or [ipv6][:port] —
// classifies as pointing at the operator's own machine.
//
// The check is smart: it only blocks loopback, unspecified, and IPs
// that match one of this machine's network interfaces. It does NOT
// blanket-block RFC1918 or link-local ranges — those are legitimate
// SSRF targets (e.g. 169.254.169.254 cloud metadata, internal IPs
// on the target's network).
func IsLocalOrListener(cfg Config, target string) bool {
	// A client may read a host out of target in more than one way (a
	// browser and curl disagree about a backslash, for example). Classify
	// every reading and refuse the target if any of them is this machine.
	resolved := map[string]resolution{}
	seen := map[string]bool{}
	for _, r := range targetReadings(target) {
		host := r.decodedHost()
		// Classify the host the way the tools that connect to it read it,
		// not only the way net.ParseIP and Go's resolver do: curl, Python,
		// glibc and browsers accept numeric IPv4 forms ("2130706433",
		// "0x7f.1", "0177.0.0.1", "127.1", "0"), a trailing dot and
		// full-width digits, and resolve "*.localhost" to loopback. Hosts
		// that look numeric but that no IPv4 parser agrees on are refused
		// rather than sent to DNS.
		hosts, ok := canonicalHosts(stripIPv6Zone(host))
		if !ok {
			return true
		}
		for _, h := range hosts {
			key := h + " " + r.port
			if h == "" || seen[key] {
				continue
			}
			seen[key] = true
			if classifyHost(cfg, h, r.port, resolved) {
				return true
			}
		}
	}
	return false
}

// resolution is a memoized lookupHost answer, so a host read in several ways
// is still resolved once per IsLocalOrListener call.
type resolution struct {
	addrs []string
	err   error
}

// classifyHost applies the Local_Or_Listener rules to one canonical host
// (see canonicalHost) and its port ("" when unknown).
func classifyHost(cfg Config, host, hostPort string, resolved map[string]resolution) bool {
	// Self-listener textual fast-path. Block if the target's port
	// matches our own listening port AND the host textually matches
	// our bind address (or 0.0.0.0 / ::). This fires before DNS
	// resolution and catches the most common self-probe patterns.
	if hostPort != "" {
		if portNum, err := strconv.Atoi(hostPort); err == nil && portNum == cfg.Port {
			bind := strings.ToLower(strings.TrimSpace(cfg.BindAddr))
			if bind == "" {
				bind = "127.0.0.1"
			}
			if host == bind || host == "0.0.0.0" || host == "::" {
				return true
			}
		}
	}

	// Per-scan provisioned-target exception: a "provision" code scan stood
	// the target app up on a specific loopback port and explicitly opted it
	// in. Loopback hosts on exactly that port are NOT self. The dashboard
	// listener port is never in the allowlist (see loopbackPortAllowed), so
	// this can never expose the operator's own dashboard.
	// The per-scan provisioned-port allowlist OR the global self-hosted
	// local-scan opt-in can exempt loopback. Both are gated so the dashboard's
	// own port is never in scope; the self-listener fast-path above already
	// blocked the exact bind host:port.
	allowLoopback := cfg.loopbackPortAllowed(hostPort) || cfg.localTargetsAllowed(hostPort)

	// Explicit textual matches (fast path) — these always mean "self".
	// "*.localhost" names are loopback too (RFC 6761): curl and browsers
	// answer them without asking DNS.
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "0.0.0.0" || host == "::1" {
		if allowLoopback && host != "0.0.0.0" {
			return false
		}
		return true
	}

	// Resolve the target host to one or more IPs exactly once for the
	// remainder of this call. IP literals skip DNS entirely; otherwise
	// a single LookupHost feeds every downstream check. An empty or
	// failing resolution falls back to "allow" (matching prior
	// behavior) so unreachable hostnames are not blocked solely on
	// lookup failure — the request will fail naturally further down.
	var resolvedIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		resolvedIPs = []net.IP{ip}
	} else {
		res, done := resolved[host]
		if !done {
			res.addrs, res.err = lookupHost(host)
			resolved[host] = res
		}
		if res.err != nil || len(res.addrs) == 0 {
			return false // can't resolve — let it through, will fail naturally
		}
		for _, a := range res.addrs {
			if parsed := net.ParseIP(stripIPv6Zone(a)); parsed != nil {
				resolvedIPs = append(resolvedIPs, parsed)
			}
		}
		if len(resolvedIPs) == 0 {
			// The resolver answered, but with nothing we can classify:
			// refuse rather than guess.
			return true
		}
	}

	// Check each resolved IP against the operator's own machine.
	// We block ONLY:
	//   1. Loopback (127.x.x.x, ::1) — always the local machine
	//   2. Unspecified (0.0.0.0, ::) — binds to all local interfaces
	//   3. IPs matching a local network interface — the operator's machine
	//
	// Everything else is allowed, including RFC1918, link-local,
	// cloud metadata (169.254.169.254), IPv6 ULA, etc. — these may
	// be legitimate targets on the scanned host's network.
	for _, ip := range resolvedIPs {
		if ip.IsLoopback() {
			if allowLoopback {
				return false // provisioned target on an opted-in loopback port
			}
			return true
		}
		if ip.IsUnspecified() {
			return true
		}
	}

	// Self-host interface check. Block ANY target whose resolved IP
	// matches one of this machine's network interface addresses —
	// regardless of port. This prevents the agent from probing the
	// operator's own public-facing services (SSH, Grafana, CUPS, etc.)
	// even when the probed port differs from the dashboard listener.
	if ipsMatchLocalInterface(resolvedIPs) {
		// Self-hosted opt-in: the operator explicitly allows scanning apps on
		// this machine's own interfaces (except the dashboard's port, which
		// localTargetsAllowed excludes).
		if cfg.localTargetsAllowed(hostPort) {
			return false
		}
		return true
	}

	return false
}

// hostReading is one way a client may read the host and port of a target.
type hostReading struct {
	host   string // as written: may keep brackets, an IPv6 zone or escapes
	port   string // "" when unknown
	decode bool   // percent-escapes in host are not decoded yet
}

// decodedHost returns r.host with percent-escapes decoded when the reading
// still needs it.
func (r hostReading) decodedHost() string {
	if r.decode && strings.Contains(r.host, "%") {
		if dec, err := url.PathUnescape(r.host); err == nil {
			return dec
		}
	}
	return r.host
}

// ReadingHosts returns the canonical hosts IsLocalOrListener classifies for
// target, one per way a client may read it, without classifying them. Hosts
// that cannot be read are left out.
func ReadingHosts(target string) []string {
	var out []string
	for _, r := range targetReadings(target) {
		if hosts, ok := canonicalHosts(stripIPv6Zone(r.decodedHost())); ok {
			out = append(out, hosts...)
		}
	}
	return out
}

// targetReadings returns the host/port readings of target — a bare host,
// host:port, [ipv6]:port, either optionally followed by a path, or a URL.
// For URLs it returns what net/url reads and, for the network schemes curl
// and browsers support, what those clients read: they drop tabs, newlines
// and surrounding control characters, accept any run of slashes or
// backslashes after "http:", and stop the authority at a backslash
// (browsers) or only at "/?#" (curl, Python's urllib).
func targetReadings(target string) []hostReading {
	t := strings.TrimFunc(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, target), func(r rune) bool { return r <= ' ' })
	var out []hostReading
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		port := u.Port()
		// url.Port() is "" when the URL omits an explicit port. Fall back to
		// the scheme's default (http->80, https->443) so the dashboard-port
		// checks — which compare the port against cfg.Port — are not
		// silently bypassed for URLs like "https://127.0.0.1/".
		if port == "" {
			port = schemeDefaultPort(u.Scheme)
		}
		out = append(out, hostReading{host: u.Hostname(), port: port})
	}
	if scheme, rest, ok := splitScheme(t); ok {
		switch {
		case IsNetworkURLScheme(scheme):
			rest = strings.TrimLeft(rest, `/\`)
			for _, stops := range []string{`/?#\`, "/?#"} {
				out = append(out, authorityReading(rest, stops, schemeDefaultPort(scheme)))
			}
			return out
		case strings.HasPrefix(rest, "//"):
			if len(out) == 0 {
				// A URL net/url refused ("code://My Project").
				out = append(out, authorityReading(rest[2:], "/?#", ""))
			}
			return out
		}
	}
	if len(out) > 0 {
		return out
	}
	// No scheme: ignore any path, query or fragment after the host, and any
	// userinfo before it ("user@127.0.0.1:9137/", as curl reads it).
	if j := strings.IndexAny(t, "/?#"); j >= 0 {
		t = t[:j]
	}
	if j := strings.LastIndexByte(t, '@'); j >= 0 {
		t = t[j+1:]
	}
	host, port := splitHostPortLoose(t)
	return []hostReading{{host: host, port: port}}
}

// splitScheme splits "scheme:rest" when target starts with a valid URL
// scheme (RFC 3986: a letter, then letters, digits, "+", "-" or ".").
func splitScheme(target string) (scheme, rest string, ok bool) {
	i := strings.IndexByte(target, ':')
	if i <= 0 {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		c := target[j]
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		other := (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
		if !letter && (j == 0 || !other) {
			return "", "", false
		}
	}
	return target[:i], target[i+1:], true
}

// IsNetworkURLScheme reports whether scheme is one curl or a browser opens
// over the network. Those clients accept one to three (back)slashes after
// "scheme:", so "gopher:/127.0.0.1:9137/" names a host.
func IsNetworkURLScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss", "ftp", "ftps", "gopher", "gophers",
		"dict", "imap", "imaps", "ldap", "ldaps", "mqtt", "mqtts", "pop3", "pop3s",
		"rtsp", "scp", "sftp", "smb", "smbs", "smtp", "smtps", "telnet", "tftp":
		return true
	}
	return false
}

// authorityReading reads host and port from the authority at the start of
// rest, which ends at the first byte in stops; userinfo is dropped.
func authorityReading(rest, stops, defaultPort string) hostReading {
	if j := strings.IndexAny(rest, stops); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		rest = rest[j+1:]
	}
	host, port := splitHostPortLoose(rest)
	if port == "" {
		port = defaultPort
	}
	return hostReading{host: host, port: port, decode: true}
}

// splitHostPortLoose splits host:port or [ipv6]:port and returns s unchanged
// (with an empty port) when it is not in either form.
func splitHostPortLoose(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, ""
}

// hostMappers apply the UTS #46 mappings clients use for lookups (full-width
// digits and ideographic full stops become ASCII) without the STD3 rules, so
// names with "_" or spaces are still mapped rather than rejected. Clients
// differ on transitional processing (which drops zero-width joiners), so
// both are applied.
var hostMappers = []*idna.Profile{
	idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false)),
	idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(true)),
}

// canonicalHosts returns host in the forms the operator's tools connect to:
// lower case, IDNA-mapped (one form per mapping for a non-ASCII host),
// without a trailing dot, and with any IPv4 form that inet_aton or a browser
// accepts rewritten as a dotted quad. ok is false when the host looks
// numeric but no IPv4 parser agrees on its value.
func canonicalHosts(host string) ([]string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if isASCII(h) {
		c, ok := canonicalHost(h)
		return []string{c}, ok
	}
	var out []string
	for _, m := range hostMappers {
		// A name a mapper rejects outright is one no client can resolve
		// that way; keep it as written.
		v := h
		if mapped, err := m.ToASCII(h); err == nil || mapped != "" {
			v = strings.ToLower(mapped)
		}
		c, ok := canonicalHost(v)
		if !ok {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

// canonicalHost removes one trailing dot from a lower-case ASCII host and
// rewrites any IPv4 form as a dotted quad (see canonicalHosts).
func canonicalHost(h string) (string, bool) {
	if strings.HasSuffix(h, ".") && !strings.HasSuffix(h, "..") {
		h = strings.TrimSuffix(h, ".")
	}
	if !LooksNumericIPv4(h) {
		return h, true
	}
	ip, ok := ParseIPv4Loose(h)
	if !ok {
		return "", false
	}
	return ip.String(), true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// LooksNumericIPv4 reports whether every dot-separated label of s is a
// decimal or 0x-hexadecimal number ("2130706433", "0x7f.1", "999.1.1.1").
// No real host name has an all-numeric top-level label, so such a host is
// meant as an address.
func LooksNumericIPv4(s string) bool {
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		digits := label
		hex := false
		if len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
			digits = label[2:]
			hex = true
		}
		for i := 0; i < len(digits); i++ {
			c := digits[i]
			isDigit := c >= '0' && c <= '9'
			isHex := hex && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
			if !isDigit && !isHex {
				return false
			}
		}
	}
	return true
}

// ParseIPv4Loose parses s the way inet_aton and the WHATWG URL parser do:
// one to four dot-separated parts, each decimal, octal (leading 0) or
// hexadecimal (0x), where the last part fills the remaining bytes
// ("127.1" is 127.0.0.1, "2130706433" is 127.0.0.1). It does not accept a
// trailing dot or surrounding text.
func ParseIPv4Loose(s string) (net.IP, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return nil, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseIPv4Part(p)
		if !ok {
			return nil, false
		}
		vals[i] = v
	}
	n := len(vals)
	for _, v := range vals[:n-1] {
		if v > 0xff {
			return nil, false
		}
	}
	if vals[n-1] >= uint64(1)<<(8*uint(5-n)) {
		return nil, false
	}
	addr := vals[n-1]
	for i, v := range vals[:n-1] {
		addr |= v << (8 * uint(3-i))
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)), true //nolint:gosec // G115: addr < 2^32 (checked above); each conversion keeps one octet
}

func parseIPv4Part(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(p) >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base = 16
		p = p[2:]
		if p == "" {
			return 0, true // "0x" is 0 to inet_aton and browsers
		}
	case len(p) > 1 && p[0] == '0':
		base = 8
		p = p[1:]
	}
	// An explicit base makes ParseUint reject signs, underscores and prefixes.
	v, err := strconv.ParseUint(p, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// stripIPv6Zone returns an IPv6 literal without brackets or its zone
// ("[::1%eth0]" → "::1"). net/http dials the address and the zone only picks
// an interface, but net.ParseIP rejects zoned literals, which would otherwise
// send "::1%x" to DNS and classify it as unresolvable (allowed). Other hosts
// are returned unchanged.
func stripIPv6Zone(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if i := strings.IndexByte(host, '%'); i >= 0 && strings.Contains(host[:i], ":") {
		host = host[:i]
	}
	return host
}

// ipsMatchLocalInterface returns true if any IP in the supplied
// slice matches one of this machine's interface addresses. Issues a
// single net.InterfaceAddrs call and walks ips × addrs so callers
// can resolve a hostname once and reuse the result for every
// downstream check.
func ipsMatchLocalInterface(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		for _, a := range addrs {
			var aIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aIP = v.IP
			case *net.IPAddr:
				aIP = v.IP
			}
			if aIP == nil {
				continue
			}
			if aIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
