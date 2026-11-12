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
	if pn, err := strconv.Atoi(hostPort); err == nil && pn == c.Port {
		return false // never scan the dashboard's own port, on any local address
	}
	return true
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
	// Strip scheme if present (http://127.0.0.1 → 127.0.0.1)
	host := target
	hostPort := ""
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
		hostPort = u.Port()
		// url.Port() is "" when the URL omits an explicit port. Fall back to
		// the scheme's default (http->80, https->443) so the dashboard-port
		// checks below — which compare hostPort against cfg.Port — are not
		// silently bypassed for URLs like "https://127.0.0.1/".
		if hostPort == "" {
			hostPort = schemeDefaultPort(u.Scheme)
		}
	}
	// Also handle host:port without scheme
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if hostPort == "" {
			hostPort = p
		}
	}

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
			lowerHost := strings.ToLower(strings.TrimSpace(host))
			if lowerHost == bind || lowerHost == "0.0.0.0" || lowerHost == "::" {
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

	// Explicit textual matches (fast path) — these always mean "self"
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		if allowLoopback && lower != "0.0.0.0" {
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
		addrs, err := lookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false // can't resolve — let it through, will fail naturally
		}
		for _, a := range addrs {
			if parsed := net.ParseIP(a); parsed != nil {
				resolvedIPs = append(resolvedIPs, parsed)
			}
		}
		if len(resolvedIPs) == 0 {
			return false
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
