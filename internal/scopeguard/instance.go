package scopeguard

import (
	"net"
	"strings"
)

// Addresses that only reach the scanning machine's own environment.
//
// A link-local address (169.254.0.0/16, fe80::/10) is never routed off the
// link the connecting machine sits on, and a cloud instance-service address
// answers only the instance that asks. So a connection the scanner itself
// makes to one reaches the scanner's own cloud metadata service (instance
// credentials, user data) or a neighbor on its own link, never the scanned
// target's network. Testing a target for SSRF to its metadata service means
// sending the address to the target as a payload, which IsLocalOrListener
// deliberately allows; the checks below are for the address a connection is
// actually made to.

// instanceServiceIPs are well-known cloud instance-service addresses. Those
// inside link-local ranges are listed too: IsInstanceService refuses them
// even where another link-local address would be allowed.
var instanceServiceIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // metadata service on most clouds
	net.ParseIP("169.254.170.2"),   // container task metadata and credentials
	net.ParseIP("169.254.170.23"),  // pod identity credentials
	net.ParseIP("169.254.0.23"),    // metadata service on some clouds
	net.ParseIP("fe80::a9fe:a9fe"), // 169.254.169.254's IPv6 link-local form
	net.ParseIP("fd00:ec2::254"),   // instance metadata over IPv6 (ULA)
	net.ParseIP("fd00:ec2::23"),    // instance credentials over IPv6 (ULA)
	net.ParseIP("fd20:ce::254"),    // instance metadata over IPv6 (ULA)
	net.ParseIP("100.100.100.200"), // metadata service outside link-local
	net.ParseIP("168.63.129.16"),   // platform endpoint outside link-local
	net.ParseIP("192.0.0.192"),     // metadata service outside link-local
}

// instanceServiceNames are well-known names of cloud metadata services, for
// callers that see a name rather than the address it resolves to (a
// connection handed to a remote proxy, which resolves it itself).
var instanceServiceNames = map[string]bool{
	"metadata":                   true,
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"metadata.tencentyun.com":    true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

// IsInstanceService reports whether address (a host, host:port or
// [ipv6]:port) is a well-known cloud instance-service address or name.
func IsInstanceService(address string) bool {
	host := addressHost(address)
	if instanceServiceNames[host] {
		return true
	}
	ip := addressIP(host)
	if ip == nil {
		return false
	}
	for _, m := range instanceServiceIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// IsLinkLocal reports whether address (a host, host:port or [ipv6]:port) is
// a link-local unicast address, IPv4-mapped forms included. Names are not
// resolved.
func IsLinkLocal(address string) bool {
	ip := addressIP(addressHost(address))
	return ip != nil && ip.IsLinkLocalUnicast()
}

// SameAddress reports whether a and b (each a host, host:port or
// [ipv6]:port) are the same IP address, however each is spelled. Names never
// match.
func SameAddress(a, b string) bool {
	ipA, ipB := addressIP(addressHost(a)), addressIP(addressHost(b))
	return ipA != nil && ipB != nil && ipA.Equal(ipB)
}

// addressHost returns the host of a host, host:port or [ipv6]:port string,
// lowercased, without brackets, IPv6 zone or trailing dot.
func addressHost(address string) string {
	h := strings.TrimSpace(address)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = stripIPv6Zone(h)
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// addressIP parses host as an IP address, accepting the numeric IPv4
// spellings browsers and inet_aton accept ("2852039166", "0xa9.254.169.254").
func addressIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if LooksNumericIPv4(host) {
		if ip, ok := ParseIPv4Loose(host); ok {
			return ip
		}
	}
	return nil
}
