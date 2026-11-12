package scopeguard

import "testing"

// A zone on an IPv6 literal does not change the address net/http dials, so
// zoned loopback (and IPv4-mapped loopback) must classify as local. Before,
// net.ParseIP rejected the zone, the literal went to DNS, the lookup failed,
// and the guard allowed it.
func TestIsLocalOrListenerIPv6ZoneLiterals(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}
	for _, target := range []string{
		"http://[::1%25x]:8080/",
		"http://[::1%25eth0]/admin",
		"http://[::ffff:127.0.0.1%25x]:9137/api/version",
		"[::1%lo]:80",
		"[::1%x]",
		"::1%x",
	} {
		if !IsLocalOrListener(cfg, target) {
			t.Errorf("%q: want local", target)
		}
	}
	if IsLocalOrListener(cfg, "http://[2606:4700::1%25x]/") {
		t.Errorf("zoned public IPv6 classified as local")
	}
}

// A resolver answer that contains no parseable address is refused instead
// of being treated like a failed lookup.
func TestIsLocalOrListenerUnparseableResolutionFailsClosed(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return []string{"not-an-ip"}, nil
	})
	if !IsLocalOrListener(Config{Port: 9137}, "http://odd.example/") {
		t.Fatal("unparseable resolver answer allowed")
	}
}

func TestStripIPv6Zone(t *testing.T) {
	cases := map[string]string{
		"[::1%eth0]":  "::1",
		"::1%x":       "::1",
		"[::1]":       "::1",
		"127.0.0.1":   "127.0.0.1",
		"example.com": "example.com",
		"a%b":         "a%b", // not an IPv6 literal
	}
	for in, want := range cases {
		if got := stripIPv6Zone(in); got != want {
			t.Errorf("stripIPv6Zone(%q) = %q, want %q", in, got, want)
		}
	}
}

type testDNSError struct{ host string }

func (e *testDNSError) Error() string { return "no such host " + e.host }

func stubLookup(t *testing.T, fn func(string) ([]string, error)) {
	t.Helper()
	prev := SetLookupHost(fn)
	t.Cleanup(func() { SetLookupHost(prev) })
}
