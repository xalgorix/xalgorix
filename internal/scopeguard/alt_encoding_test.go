package scopeguard

import "testing"

// curl, Python, glibc and browsers read numeric IPv4 forms, a trailing dot,
// full-width digits and percent-encoded hosts as addresses, and answer
// "*.localhost" with loopback. net.ParseIP and Go's resolver do neither, so
// before, these hosts went to DNS, the lookup failed and the guard allowed
// them while the tools connected to this machine.
func TestIsLocalOrListenerAlternateHostForms(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}
	for _, target := range []string{
		"http://2130706433:9137/",
		"2130706433:9137",
		"http://0x7f.0.0.1:9137/",
		"http://0X7F.0.0.1:9137/",
		"http://0177.0.0.1:9137/",
		"http://127.1:9137/",
		"http://127.0.1/",
		"http://0x7f000001:9137/",
		"0x7f000001:22",
		"http://0:9137/",
		"http://0x0:80/",
		"http://127.000.000.001/",
		"http://127.0.0.1./",
		"http://user@0x7f.1/",
		"http://foo.localhost:8080/",
		"http://a.b.localhost./",
		"http://localhost.:8080/",
		"http://１２７.０.０.１:8080/",       // full-width digits
		"http://127。0。0。1/",            // ideographic full stops
		"http://%31%32%37.0.0.1:9137/", // net/url refuses this URL
		"http://[::1%x]/",              // unescaped zone, net/url refuses it
	} {
		if !IsLocalOrListener(cfg, target) {
			t.Errorf("%q: want local", target)
		}
	}
}

// Browsers, curl and Python also accept URL spellings that net/url reads as
// having no host, or refuses: missing or extra slashes, backslashes, tabs
// and newlines inside the host, and a backslash before userinfo (curl reads
// through it to the "@"). Schemeless targets may carry a path.
func TestIsLocalOrListenerLenientURLSyntax(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}
	for _, target := range []string{
		"http:/127.0.0.1:9137/",
		"http:///127.0.0.1:9137/",
		"http:127.0.0.1:9137/",
		`http:\\127.0.0.1:9137/`,
		"HTTPS:/localhost/admin",
		"http://loc\talhost:9137/",
		"http://1\t27.0.0.1:9137/",
		"http://127.0.0.1\n:9137/",
		`http://x.com\@127.0.0.1/`,
		"127.0.0.1/",
		"localhost/admin",
		"127.0.0.1:9137/?next=http://example.com",
		"gopher:/127.0.0.1:9137/_GET",
		"gopher:///127.0.0.1:9137/_GET",
		"dict:/127.0.0.1:9137/info",
		"telnet:/127.0.0.1:9137",
		"user@127.0.0.1:9137/",
		"admin:pw@localhost/",
		"\x01http://127.0.0.1:9137/",
		"http://local" + string(rune(0x200d)) + "host:9137/", // zero-width joiner
		"http://local" + string(rune(0x200c)) + "host:9137/", // zero-width non-joiner
	} {
		if !IsLocalOrListener(cfg, target) {
			t.Errorf("%q: want local", target)
		}
	}
	for _, target := range []string{
		`http://example.com\path`,
		"http://example.com/a@127.0.0.1",
		"http://example.com?u=@127.0.0.1",
		"example.com/127.0.0.1",
	} {
		if IsLocalOrListener(cfg, target) {
			t.Errorf("%q: classified as local", target)
		}
	}
}

// Non-ASCII names that UTS #46 maps but STD3 rejects ("_", spaces) are
// ordinary names, not unreadable ones.
func TestIsLocalOrListenerNonASCIINamesWithUnderscores(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	for _, target := range []string{
		"http://bücher_shop.example/",
		"code://café_app",
		"code://Mon Projet été",
		"rapport_été.docx",
	} {
		if IsLocalOrListener(Config{Port: 9137}, target) {
			t.Errorf("%q: classified as local", target)
		}
	}
}

// Numeric hosts that no IPv4 parser agrees on are refused instead of being
// sent to DNS and allowed when the lookup fails.
func TestIsLocalOrListenerUnparseableNumericHostFailsClosed(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	for _, target := range []string{
		"http://999.1.1.1/",
		"http://4294967296/",
		"http://08.0.0.1/",
		"http://1.2.3.4.5/",
		"http://0x1.0x100.0.0/",
	} {
		if !IsLocalOrListener(Config{Port: 9137}, target) {
			t.Errorf("%q: want refused", target)
		}
	}
}

// Numeric forms of public addresses, and ordinary names, are not local.
func TestIsLocalOrListenerAlternateFormsOfPublicAddresses(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}
	for _, target := range []string{
		"http://0x08080808/",
		"http://134744072/",
		"http://8.8.8.8./",
		"http://1.2.3.4/",
		"http://example.com/",
		"http://example.com./",
		"http://bücher.example/",
		"http://localhost.example/",
	} {
		if IsLocalOrListener(cfg, target) {
			t.Errorf("%q: classified as local", target)
		}
	}
}

// The local-target opt-ins see the canonical address, so they keep working
// for any spelling, and still never expose the dashboard's port.
func TestIsLocalOrListenerAlternateFormsWithOptIns(t *testing.T) {
	stubLookup(t, func(host string) ([]string, error) {
		return nil, &testDNSError{host}
	})
	provision := Config{BindAddr: "127.0.0.1", Port: 9137, AllowLoopbackPorts: []int{3000}}
	if IsLocalOrListener(provision, "http://127.1:3000/") {
		t.Error("provisioned loopback port refused for a short-form address")
	}
	if !IsLocalOrListener(provision, "http://127.1:3001/") {
		t.Error("loopback port outside the allowlist allowed")
	}
	local := Config{BindAddr: "127.0.0.1", Port: 9137, AllowLocalTargets: true}
	if IsLocalOrListener(local, "http://2130706433:8080/") {
		t.Error("AllowLocalTargets refused a numeric loopback target")
	}
	for _, target := range []string{
		"http://2130706433:9137/", "http://0:8080/", "http://0x7f.1:9137/",
		"127.0.0.1:9137/api/settings", "http://127.0.0.1:abc/",
	} {
		if !IsLocalOrListener(local, target) {
			t.Errorf("%q: dashboard port or unspecified address allowed under AllowLocalTargets", target)
		}
	}
}

func TestParseIPv4Loose(t *testing.T) {
	valid := map[string]string{
		"127.0.0.1":       "127.0.0.1",
		"127.1":           "127.0.0.1",
		"127.0.1":         "127.0.0.1",
		"2130706433":      "127.0.0.1",
		"0x7f000001":      "127.0.0.1",
		"0x7f.0.0.1":      "127.0.0.1",
		"0X7F.1":          "127.0.0.1",
		"0177.0.0.1":      "127.0.0.1",
		"127.000.000.001": "127.0.0.1",
		"0":               "0.0.0.0",
		"0x":              "0.0.0.0",
		"1.2.3.4":         "1.2.3.4",
		"10.0.65535":      "10.0.255.255",
		"4294967295":      "255.255.255.255",
	}
	for in, want := range valid {
		ip, ok := ParseIPv4Loose(in)
		if !ok || ip.String() != want {
			t.Errorf("ParseIPv4Loose(%q) = %v, %v; want %s", in, ip, ok, want)
		}
	}
	for _, in := range []string{
		"", ".", "1..2", "127.0.0.1.", "256.1.1.1", "1.2.3.4.5", "1.2.65536",
		"4294967296", "08", "0x1g", "+1", "-1", "1_0", "1 ", "a.b.c.d", "::1",
	} {
		if ip, ok := ParseIPv4Loose(in); ok {
			t.Errorf("ParseIPv4Loose(%q) = %v, want invalid", in, ip)
		}
	}
}
