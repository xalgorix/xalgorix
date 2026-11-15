package tools

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGuardRedirectsRefusesAHopWithoutFollowingIt(t *testing.T) {
	var hits atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer final.Close()
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/secret", http.StatusFound)
	}))
	defer start.Close()

	client := &http.Client{}
	refused := GuardRedirects(client, func(raw string) error {
		if strings.HasPrefix(raw, final.URL) {
			return errors.New("not allowed")
		}
		return nil
	})
	resp, err := client.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 itself", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatal("refused hop was requested")
	}
	if note := refused(); !strings.Contains(note, final.URL+"/secret") || !strings.Contains(note, "not allowed") {
		t.Fatalf("note = %q", note)
	}

	// Allowed hops are followed as before.
	client = &http.Client{}
	refused = GuardRedirects(client, func(string) error { return nil })
	resp, err = client.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 || refused() != "" {
		t.Fatalf("allowed hop: status %d hits %d note %q", resp.StatusCode, hits.Load(), refused())
	}
}

func TestGuardRedirectsKeepsTheRedirectLimit(t *testing.T) {
	var loop *httptest.Server
	loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loop.URL+"/again", http.StatusFound)
	}))
	defer loop.Close()
	client := &http.Client{}
	GuardRedirects(client, func(string) error { return nil })
	if _, err := client.Get(loop.URL); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("err = %v, want the 10-redirect limit", err)
	}
}

func TestGuardRedirectsNilGuardLeavesClientAlone(t *testing.T) {
	client := &http.Client{}
	if refused := GuardRedirects(client, nil); refused() != "" || client.CheckRedirect != nil {
		t.Fatal("nil guard changed the client")
	}
}

func TestRegistryRequestGuard(t *testing.T) {
	r := NewRegistry()
	if r.RequestGuard() != nil {
		t.Fatal("new registry has a guard")
	}
	r.SetRequestGuard(func(string) error { return errors.New("no") })
	if g := r.RequestGuard(); g == nil || g("http://x") == nil {
		t.Fatal("guard not installed")
	}
}

// The dial guard sees the address a hostname resolved to, not the name, and
// a refusal stops the request before anything is sent.
func TestGuardDialsChecksTheResolvedAddress(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	var seen []string
	tr := &http.Transport{}
	if err := GuardDials(tr, func(address string) error {
		seen = append(seen, address)
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || ip.IsLoopback() {
			return errors.New("loopback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: tr}).Get("http://localhost:" + port + "/")
	if err == nil || !strings.Contains(err.Error(), "not allowed: loopback") {
		t.Fatalf("err = %v, want the guard's refusal", err)
	}
	if hits.Load() != 0 {
		t.Fatal("refused connection reached the server")
	}
	if len(seen) == 0 {
		t.Fatal("guard was not consulted")
	}
	for _, a := range seen {
		if strings.HasPrefix(a, "localhost") {
			t.Fatalf("guard saw the name %q, want the resolved address", a)
		}
	}

	// An allowing guard leaves the request alone.
	tr = &http.Transport{}
	if err := GuardDials(tr, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

// A connection to the proxy the transport chose is not checked: the proxy,
// not this host, resolves and connects to the destination.
func TestGuardDialsLeavesTheProxyConnectionAlone(t *testing.T) {
	var proxied atomic.Int32
	prx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "destination.invalid" {
			proxied.Add(1)
		}
	}))
	defer prx.Close()
	proxyURL, err := url.Parse(prx.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	if err := GuardDials(tr, func(string) error { return errors.New("refuse everything") }); err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Get("http://destination.invalid/")
	if err != nil {
		t.Fatalf("request through the proxy refused: %v", err)
	}
	resp.Body.Close()
	if proxied.Load() != 1 {
		t.Fatal("request did not go through the proxy")
	}
}

func TestGuardDialsNilGuardLeavesTransportAlone(t *testing.T) {
	tr := &http.Transport{}
	if err := GuardDials(tr, nil); err != nil {
		t.Fatal(err)
	}
	if tr.DialContext != nil || tr.Proxy != nil {
		t.Fatal("nil guard changed the transport")
	}
}

func TestRegistryDialGuard(t *testing.T) {
	r := NewRegistry()
	if r.DialGuard() != nil {
		t.Fatal("new registry has a dial guard")
	}
	r.SetDialGuard(func(string) error { return errors.New("no") })
	if g := r.DialGuard(); g == nil || g("127.0.0.1:80") == nil {
		t.Fatal("dial guard not installed")
	}
}

func TestProxyDialAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"http://127.0.0.1:8080":   "127.0.0.1:8080",
		"http://proxy.example":    "proxy.example:80",
		"https://proxy.example":   "proxy.example:443",
		"socks5://[::1]":          "[::1]:1080",
		"socks5h://user:pw@p.e:9": "p.e:9",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := proxyDialAddr(u); got != want {
			t.Errorf("proxyDialAddr(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Recording a proxy does not exempt the direct connections the same
// transport makes for requests the proxy does not carry.
func TestGuardDialsStillChecksDirectRequestsOnAProxiedTransport(t *testing.T) {
	var direct atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
	}))
	defer srv.Close()
	prx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer prx.Close()
	proxyURL, err := url.Parse(prx.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	tr := &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
		if req.URL.Hostname() == "destination.invalid" {
			return proxyURL, nil
		}
		return nil, nil // like NO_PROXY
	}}
	if err := GuardDials(tr, func(string) error { return errors.New("refused") }); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://destination.invalid/")
	if err != nil {
		t.Fatalf("proxied request refused: %v", err)
	}
	resp.Body.Close()
	if _, err := client.Get("http://localhost:" + port + "/"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("direct request after a proxied one: err = %v, want the guard's refusal", err)
	}
	if direct.Load() != 0 {
		t.Fatal("direct request reached the server")
	}
}

// A transport with its own TLS dialer would send HTTPS around the check, so
// it is refused rather than half guarded.
func TestGuardDialsRefusesACustomTLSDialer(t *testing.T) {
	tr := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }}
	if err := GuardDials(tr, func(string) error { return nil }); err == nil {
		t.Fatal("transport with a custom TLS dialer was accepted")
	}
	if err := GuardDials(tr, nil); err != nil {
		t.Fatalf("nil guard: %v", err)
	}
}

func TestSetDialResolverRestores(t *testing.T) {
	r := &net.Resolver{PreferGo: true}
	prev := SetDialResolver(r)
	if got := SetDialResolver(prev); got != r {
		t.Fatal("SetDialResolver did not return the installed resolver")
	}
}
