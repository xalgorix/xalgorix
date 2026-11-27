package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errOperatorMachine = errors.New("it is the operator's machine")

// refuseAddresses returns a guard that refuses exactly the given host:port
// strings and counts how often it was consulted.
func refuseAddresses(asked *atomic.Int32, refused ...string) GuardFunc {
	set := map[string]bool{}
	for _, a := range refused {
		set[a] = true
	}
	return func(address string) error {
		asked.Add(1)
		if set[address] {
			return errOperatorMachine
		}
		return nil
	}
}

func guardedClient(t *testing.T, g *GuardedLocal) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local test server
		},
		Timeout: 5 * time.Second,
		// The proxy, not the client, is under test: see each hop.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func countingServer(t *testing.T, tlsServer bool, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, body)
	})
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &hits
}

func serverHostPort(srv *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
}

func serverPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(serverHostPort(srv))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// wantForbidden asserts a plain-HTTP request was answered with the proxy's
// generic 403, which says nothing about the destination.
func wantForbidden(t *testing.T, client *http.Client, target string) {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("%s: status=%d body=%q, want 403", target, resp.StatusCode, body)
	}
	if strings.Contains(string(body), "127.0.0.1") || strings.Contains(string(body), "operator") {
		t.Fatalf("%s: refusal body leaks detail: %q", target, body)
	}
}

// wantTunnelRefused asserts a CONNECT tunnel was refused.
func wantTunnelRefused(t *testing.T, client *http.Client, target string) {
	t.Helper()
	resp, err := client.Get(target)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("%s: tunnel was opened (status %d)", target, resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("%s: want the proxy's 403, got %v", target, err)
	}
}

// A redirect that a client follows on its own lands on the guarded proxy as a
// new request; the proxy must refuse it without sending anything.
func TestGuardedLocalRefusesGuardedDestinations(t *testing.T) {
	secret, secretHits := countingServer(t, false, "SECRET")
	secretTLS, secretTLSHits := countingServer(t, true, "SECRET-TLS")
	allowed, allowedHits := countingServer(t, false, "public")
	allowedTLS, allowedTLSHits := countingServer(t, true, "public-tls")

	var asked atomic.Int32
	g, err := StartGuardedLocal(nil, refuseAddresses(&asked, serverHostPort(secret), serverHostPort(secretTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	wantForbidden(t, client, secret.URL+"/x")
	wantTunnelRefused(t, client, secretTLS.URL+"/x")
	if secretHits.Load() != 0 || secretTLSHits.Load() != 0 {
		t.Fatalf("refused destinations were contacted: http=%d https=%d", secretHits.Load(), secretTLSHits.Load())
	}

	for _, target := range []string{allowed.URL + "/ok", allowedTLS.URL + "/ok"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "public") {
			t.Fatalf("%s: status=%d body=%q", target, resp.StatusCode, body)
		}
	}
	if allowedHits.Load() != 1 || allowedTLSHits.Load() != 1 {
		t.Fatalf("allowed destination hits = %d/%d, want 1/1", allowedHits.Load(), allowedTLSHits.Load())
	}
	if asked.Load() == 0 {
		t.Fatal("guard was never consulted")
	}
}

// With no upstream the guard also sees the address each connection dials, so
// a name the destination check accepts but that resolves to a refused address
// (DNS rebinding, or simply a name for this machine) is still refused.
func TestGuardedLocalChecksTheDialedAddress(t *testing.T) {
	secret, secretHits := countingServer(t, false, "SECRET")
	secretTLS, secretTLSHits := countingServer(t, true, "SECRET-TLS")
	var asked atomic.Int32
	// Only the literal addresses are refused: "localhost:port" passes the
	// destination check and must be caught when it is dialed.
	g, err := StartGuardedLocal(nil, refuseAddresses(&asked,
		serverHostPort(secret), "[::1]:"+serverPort(t, secret),
		serverHostPort(secretTLS), "[::1]:"+serverPort(t, secretTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	wantForbidden(t, client, "http://localhost:"+serverPort(t, secret)+"/x")
	wantTunnelRefused(t, client, "https://localhost:"+serverPort(t, secretTLS)+"/x")
	if secretHits.Load() != 0 || secretTLSHits.Load() != 0 {
		t.Fatalf("dial-time check missed: http=%d https=%d", secretHits.Load(), secretTLSHits.Load())
	}
}

// The exempt address (the browser extension's channel) is reachable through a
// CONNECT tunnel even though the guard refuses it; a plain request to it is
// still refused.
func TestGuardedLocalExemptConnectOnly(t *testing.T) {
	bridge, bridgeHits := countingServer(t, true, "bridge")
	refuseAll := func(string) error { return errors.New("refused") }
	g, err := StartGuardedLocal(nil, refuseAll, serverHostPort(bridge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	resp, err := client.Get(bridge.URL + "/ext")
	if err != nil {
		t.Fatalf("exempt CONNECT failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "bridge" || bridgeHits.Load() != 1 {
		t.Fatalf("exempt CONNECT body=%q hits=%d", body, bridgeHits.Load())
	}
	wantForbidden(t, client, "http://"+serverHostPort(bridge)+"/ext")
	if bridgeHits.Load() != 1 {
		t.Fatalf("plain request reached the exempt address: hits=%d", bridgeHits.Load())
	}
}

// recordingUpstream is an HTTP proxy that records what it was asked for and
// tunnels CONNECTs to the requested address.
type recordingUpstream struct {
	*httptest.Server
	mu       sync.Mutex
	connects []string // CONNECT targets
	urls     []string // absolute-form request hosts
	hosts    []string // Host headers of absolute-form requests
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			u.mu.Lock()
			u.urls = append(u.urls, r.URL.Host)
			u.hosts = append(u.hosts, r.Host)
			u.mu.Unlock()
			_, _ = io.WriteString(w, "via-upstream")
			return
		}
		u.mu.Lock()
		u.connects = append(u.connects, r.Host)
		u.mu.Unlock()
		dst, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "unreachable", http.StatusBadGateway)
			return
		}
		defer dst.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(dst, buffered) }()
		_, _ = io.Copy(client, dst)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *recordingUpstream) seen() (connects, urls, hosts []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.connects...), append([]string(nil), u.urls...), append([]string(nil), u.hosts...)
}

// With an upstream proxy (an operator's proxy, Caido), the proxy resolves the
// destination itself and checks every address: a name resolving to a refused
// address, or not resolving at all, never reaches the upstream, and an
// allowed name is forwarded as the checked address so the upstream cannot
// resolve it differently.
func TestGuardedLocalUpstreamChecksResolvedAddressesAndPins(t *testing.T) {
	upstream := newRecordingUpstream(t)
	up, err := Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target, targetHits := countingServer(t, true, "target")
	targetPort := serverPort(t, target)

	// Refuse the dashboard port in any spelling, and the loopback addresses
	// "localhost" resolves to on one specific port.
	refusedPort := "9137"
	refusedLocalPort := "9"
	var asked atomic.Int32
	guard := func(address string) error {
		asked.Add(1)
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if port == refusedPort {
			return errOperatorMachine
		}
		if port == refusedLocalPort && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
			return errOperatorMachine
		}
		return nil
	}
	g, err := StartGuardedLocal(up, guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	// Refused by name or address.
	wantForbidden(t, client, "http://127.0.0.1:9137/api/settings/export")
	wantTunnelRefused(t, client, "https://127.0.0.1:9137/")
	// The name passes, but what it resolves to does not (rebinding to this
	// machine): refused before anything is sent upstream.
	wantForbidden(t, client, "http://localhost:"+refusedLocalPort+"/")
	wantTunnelRefused(t, client, "https://localhost:"+refusedLocalPort+"/")
	// A name that does not resolve here is refused rather than handed to an
	// upstream that may resolve it to anything.
	wantForbidden(t, client, "http://name.invalid/")
	wantTunnelRefused(t, client, "https://name.invalid/")
	if connects, urls, _ := upstream.seen(); len(connects) != 0 || len(urls) != 0 {
		t.Fatalf("refused destinations reached the upstream: connects=%v urls=%v", connects, urls)
	}

	// Allowed: forwarded as the checked address, name kept in Host / SNI.
	resp, err := client.Get("http://localhost:8080/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-upstream" {
		t.Fatalf("allowed HTTP request: body=%q", body)
	}
	resp, err = client.Get("https://localhost:" + targetPort + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "target" || targetHits.Load() != 1 {
		t.Fatalf("allowed tunnel: body=%q hits=%d", body, targetHits.Load())
	}
	connects, urls, hosts := upstream.seen()
	if len(urls) != 1 || len(hosts) != 1 || len(connects) != 1 {
		t.Fatalf("upstream saw connects=%v urls=%v hosts=%v", connects, urls, hosts)
	}
	// The tunnel is requested for the checked address, not the name.
	if host, _, err := net.SplitHostPort(connects[0]); err != nil || net.ParseIP(host) == nil {
		t.Fatalf("upstream CONNECT was for %q, want the checked IP address", connects[0])
	}
	// Plain HTTP through an HTTP upstream keeps the name in the request line
	// and Host header (virtual hosting); only the resolution check applies.
	if urls[0] != "localhost:8080" || hosts[0] != "localhost:8080" {
		t.Fatalf("plain HTTP via HTTP upstream: url host=%q Host=%q", urls[0], hosts[0])
	}
}

// When one side of a tunnel ends, the proxy closes the other, so a peer that
// ignores the close cannot hold the tunnel (and its connections) open; Close
// ends tunnels that are still open.
func TestGuardedLocalTunnelTeardown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	serverSawEOF := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Never write, never close: just wait for the proxy to hang up.
				_, _ = io.Copy(io.Discard, c)
				serverSawEOF <- struct{}{}
				_ = c.Close()
			}(c)
		}
	}()

	g, err := StartGuardedLocal(nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	proxyAddr := strings.TrimPrefix(g.URL(), "http://")

	openTunnel := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT: resp=%v err=%v", resp, err)
		}
		return c
	}

	// The client hangs up: the proxy must close its side to the server.
	c := openTunnel()
	_ = c.Close()
	select {
	case <-serverSawEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel to the server stayed open after the client closed")
	}

	// Close ends a tunnel that is still open on both sides.
	c = openTunnel()
	defer c.Close()
	time.Sleep(100 * time.Millisecond)
	_ = g.Close()
	select {
	case <-serverSawEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("Close left an open tunnel running")
	}
}

func TestStartGuardedLocalRequiresGuard(t *testing.T) {
	if _, err := StartGuardedLocal(nil, nil); err == nil {
		t.Fatal("expected an error without a guard")
	}
}
