package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// refusePort returns a guard that refuses every address on port, however the
// host is written, and records each address it was asked about.
func refusePort(port string, asked *atomic.Int32) GuardFunc {
	return func(address string) error {
		asked.Add(1)
		if _, p, err := net.SplitHostPort(address); err == nil && p == port {
			return errors.New("it is the operator's machine")
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

func serverPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// A redirect that a client follows on its own lands on the guarded proxy as a
// new request; the proxy must refuse it without sending anything.
func TestGuardedLocalRefusesGuardedDestinations(t *testing.T) {
	secret, secretHits := countingServer(t, false, "SECRET")
	secretTLS, secretTLSHits := countingServer(t, true, "SECRET-TLS")
	allowed, allowedHits := countingServer(t, false, "public")
	allowedTLS, _ := countingServer(t, true, "public-tls")

	var asked atomic.Int32
	refused := map[string]bool{serverPort(t, secret): true, serverPort(t, secretTLS): true}
	guard := func(address string) error {
		asked.Add(1)
		if _, p, err := net.SplitHostPort(address); err == nil && refused[p] {
			return errors.New("it is the operator's machine")
		}
		return nil
	}
	g, err := StartGuardedLocal(nil, guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	for _, target := range []string{secret.URL + "/x", secretTLS.URL + "/x"} {
		resp, err := client.Get(target)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || strings.Contains(string(body), "SECRET") {
				t.Fatalf("%s: status=%d body=%q, want 403 without the secret", target, resp.StatusCode, body)
			}
		}
		// For HTTPS the refused CONNECT surfaces as a client error instead.
	}
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
	if allowedHits.Load() != 1 {
		t.Fatalf("allowed destination hits = %d, want 1", allowedHits.Load())
	}
}

// With no upstream the guard also sees the address each connection dials, so
// a name the destination check accepts but that resolves to a refused address
// (DNS rebinding, or simply a name for this machine) is still refused.
func TestGuardedLocalChecksTheDialedAddress(t *testing.T) {
	secret, secretHits := countingServer(t, false, "SECRET")
	secretTLS, secretTLSHits := countingServer(t, true, "SECRET-TLS")
	refused := map[string]bool{
		net.JoinHostPort("127.0.0.1", serverPort(t, secret)):    true,
		net.JoinHostPort("127.0.0.1", serverPort(t, secretTLS)): true,
	}
	var dialed atomic.Int32
	guard := func(address string) error {
		// Only the literal address is refused: "localhost:port" passes the
		// destination check and must be caught when it is dialed.
		if refused[address] {
			dialed.Add(1)
			return errors.New("it is the operator's machine")
		}
		return nil
	}
	g, err := StartGuardedLocal(nil, guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	for _, target := range []string{
		"http://localhost:" + serverPort(t, secret) + "/x",
		"https://localhost:" + serverPort(t, secretTLS) + "/x",
	} {
		resp, err := client.Get(target)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK || strings.Contains(string(body), "SECRET") {
				t.Fatalf("%s: status=%d body=%q, want a refusal", target, resp.StatusCode, body)
			}
		}
	}
	if secretHits.Load() != 0 || secretTLSHits.Load() != 0 {
		t.Fatalf("dial-time check missed: http=%d https=%d", secretHits.Load(), secretTLSHits.Load())
	}
	if dialed.Load() == 0 {
		t.Fatal("guard was never asked about the dialed address")
	}
}

// The exempt address (the browser extension's channel) is reachable through a
// CONNECT tunnel even though the guard refuses it; a plain request to it is
// still refused.
func TestGuardedLocalExemptConnectOnly(t *testing.T) {
	bridge, bridgeHits := countingServer(t, true, "bridge")
	bridgeAddr := strings.TrimPrefix(bridge.URL, "https://")
	refuseAll := func(string) error { return errors.New("refused") }
	g, err := StartGuardedLocal(nil, refuseAll, bridgeAddr)
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

	resp, err = client.Get("http://" + bridgeAddr + "/ext")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || bridgeHits.Load() != 1 {
		t.Fatalf("plain request to exempt address: status=%d hits=%d", resp.StatusCode, bridgeHits.Load())
	}
}

// With an upstream proxy (an operator's proxy, Caido) the destination is
// checked before anything is sent upstream.
func TestGuardedLocalChecksBeforeUpstream(t *testing.T) {
	var upstreamHTTP, upstreamCONNECT atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			upstreamCONNECT.Add(1)
			http.Error(w, "no tunnels here", http.StatusForbidden)
			return
		}
		upstreamHTTP.Add(1)
		_, _ = io.WriteString(w, "via-upstream")
	}))
	t.Cleanup(upstream.Close)
	up, err := Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	g, err := StartGuardedLocal(up, refusePort("9137", &asked))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	resp, err := client.Get("http://127.0.0.1:9137/api/settings/export")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("refused HTTP destination: status=%d", resp.StatusCode)
	}
	if _, err := client.Get("https://127.0.0.1:9137/"); err == nil {
		t.Fatal("refused CONNECT destination succeeded")
	}
	if upstreamHTTP.Load() != 0 || upstreamCONNECT.Load() != 0 {
		t.Fatalf("refused destinations reached the upstream: http=%d connect=%d", upstreamHTTP.Load(), upstreamCONNECT.Load())
	}

	resp, err = client.Get("http://example.invalid/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-upstream" || upstreamHTTP.Load() != 1 {
		t.Fatalf("allowed destination: body=%q upstream hits=%d", body, upstreamHTTP.Load())
	}
	if _, err := client.Get("https://example.invalid/"); err == nil {
		t.Fatal("upstream refused the tunnel; the client should see an error")
	}
	if upstreamCONNECT.Load() != 1 {
		t.Fatalf("allowed CONNECT did not reach the upstream: %d", upstreamCONNECT.Load())
	}
}

func TestStartGuardedLocalRequiresGuard(t *testing.T) {
	if _, err := StartGuardedLocal(nil, nil); err == nil {
		t.Fatal("expected an error without a guard")
	}
}
