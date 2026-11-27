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
	"os"
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
// 403, which says it is not the target's answer but nothing about the
// destination.
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
	if strings.Contains(string(body), "127.0.0.1") || strings.Contains(string(body), "::1") || strings.Contains(string(body), "operator") {
		t.Fatalf("%s: refusal body leaks detail: %q", target, body)
	}
	if !strings.Contains(string(body), "not from the target") {
		t.Fatalf("%s: refusal body does not say it is the proxy's answer: %q", target, body)
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
	g, err := StartGuardedLocal(nil, refuseAddresses(&asked, serverHostPort(secret), serverHostPort(secretTLS)), GuardedOptions{})
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
		serverHostPort(secretTLS), "[::1]:"+serverPort(t, secretTLS)), GuardedOptions{})
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
	g, err := StartGuardedLocal(nil, refuseAll, GuardedOptions{Exempt: []string{serverHostPort(bridge)}})
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

// With an upstream proxy on this machine (Caido, Burp, a local proxy), the
// proxy resolves the destination itself and checks every address: a name
// resolving to a refused address, or not resolving at all, never reaches the
// upstream, and an allowed name is forwarded as the checked address so the
// upstream cannot resolve it differently.
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
	g, err := StartGuardedLocal(up, guard, GuardedOptions{})
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
	// Plain HTTP carries the checked address in the request line too (the
	// Host header keeps the name: see TestGuardedLocalPinsPlainHTTPForLocalUpstream).
	if host, _, err := net.SplitHostPort(urls[0]); err != nil || net.ParseIP(host) == nil {
		t.Fatalf("plain HTTP via the local upstream was for %q, want the checked IP address", urls[0])
	}
}

// treatUpstreamsAsRemote makes every upstream count as one on another
// machine for the rest of the test, so a loopback test proxy can stand in
// for a remote one.
func treatUpstreamsAsRemote(t *testing.T) {
	t.Helper()
	prev := upstreamOnThisMachine
	upstreamOnThisMachine = func(*Proxy) bool { return false }
	t.Cleanup(func() { upstreamOnThisMachine = prev })
}

// An upstream on another machine is sent the name once the guard has
// accepted it, so proxies that filter by domain and pivots into networks
// this machine cannot resolve keep working. Destinations the guard refuses,
// including names that resolve here to a refused address, still never reach
// it.
func TestGuardedLocalRemoteUpstreamIsSentNames(t *testing.T) {
	treatUpstreamsAsRemote(t)
	upstream := newRecordingUpstream(t)
	up, err := Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target, targetHits := countingServer(t, true, "target")
	targetPort := serverPort(t, target)
	refusedLocalPort := "9"
	guard := func(address string) error {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if port == "9137" {
			return errOperatorMachine
		}
		// Like the real guard, resolve names and refuse any that lands on
		// loopback at the refused port.
		if port == refusedLocalPort {
			addrs := []string{host}
			if net.ParseIP(host) == nil {
				addrs, _ = net.LookupHost(host)
			}
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.IsLoopback() {
					return errOperatorMachine
				}
			}
		}
		return nil
	}
	g, err := StartGuardedLocal(up, guard, GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	wantForbidden(t, client, "http://127.0.0.1:9137/api/settings/export")
	wantTunnelRefused(t, client, "https://127.0.0.1:9137/")
	wantForbidden(t, client, "http://localhost:"+refusedLocalPort+"/")
	wantTunnelRefused(t, client, "https://localhost:"+refusedLocalPort+"/")
	if connects, urls, _ := upstream.seen(); len(connects) != 0 || len(urls) != 0 {
		t.Fatalf("refused destinations reached the upstream: connects=%v urls=%v", connects, urls)
	}

	// Allowed names go to the upstream as names.
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
	// A name this machine cannot resolve is the upstream's to resolve.
	resp, err = client.Get("http://internal-only.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-upstream" {
		t.Fatalf("unresolvable name via remote upstream: status=%d body=%q", resp.StatusCode, body)
	}
	if resp, err := client.Get("https://internal-only.invalid/"); err == nil {
		resp.Body.Close()
	}

	connects, urls, _ := upstream.seen()
	wantConnects := []string{"localhost:" + targetPort, "internal-only.invalid:443"}
	if strings.Join(connects, ",") != strings.Join(wantConnects, ",") {
		t.Fatalf("upstream CONNECTs = %v, want the names %v", connects, wantConnects)
	}
	wantURLs := []string{"localhost:8080", "internal-only.invalid"}
	if strings.Join(urls, ",") != strings.Join(wantURLs, ",") {
		t.Fatalf("upstream plain-HTTP hosts = %v, want the names %v", urls, wantURLs)
	}
}

// Whether an upstream runs on this machine: loopback names and addresses
// (IPv4-mapped too), the unspecified address, this machine's interface
// addresses, and names that do not resolve here (the strict answer). The
// guard plays no part, so a local-targets opt-in cannot make a local proxy
// look remote.
func TestUpstreamOnThisMachine(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"::1", true},
		{"[::1]", true},
		{"::ffff:127.0.0.1", true},
		{"localhost", true},
		{"localhost.", true},
		{"caido.localhost", true},
		{"0.0.0.0", true},
		{"::", true},
		{"proxy.name.invalid", true}, // does not resolve here
		{"198.51.100.7", false},      // another machine (TEST-NET-2)
		{"2001:db8::7", false},       // another machine (documentation range)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				cases = append(cases, struct {
					host string
					want bool
				}{n.IP.String(), true}) // this machine's own interface
				break
			}
		}
	}
	for _, c := range cases {
		if got := upstreamOnThisMachine(&Proxy{Type: ProxyTypeHTTP, Host: c.host, Port: "8080"}); got != c.want {
			t.Errorf("%s on this machine = %v, want %v", c.host, got, c.want)
		}
	}
}

// A proxy the browser reaches through an address of this machine's own
// interface is treated as on this machine, and so is handed checked
// addresses, even when the guard's policy would let that address through as
// a scan target (the local-targets opt-in).
func TestGuardedLocalInterfaceUpstreamIsPinnedDespiteGuardOptIn(t *testing.T) {
	var ifaceIP net.IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				ifaceIP = n.IP
				break
			}
		}
	}
	if ifaceIP == nil {
		t.Skip("no non-loopback IPv4 interface address")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ifaceIP.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ifaceIP, err)
	}
	upstream := &recordingUpstream{}
	upstream.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.urls = append(upstream.urls, r.URL.Host)
		upstream.mu.Unlock()
		_, _ = io.WriteString(w, "via-upstream")
	}))
	_ = upstream.Listener.Close()
	upstream.Listener = ln
	upstream.Start()
	t.Cleanup(upstream.Close)
	up, err := Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	// The guard allows everything, like a policy with the local-targets
	// opt-in switched on.
	g, err := StartGuardedLocal(up, func(string) error { return nil }, GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	resp, err := guardedClient(t, g).Get("http://localhost:8080/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, urls, _ := upstream.seen()
	if len(urls) != 1 {
		t.Fatalf("upstream saw %v", urls)
	}
	if host, _, err := net.SplitHostPort(urls[0]); err != nil || net.ParseIP(host) == nil {
		t.Fatalf("proxy on this machine's interface was sent %q, want a checked IP address", urls[0])
	}
}

// Without an upstream, opts.Proxy picks a proxy per destination, the way
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY work for http_request. Destinations
// it sends to a proxy are checked like any other, and one it leaves out goes
// direct.
func TestGuardedLocalFollowsPerDestinationProxy(t *testing.T) {
	upstream := newRecordingUpstream(t)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	direct, directHits := countingServer(t, false, "direct")
	target, targetHits := countingServer(t, true, "target")

	var mu sync.Mutex
	var asked []string
	pick := func(req *http.Request) (*url.URL, error) {
		mu.Lock()
		asked = append(asked, req.URL.Scheme+"://"+req.URL.Host)
		mu.Unlock()
		if req.URL.Host == serverHostPort(direct) { // NO_PROXY
			return nil, nil
		}
		if req.URL.Hostname() == "broken.test" {
			return nil, errors.New("bad proxy setting")
		}
		return upstreamURL, nil
	}
	var guardAsked atomic.Int32
	g, err := StartGuardedLocal(nil, refuseAddresses(&guardAsked, "127.0.0.1:9137"), GuardedOptions{Proxy: pick})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	client := guardedClient(t, g)

	// Refused before a proxy is even chosen.
	wantForbidden(t, client, "http://127.0.0.1:9137/")
	// Left out of the proxy: direct.
	resp, err := client.Get(direct.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "direct" || directHits.Load() != 1 {
		t.Fatalf("direct request: body=%q hits=%d", body, directHits.Load())
	}
	// Through the proxy (a loopback one, so it is handed checked addresses).
	resp, err = client.Get("http://localhost:8080/page")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-upstream" {
		t.Fatalf("proxied HTTP request: body=%q", body)
	}
	resp, err = client.Get("https://localhost:" + serverPort(t, target) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "target" || targetHits.Load() != 1 {
		t.Fatalf("proxied tunnel: body=%q hits=%d", body, targetHits.Load())
	}
	connects, urls, _ := upstream.seen()
	if len(connects) != 1 || len(urls) != 1 {
		t.Fatalf("upstream saw connects=%v urls=%v", connects, urls)
	}
	for _, hostPort := range []string{connects[0], urls[0]} {
		if host, _, err := net.SplitHostPort(hostPort); err != nil || net.ParseIP(host) == nil {
			t.Fatalf("local proxy was sent %q, want a checked IP address", hostPort)
		}
	}
	// A proxy setting that cannot be used is a gateway error from the proxy.
	resp, err = client.Get("http://broken.test/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "not from the target") {
		t.Fatalf("unusable proxy: status=%d body=%q", resp.StatusCode, body)
	}

	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(asked, ",")
	if !strings.Contains(joined, "http://localhost:8080") || !strings.Contains(joined, "https://localhost:"+serverPort(t, target)) {
		t.Fatalf("proxy chooser was asked %v; want http for plain requests and https for tunnels", asked)
	}
	if strings.Contains(joined, "9137") {
		t.Fatalf("proxy chooser was asked about a refused destination: %v", asked)
	}
}

// A failed connection is answered with a 502 that names the kind of failure
// and says it is the proxy's answer, without addresses.
func TestGuardedLocalBadGatewayNamesTheCause(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()

	g, err := StartGuardedLocal(nil, func(string) error { return nil }, GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	resp, err := guardedClient(t, g).Get("http://" + closed + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q, want 502", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "connection refused") || !strings.Contains(string(body), "not from the target") {
		t.Fatalf("502 body does not name the cause or the proxy: %q", body)
	}
	if strings.Contains(string(body), "127.0.0.1") {
		t.Fatalf("502 body leaks the address: %q", body)
	}
}

// A SOCKS5 upstream that accepts the connection and then says nothing cannot
// hold a tunnel request open past the handshake deadline.
func TestDialThroughUpstreamSOCKS5HandshakeDeadline(t *testing.T) {
	prev := upstreamHandshakeTimeout
	upstreamHandshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { upstreamHandshakeTimeout = prev })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				<-release
				_ = c.Close()
			}(c)
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &Proxy{Type: ProxyTypeSOCKS5, Host: host, Port: port}

	started := time.Now()
	done := make(chan error, 1)
	go func() {
		conn, _, err := dialThroughUpstream(t.Context(), p, "example.test:443")
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake with a silent SOCKS5 upstream succeeded")
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("SOCKS5 handshake still blocked after %v", time.Since(started))
	}
}

// Proxy URLs from the environment get net/http's default ports.
func TestProxyFromURL(t *testing.T) {
	cases := []struct {
		raw, wantType, wantPort string
	}{
		{"http://proxy.test", "http", "80"},
		{"https://proxy.test", "https", "443"},
		{"socks5://proxy.test", "socks5", "1080"},
		{"socks5h://proxy.test:9050", "socks5", "9050"},
		{"http://user:pw@proxy.test:3128", "http", "3128"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := proxyFromURL(u)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if string(p.Type) != c.wantType || p.Port != c.wantPort || p.Host != "proxy.test" {
			t.Fatalf("%s: got %+v", c.raw, p)
		}
	}
	if p, _ := proxyFromURL(&url.URL{Scheme: "http", Host: "proxy.test", User: url.UserPassword("user", "pw")}); p.Username != "user" || p.Password != "pw" {
		t.Fatalf("credentials not carried over: %+v", p)
	}
	for _, raw := range []string{"ftp://proxy.test", "http://"} {
		u, _ := url.Parse(raw)
		if _, err := proxyFromURL(u); err == nil {
			t.Fatalf("%s: want an error", raw)
		}
	}
}

// rawUpstream is an HTTP proxy that records each raw request line and Host
// header (net/http's server would replace the Host header with the
// request-line host) and answers "via-upstream".
func rawUpstream(t *testing.T) (addr string, lines, hosts func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var gotLines, gotHosts []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				host := ""
				for {
					h, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(h) == "" {
						break
					}
					if k, v, ok := strings.Cut(h, ":"); ok && strings.EqualFold(k, "Host") {
						host = strings.TrimSpace(v)
					}
				}
				mu.Lock()
				gotLines = append(gotLines, strings.TrimSpace(line))
				gotHosts = append(gotHosts, host)
				mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nvia-upstream")
			}(c)
		}
	}()
	snapshot := func(s *[]string) func() []string {
		return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), (*s)...) }
	}
	return ln.Addr().String(), snapshot(&gotLines), snapshot(&gotHosts)
}

// For a proxy on this machine (an intercepting proxy like Caido or Burp),
// plain HTTP is sent with the checked address in the request line and the
// name kept in the Host header, so the upstream has no name to resolve to
// this machine.
func TestGuardedLocalPinsPlainHTTPForLocalUpstream(t *testing.T) {
	addr, lines, hosts := rawUpstream(t)
	up, err := Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	g, err := StartGuardedLocal(up, func(string) error { return nil }, GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	resp, err := guardedClient(t, g).Get("http://localhost:8080/api/x?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-upstream" {
		t.Fatalf("body=%q", body)
	}
	gotLines, gotHosts := lines(), hosts()
	if len(gotLines) != 1 {
		t.Fatalf("upstream saw %v", gotLines)
	}
	want := []string{"GET http://127.0.0.1:8080/api/x?q=1 HTTP/1.1", "GET http://[::1]:8080/api/x?q=1 HTTP/1.1"}
	if gotLines[0] != want[0] && gotLines[0] != want[1] {
		t.Fatalf("request line = %q, want the checked address with path and query", gotLines[0])
	}
	if gotHosts[0] != "localhost:8080" {
		t.Fatalf("Host header = %q, want the original name", gotHosts[0])
	}
}

// count reports how many connections open tunnels hold.
func (t *tunnelSet) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
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
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	serverSawEOF := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// A hostile peer: read until the proxy stops sending, then
				// keep the connection open and silent.
				_, _ = io.Copy(io.Discard, c)
				serverSawEOF <- struct{}{}
				<-release
				_ = c.Close()
			}(c)
		}
	}()

	g, err := StartGuardedLocal(nil, func(string) error { return nil }, GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	proxyAddr := strings.TrimPrefix(g.URL(), "http://")
	waitTunnels := func(want int, why string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for g.handler.tunnels.count() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d tunnel connections open, want %d", why, g.handler.tunnels.count(), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

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

	// The client hangs up while the server stays silent and open: the
	// proxy must still tear the whole tunnel down.
	c := openTunnel()
	waitTunnels(2, "tunnel open")
	_ = c.Close()
	select {
	case <-serverSawEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("the server was never told the client left")
	}
	waitTunnels(0, "after the client closed, with a silent server")

	// Close ends a tunnel that is still open on both sides.
	c = openTunnel()
	defer c.Close()
	waitTunnels(2, "second tunnel open")
	_ = g.Close()
	waitTunnels(0, "after Close")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("client side of the tunnel still open after Close: %v", err)
	}
}

func TestStartGuardedLocalRequiresGuard(t *testing.T) {
	if _, err := StartGuardedLocal(nil, nil, GuardedOptions{}); err == nil {
		t.Fatal("expected an error without a guard")
	}
}
