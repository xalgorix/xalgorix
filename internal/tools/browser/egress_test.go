package browser

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// guardedRegistry returns a registry for ctxID whose dial guard refuses the
// given ports on any host, the way the agent's guard refuses the operator's
// machine.
func guardedRegistry(ctxID string, refusedPorts ...string) *tools.Registry {
	refused := map[string]bool{}
	for _, p := range refusedPorts {
		refused[p] = true
	}
	reg := tools.NewRegistry()
	reg.SetScanContextID(ctxID)
	reg.SetDialGuard(func(address string) error {
		if _, port, err := net.SplitHostPort(address); err == nil && refused[port] {
			return errors.New("it is the operator's machine or the dashboard's listener")
		}
		return nil
	})
	Register(reg)
	return reg
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// A page the scan's browser loads must not reach an address the scan's dial
// guard refuses — not by redirecting the browser there, and not with its own
// subresources, frames, scripts or WebSockets. The agent's argument checks
// only see the URL browser_action is called with, which here is allowed.
func TestEgressGuardRefusesRedirectsAndPageRequests(t *testing.T) {
	var secretHits atomic.Int32
	secret := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No CORS headers: only a browser without the same-origin policy
		// lets the public page's script read this response.
		secretHits.Add(1)
		_, _ = io.WriteString(w, "XALGORIX-EGRESS-SECRET")
	}))
	defer secret.Close()
	// For HTTPS, count connections: the certificate is untrusted, so a
	// request would fail after connecting, which is already too late.
	var secretTLSConns atomic.Int32
	secretTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "XALGORIX-EGRESS-SECRET")
	}))
	secretTLS.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			secretTLSConns.Add(1)
		}
	}
	secretTLS.StartTLS()
	defer secretTLS.Close()
	secretURL, secretPort, secretTLSPort := secret.URL, portOf(t, secret.URL), portOf(t, secretTLS.URL)

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, secretURL+"/secret", http.StatusFound)
		case "/redirect-localhost":
			http.Redirect(w, r, "http://localhost:"+secretPort+"/secret", http.StatusFound)
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>pending</title></head><body>
<h1 id="ok">public page</h1>
<img src="%[1]s/img"><img src="http://localhost:%[2]s/img"><img src="https://127.0.0.1:%[3]s/img">
<iframe src="%[1]s/frame"></iframe>
<script>
try { new WebSocket("ws://127.0.0.1:%[2]s/ws"); } catch (e) {}
fetch(%[4]q).then(r => r.text()).then(t => { document.title = t; }).catch(() => { document.title = "blocked"; });
</script></body></html>`, secretURL, secretPort, secretTLSPort, secretURL+"/fetch")
		default:
			http.NotFound(w, r)
		}
	}))
	defer public.Close()

	ctxID := "int-egress-guard"
	reg := guardedRegistry(ctxID, secretPort, secretTLSPort)
	tool, ok := reg.Get("browser_action")
	if !ok {
		t.Fatal("browser_action not registered")
	}
	run := func(args map[string]string) string {
		t.Helper()
		res, err := tool.Execute(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return res.Output + res.Error
	}
	t.Cleanup(func() { _, _ = tool.Execute(map[string]string{"command": "close"}) })

	run(map[string]string{"command": "launch", "url": public.URL + "/redirect"})
	if s := getBrowserStoreByID(ctxID); s.egress == nil {
		t.Fatal("browser launched for a guarded registry without the egress guard")
	}
	for _, path := range []string{"/redirect", "/redirect-localhost"} {
		run(map[string]string{"command": "goto", "url": public.URL + path})
		if html := run(map[string]string{"command": "get_html"}); strings.Contains(html, "XALGORIX-EGRESS-SECRET") {
			t.Fatalf("%s reached the refused address; page:\n%s", path, html)
		}
	}

	run(map[string]string{"command": "goto", "url": public.URL + "/page"})
	deadline := time.Now().Add(10 * time.Second)
	title := ""
	for time.Now().Before(deadline) {
		title = run(map[string]string{"command": "execute_js", "code": "() => document.title"})
		if !strings.Contains(title, "pending") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The script either fails ("blocked") or reads the proxy's generic
	// refusal; it must never see the refused service's response.
	if strings.Contains(title, "XALGORIX-EGRESS-SECRET") || strings.Contains(title, "pending") {
		t.Fatalf("page script read the refused address (or never finished): title=%q", title)
	}
	if html := run(map[string]string{"command": "get_html"}); !strings.Contains(html, "public page") {
		t.Fatalf("allowed page did not load through the guard:\n%s", html)
	}
	time.Sleep(500 * time.Millisecond) // let the WebSocket and images settle
	if n, m := secretHits.Load(), secretTLSConns.Load(); n != 0 || m != 0 {
		t.Fatalf("refused addresses were contacted by the browser: http=%d https-connections=%d", n, m)
	}
}

// A browser launched without the guard (by a caller with no dial guard) is
// not handed to a guarded registry: it would have no egress checks.
func TestEgressGuardRefusesToReuseUnguardedBrowser(t *testing.T) {
	ctxID := "int-egress-unguarded-reuse"
	if _, err := browserActionWithContext(ctxID, map[string]string{"command": "launch"}); err != nil {
		t.Fatalf("unguarded launch: %v", err)
	}
	t.Cleanup(func() { _, _ = browserActionWithContext(ctxID, map[string]string{"command": "close"}) })

	reg := guardedRegistry(ctxID, "1")
	tool, _ := reg.Get("browser_action")
	_, err := tool.Execute(map[string]string{"command": "launch", "url": "about:blank"})
	if err == nil || !strings.Contains(err.Error(), "without the local-network guard") {
		t.Fatalf("guarded launch reused an unguarded browser: err=%v", err)
	}
}
