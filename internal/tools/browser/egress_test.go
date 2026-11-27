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

// A page the scan's browser loads must not reach an address the scan's dial
// guard refuses — not by redirecting the browser there, and not with its own
// subresources, frames or scripts. The agent's argument checks only see the
// URL browser_action is called with, which here is an allowed address.
func TestEgressGuardRefusesRedirectsAndPageRequests(t *testing.T) {
	var secretHits atomic.Int32
	secret := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No CORS headers: only a browser without the same-origin policy
		// lets the public page's script read this response.
		secretHits.Add(1)
		_, _ = io.WriteString(w, "XALGORIX-EGRESS-SECRET")
	}))
	defer secret.Close()
	secretURL := secret.URL
	_, secretPort, err := net.SplitHostPort(strings.TrimPrefix(secretURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, secretURL+"/secret", http.StatusFound)
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>pending</title></head><body>
<h1 id="ok">public page</h1>
<img src="%[1]s/img"><iframe src="%[1]s/frame"></iframe>
<script>
fetch(%[2]q).then(r => r.text()).then(t => { document.title = t; }).catch(() => { document.title = "blocked"; });
</script></body></html>`, secretURL, secretURL+"/fetch")
		default:
			http.NotFound(w, r)
		}
	}))
	defer public.Close()

	ctxID := "int-egress-guard"
	reg := tools.NewRegistry()
	reg.SetScanContextID(ctxID)
	reg.SetDialGuard(func(address string) error {
		if _, port, err := net.SplitHostPort(address); err == nil && port == secretPort {
			return errors.New("it is the operator's machine or the dashboard's listener")
		}
		return nil
	})
	Register(reg)
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
	if html := run(map[string]string{"command": "get_html"}); strings.Contains(html, "XALGORIX-EGRESS-SECRET") {
		t.Fatalf("redirect reached the refused address; page:\n%s", html)
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
	// The script either fails ("blocked") or reads the guard's refusal page;
	// it must never see the refused service's response.
	if strings.Contains(title, "XALGORIX-EGRESS-SECRET") || strings.Contains(title, "pending") {
		t.Fatalf("page script read the refused address (or never finished): title=%q", title)
	}
	if html := run(map[string]string{"command": "get_html"}); !strings.Contains(html, "public page") {
		t.Fatalf("allowed page did not load through the guard:\n%s", html)
	}
	if n := secretHits.Load(); n != 0 {
		t.Fatalf("refused address received %d request(s) from the browser", n)
	}
}
