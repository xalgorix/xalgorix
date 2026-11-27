package browser

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// guardFixture is an "internal" server the guard refuses, standing in for the
// operator's dashboard, and a counter of requests that reached it.
type guardFixture struct {
	internal *httptest.Server
	hits     atomic.Int32
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	f := &guardFixture{}
	f.internal = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, `<html><title>SECRET-EXPORT</title><body>{"api_key":"sk-test"}</body></html>`)
	}))
	t.Cleanup(f.internal.Close)
	return f
}

// guard refuses every URL on the internal server's host:port, the way the
// agent's checkHTTPHop refuses the operator's machine and listener.
func (f *guardFixture) guard(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	internal, _ := url.Parse(f.internal.URL)
	if u.Host == internal.Host {
		return errors.New("it points at the operator's machine or the dashboard's listener")
	}
	return nil
}

func (f *guardFixture) assertNotReached(t *testing.T, out string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("internal server was reached %d time(s); output:\n%s", n, out)
	}
	if strings.Contains(out, "SECRET-EXPORT") {
		t.Fatalf("internal page content reached the agent:\n%s", out)
	}
	if !strings.Contains(out, "BROWSER REQUEST BLOCKED") {
		t.Fatalf("output does not report the refused request:\n%s", out)
	}
}

func redirector(t *testing.T, to string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A redirect from an allowed page into a refused address is not followed.
func TestRequestGuard_BlocksRedirectHop(t *testing.T) {
	f := newGuardFixture(t)
	public := redirector(t, f.internal.URL+"/api/settings/export")

	ctxID := "guard-redirect-hop"
	getBrowserStoreByID(ctxID).setRequestGuard(f.guard)
	launchCtx(t, ctxID, "")
	out, _ := action(ctxID, map[string]string{"command": "goto", "url": public.URL + "/r"})
	f.assertNotReached(t, out)
}

// A chain of redirects is checked at every hop, not only the first.
func TestRequestGuard_BlocksLaterHopInChain(t *testing.T) {
	f := newGuardFixture(t)
	second := redirector(t, f.internal.URL+"/api/settings/export")
	first := redirector(t, second.URL+"/hop2")

	ctxID := "guard-redirect-chain"
	getBrowserStoreByID(ctxID).setRequestGuard(f.guard)
	out, _ := action(ctxID, map[string]string{"command": "launch", "url": first.URL + "/hop1"})
	t.Cleanup(func() { action(ctxID, map[string]string{"command": "close"}) })
	f.assertNotReached(t, out)
}

// A page's own script cannot read the refused address with fetch().
func TestRequestGuard_BlocksScriptFetch(t *testing.T) {
	f := newGuardFixture(t)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body><script>
fetch(%q).then(r => r.text()).then(t => { document.title = t.includes("SECRET") ? "LEAKED" : "no"; })
  .catch(() => { document.title = "fetch-refused"; });
</script></body></html>`, f.internal.URL+"/api/settings/export")
	}))
	t.Cleanup(page.Close)

	ctxID := "guard-script-fetch"
	getBrowserStoreByID(ctxID).setRequestGuard(f.guard)
	launchCtx(t, ctxID, "")
	out, _ := action(ctxID, map[string]string{"command": "goto", "url": page.URL})
	time.Sleep(500 * time.Millisecond)
	title, _ := action(ctxID, map[string]string{"command": "get_url"})
	out += title
	if strings.Contains(out, "LEAKED") {
		t.Fatalf("page script read the internal address:\n%s", out)
	}
	f.assertNotReached(t, out)
}

// A tab opened after launch is guarded too.
func TestRequestGuard_BlocksInNewTab(t *testing.T) {
	f := newGuardFixture(t)
	public := redirector(t, f.internal.URL+"/api/settings/export")

	ctxID := "guard-new-tab"
	getBrowserStoreByID(ctxID).setRequestGuard(f.guard)
	launchCtx(t, ctxID, "")
	out, _ := action(ctxID, map[string]string{"command": "new_tab", "url": public.URL + "/r"})
	f.assertNotReached(t, out)
}

// Redirects to allowed addresses are still followed.
func TestRequestGuard_AllowsPermittedRedirect(t *testing.T) {
	f := newGuardFixture(t)
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>LANDED-OK</title></html>`)
	}))
	t.Cleanup(dest.Close)
	public := redirector(t, dest.URL+"/landing")

	ctxID := "guard-allowed-redirect"
	getBrowserStoreByID(ctxID).setRequestGuard(f.guard)
	launchCtx(t, ctxID, "")
	out, _ := action(ctxID, map[string]string{"command": "goto", "url": public.URL + "/r"})
	if !strings.Contains(out, "LANDED-OK") || strings.Contains(out, "BLOCKED") {
		t.Fatalf("permitted redirect was not followed cleanly:\n%s", out)
	}
}

// browser_action called through a registry picks up the registry's request
// guard, the one the agent installs with SetRequestGuard.
func TestRequestGuard_RegistryWiring(t *testing.T) {
	f := newGuardFixture(t)
	public := redirector(t, f.internal.URL+"/api/settings/export")

	reg := tools.NewRegistry()
	reg.SetScanContextID("guard-registry-wiring")
	reg.SetRequestGuard(f.guard)
	Register(reg)
	tool, ok := reg.Get("browser_action")
	if !ok {
		t.Fatal("browser_action not registered")
	}
	t.Cleanup(func() { tool.Execute(map[string]string{"command": "close"}) })
	res, _ := tool.Execute(map[string]string{"command": "launch", "url": public.URL + "/r"})
	f.assertNotReached(t, res.Output)
}

// A nil guard never removes one already installed.
func TestRequestGuard_NilDoesNotClear(t *testing.T) {
	s := &browserStore{}
	s.setRequestGuard(func(string) error { return errors.New("no") })
	s.setRequestGuard(nil)
	if s.currentRequestGuard() == nil {
		t.Fatal("nil guard cleared the installed guard")
	}
}
