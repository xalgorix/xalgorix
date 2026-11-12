package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// http_request and send_request are checked on their destination: the
// operator's machine and the dashboard's listener are refused on the main
// tool path, exactly as the verifier path already refused them.
func TestShouldBlockForOutOfScope_HTTPToolDestination(t *testing.T) {
	a := &Agent{localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137}}

	blocked := []struct {
		tool, url string
	}{
		{"http_request", "http://127.0.0.1:8889/proof"},
		{"http_request", "http://127.0.0.1:9137/api/version"}, // the dashboard listener
		{"http_request", "127.0.0.1:8889/proof"},              // sent as https://127.0.0.1:8889/proof
		{"http_request", "localhost/proof"},                   // sent as https://localhost/proof
		{"http_request", "HTTP://127.0.0.1/"},
		{"http_request", "http://[::1]:8080/"},
		{"http_request", "http://0.0.0.0:9137/"},
		{"http_request", "http://[::1%25x]:8080/"}, // zoned IPv6 literals dial the same address
		{"http_request", "http://[::ffff:127.0.0.1%25x]:9137/api/version"},
		{"send_request", "http://127.0.0.1:8889/proof"},
		{"SEND_REQUEST", "http://localhost:6060/debug/pprof/heap"},
	}
	for _, c := range blocked {
		if ok, reason := a.shouldBlockForOutOfScope(c.tool, map[string]string{"url": c.url, "method": "GET"}); !ok {
			t.Errorf("%s %q: want blocked, got allowed", c.tool, c.url)
		} else if !strings.Contains(reason, "operator's machine") {
			t.Errorf("%s %q: unexpected reason %q", c.tool, c.url, reason)
		}
	}

	// A call without parameter tags arrives as _raw; the registry turns it
	// into url, so it is the destination too.
	for _, tool := range []string{"http_request", "send_request"} {
		if ok, _ := a.shouldBlockForOutOfScope(tool, map[string]string{"_raw": "http://127.0.0.1:9137/api/version"}); !ok {
			t.Errorf("%s with _raw destination: want blocked", tool)
		}
	}

	// Hosts named in the query, headers or body are payloads aimed at the
	// target (SSRF probes); only the destination is the agent's own request.
	allowed := []map[string]string{
		{"url": "https://93.184.216.34/fetch?url=http://127.0.0.1:22/"},
		{"url": "https://93.184.216.34/api", "method": "POST", "body": `{"callback":"http://localhost:9137/api/version"}`},
		{"url": "https://93.184.216.34/", "headers": `{"X-Forwarded-Host":"127.0.0.1"}`},
		{"url": "http://169.254.169.254/latest/meta-data/"}, // target-side SSRF surface, allowed by design
		{"url": ""},
	}
	for _, args := range allowed {
		for _, tool := range []string{"http_request", "send_request"} {
			if ok, reason := a.shouldBlockForOutOfScope(tool, args); ok {
				t.Errorf("%s %v: want allowed, got blocked: %s", tool, args, reason)
			}
		}
	}

	// A loopback port the scan deliberately provisioned stays reachable; the
	// dashboard's own port never is.
	prov := &Agent{localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137, AllowLoopbackPorts: []int{3000, 9137}}}
	if ok, reason := prov.shouldBlockForOutOfScope("http_request", map[string]string{"url": "http://127.0.0.1:3000/"}); ok {
		t.Errorf("provisioned loopback port blocked: %s", reason)
	}
	if ok, _ := prov.shouldBlockForOutOfScope("http_request", map[string]string{"url": "http://127.0.0.1:9137/"}); !ok {
		t.Errorf("dashboard port allowed through the provisioned-port allowlist")
	}
}

func TestCheckHTTPHop(t *testing.T) {
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:    []string{"https://93.184.216.34:8443"},
	}
	refused := []string{
		"http://127.0.0.1:8889/proof",
		"http://127.0.0.1:9137/api/version",
		"http://localhost/",
		"http://[::1%25x]:8889/",
		"https://93.184.216.34:9000/", // another port of the port-pinned target
		"https://93.184.216.34/",      // implied 443
	}
	for _, u := range refused {
		if err := a.checkHTTPHop(u); err == nil {
			t.Errorf("hop %q: want refused", u)
		}
	}
	allowed := []string{
		"https://93.184.216.34:8443/login",
		"https://93.184.216.35/",
		"http://169.254.169.254/latest/meta-data/",
	}
	for _, u := range allowed {
		if err := a.checkHTTPHop(u); err != nil {
			t.Errorf("hop %q: want allowed, got %v", u, err)
		}
	}
}

// End to end through the agent's real registry: a redirect from an allowed
// destination must not carry http_request or send_request to a loopback
// service the agent may not reach directly.
func TestHTTPToolsDoNotFollowRedirectsToTheOperatorsMachine(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHits.Add(1)
		_, _ = w.Write([]byte("INTERNAL_ONLY"))
	}))
	defer internal.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.URL.Query().Get("code"))
		http.Redirect(w, r, r.URL.Query().Get("to"), code)
	}))
	defer redirector.Close()

	// The redirector stands in for an allowed destination: its loopback port
	// is provisioned for this scan. The internal service is not.
	cfg := &config.Config{MaxIterations: 1, BindAddr: "127.0.0.1", SkillsDir: t.TempDir()}
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(func() { sctx.Close() })
	a := NewAgent(cfg, "redirect-scope", make(chan Event, 64), scopeguard.Config{
		BindAddr:           "127.0.0.1",
		Port:               9137,
		AllowLoopbackPorts: []int{portOf(t, redirector.URL)},
	}, sctx)
	t.Cleanup(func() { a.Stop() })

	for _, args := range []map[string]string{
		{"url": internal.URL + "/proof"},
		{"_raw": internal.URL + "/proof"},
	} {
		if ok, _ := a.shouldBlockForOutOfScope("http_request", args); !ok {
			t.Fatalf("direct request to the internal service must be refused: %v", args)
		}
	}

	for _, tool := range []string{"http_request", "send_request"} {
		for _, code := range []int{301, 302, 303, 307, 308} {
			hop := redirector.URL + "/r?code=" + strconv.Itoa(code) + "&to=" + url.QueryEscape(internal.URL+"/proof")
			args := map[string]string{"url": hop, "method": "GET"}
			if ok, reason := a.shouldBlockForOutOfScope(tool, args); ok {
				t.Fatalf("%s: allowed first hop refused: %s", tool, reason)
			}
			res, err := a.registry.Execute(tool, args)
			if err != nil {
				t.Fatalf("%s %d: %v", tool, code, err)
			}
			if strings.Contains(res.Output, "INTERNAL_ONLY") {
				t.Fatalf("%s %d: redirect reached the internal service:\n%s", tool, code, res.Output)
			}
			if !strings.Contains(res.Output, "REDIRECT NOT FOLLOWED") || !strings.Contains(res.Output, strconv.Itoa(code)) {
				t.Fatalf("%s %d: want the refused redirect response, got:\n%s", tool, code, res.Output)
			}
		}
	}
	if n := internalHits.Load(); n != 0 {
		t.Fatalf("internal service received %d requests through redirects", n)
	}
}

func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
