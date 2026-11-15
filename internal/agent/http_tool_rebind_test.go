package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

// rebindHost is the name the scope checks see as a public address and the
// connection sees as loopback.
const rebindHost = "rebind.test"

// rebindingSetup stands up the DNS rebinding case: the agent's URL checks
// resolve rebindHost to a public address, while the resolver the HTTP tools
// connect with answers 127.0.0.1, where a local service is listening. It
// returns the service's URL under rebindHost, its port and its hit counter.
func rebindingSetup(t *testing.T) (target string, port int, hits *atomic.Int32) {
	t.Helper()
	if proxy.Required() || proxy.Enabled() {
		t.Skip("proxy routing is active; these requests must dial directly")
	}

	// The URL checks see a public address.
	withScopeguardLookupHost(t, func(host string) ([]string, error) {
		if host == rebindHost {
			return []string{"93.184.216.34"}, nil
		}
		return net.LookupHost(host)
	})

	// The connection's resolver answers loopback.
	dnsAddr := startLoopbackDNS(t)
	prev := tools.SetDialResolver(&net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", dnsAddr)
		},
	})
	t.Cleanup(func() { tools.SetDialResolver(prev) })

	hits = new(atomic.Int32)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("LOCAL_ONLY auth=" + r.Header.Get("Authorization")))
	}))
	t.Cleanup(local.Close)
	port = portOf(t, local.URL)
	target = "http://" + rebindHost + ":" + strconv.Itoa(port) + "/proof"

	// An environment proxy would carry these requests instead of a dial.
	if u, err := url.Parse(target); err == nil {
		if p, _ := http.ProxyFromEnvironment(&http.Request{URL: u}); p != nil {
			t.Skip("an environment proxy applies to the test target")
		}
	}
	return target, port, hits
}

// startLoopbackDNS serves A queries for any name with 127.0.0.1 (TTL 0) and
// answers other types with no records. It returns its UDP address.
func startLoopbackDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID: hdr.ID, Response: true, Authoritative: true,
				RecursionDesired: hdr.RecursionDesired, RecursionAvailable: true,
			})
			if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
				continue
			}
			if q.Type == dnsmessage.TypeA {
				rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
				if b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}) != nil {
					continue
				}
			}
			msg, err := b.Finish()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(msg, from)
		}
	}()
	return pc.LocalAddr().String()
}

func newRebindAgent(t *testing.T, guard scopeguard.Config) *Agent {
	t.Helper()
	cfg := &config.Config{MaxIterations: 1, BindAddr: "127.0.0.1", SkillsDir: t.TempDir()}
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(func() { sctx.Close() })
	a := NewAgent(cfg, "rebind-scope", make(chan Event, 64), guard, sctx)
	t.Cleanup(func() { a.Stop() })
	return a
}

// withUseProxy sets the UseProxy setting for the test. With the proxy manager
// off, send_request still connects directly.
func withUseProxy(t *testing.T, on bool) {
	t.Helper()
	cfg := config.Get()
	old := cfg.UseProxy
	cfg.UseProxy = on
	t.Cleanup(func() { cfg.UseProxy = old })
}

func toolError(res tools.Result, err error) string {
	if err != nil {
		return err.Error()
	}
	return res.Error
}

// A hostname that passes the URL checks as a public address but resolves to
// loopback when the tool connects must not reach the local service, on any
// of the direct HTTP paths: http_request, send_request (also with the proxy
// setting on while no proxy is active), SendRaw (probe and verify tools) and
// the target availability probe.
func TestHTTPToolsRefuseDNSRebindingToLoopback(t *testing.T) {
	target, _, hits := rebindingSetup(t)
	a := newRebindAgent(t, scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137})
	headers, _ := json.Marshal(map[string]string{"Authorization": "Bearer proof-secret"})

	for _, c := range []struct {
		tool     string
		useProxy bool
	}{
		{"http_request", false},
		{"send_request", false},
		{"send_request", true},
	} {
		withUseProxy(t, c.useProxy)
		args := map[string]string{"url": target, "method": "GET", "headers": string(headers), "follow_redirects": "false"}
		if ok, reason := a.shouldBlockForOutOfScope(c.tool, args); ok {
			t.Fatalf("%s: the URL check must see the public address (test setup): %s", c.tool, reason)
		}
		res, err := a.registry.Execute(c.tool, args)
		if err == nil && res.Error == "" {
			t.Fatalf("%s (UseProxy=%v): request to a name rebound to loopback succeeded:\n%s", c.tool, c.useProxy, res.Output)
		}
		if msg := toolError(res, err); !strings.Contains(msg, "not allowed") {
			t.Fatalf("%s (UseProxy=%v): want the dial guard's refusal, got: %s", c.tool, c.useProxy, msg)
		}
	}
	withUseProxy(t, false)

	if _, err := a.sendRaw(httpclient.RawRequest{
		Method: "GET", URL: target, Headers: map[string]string{"Authorization": "Bearer proof-secret"},
	}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("SendRaw: want the dial guard's refusal, got %v", err)
	}

	// The availability probe of the scan target goes through the same check.
	if _, err := httpclient.ProbeTarget(context.Background(), "", target, a.checkDialAddr); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("ProbeTarget: want the dial guard's refusal, got %v", err)
	}

	if n := hits.Load(); n != 0 {
		t.Fatalf("local service received %d requests through DNS rebinding", n)
	}
}

// The dial check applies the same opt-ins as the URL checks: a loopback port
// provisioned for the scan stays reachable when a name resolves to it.
func TestHTTPToolsDialGuardKeepsProvisionedLoopbackPorts(t *testing.T) {
	target, port, hits := rebindingSetup(t)
	a := newRebindAgent(t, scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137, AllowLoopbackPorts: []int{port}})

	for _, tool := range []string{"http_request", "send_request"} {
		res, err := a.registry.Execute(tool, map[string]string{"url": target, "method": "GET"})
		if err != nil || !strings.Contains(res.Output, "LOCAL_ONLY") {
			t.Fatalf("%s: provisioned loopback port refused: err=%v output=%q error=%q", tool, err, res.Output, res.Error)
		}
	}
	resp, err := a.sendRaw(httpclient.RawRequest{Method: "GET", URL: target})
	if err != nil || !strings.Contains(string(resp.Body), "LOCAL_ONLY") {
		t.Fatalf("SendRaw: provisioned loopback port refused: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("hits = %d, want 3", n)
	}
}
