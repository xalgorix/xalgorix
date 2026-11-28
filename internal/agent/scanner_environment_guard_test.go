package agent

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	egressproxy "github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

const scannerEnvRefusal = "scanning machine's own"

// stubPublicDNS makes every name resolve to a public documentation address
// for the scope checks, so the tests never depend on real DNS.
func stubPublicDNS(t *testing.T) {
	t.Helper()
	prev := scopeguard.SetLookupHost(func(string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	})
	t.Cleanup(func() { scopeguard.SetLookupHost(prev) })
}

func wantScannerEnvRefused(t *testing.T, a *Agent, addr string) {
	t.Helper()
	if err := a.checkDialAddr(addr); err == nil || !strings.Contains(err.Error(), scannerEnvRefusal) {
		t.Errorf("checkDialAddr(%q) = %v, want the scanner-environment refusal", addr, err)
	}
}

func wantDialAllowed(t *testing.T, a *Agent, addr string) {
	t.Helper()
	if err := a.checkDialAddr(addr); err != nil {
		t.Errorf("checkDialAddr(%q) = %v, want allowed", addr, err)
	}
}

// A connection the scanner itself makes to a link-local or cloud metadata
// address reaches its own environment, never the target's network. The dial
// guard (shared by http_request, send_request, the probe tools and every
// connection the scan browser makes) refuses it.
func TestCheckDialAddrRefusesScannerEnvironment(t *testing.T) {
	stubPublicDNS(t)
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:    []string{"https://example.com"},
	}
	for _, addr := range []string{
		"169.254.169.254:80",
		"169.254.169.254:443",
		"169.254.170.2:80",
		"169.254.170.23:80",
		"[fd00:ec2::254]:80",
		"[fd20:ce::254]:80",
		"100.100.100.200:80",
		"168.63.129.16:80",
		"192.0.0.192:80",
		"[::ffff:169.254.169.254]:80",
		"169.254.10.5:80", // another device on the scanner's link
		"[fe80::1]:80",
		"[fe80::1%eth0]:80",
		"metadata.google.internal:80", // a name handed to a remote proxy
		"instance-data:80",
	} {
		wantScannerEnvRefused(t, a, addr)
	}

	// The operator's machine keeps its own reason.
	if err := a.checkDialAddr("127.0.0.1:8080"); err == nil || !strings.Contains(err.Error(), "operator's machine") {
		t.Errorf("checkDialAddr(loopback) = %v, want the operator's-machine refusal", err)
	}

	// Private ranges stay reachable by design: they may be the target's own
	// network. Names are resolved and checked when dialed.
	for _, addr := range []string{
		"93.184.216.34:443",
		"10.0.0.5:80",
		"172.16.0.9:80",
		"192.168.1.10:8080",
		"[fd12::1]:80",
		"example.com:443",
		"169.254.169.254.nip.io:80",
	} {
		wantDialAllowed(t, a, addr)
	}
}

// A link-local device the operator names as a scan target stays reachable;
// other link-local addresses and the metadata service do not.
func TestCheckDialAddrAllowsLinkLocalTargetsNamedByAddress(t *testing.T) {
	stubPublicDNS(t)
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:    []string{"http://169.254.10.5:8080/", "[fe80::2]", "printer.example"},
	}
	for _, addr := range []string{"169.254.10.5:8080", "[::ffff:169.254.10.5]:8080", "[fe80::2]:443", "[fe80::2%eth0]:80"} {
		wantDialAllowed(t, a, addr)
	}
	// 169.254.10.6 might be what printer.example resolves to; a target's own
	// DNS cannot open the scanner's link.
	for _, addr := range []string{"169.254.10.6:80", "169.254.169.254:80", "[fe80::3]:80"} {
		wantScannerEnvRefused(t, a, addr)
	}

	// Naming the metadata service as a target does not open it.
	md := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:    []string{"http://169.254.169.254/", "http://169.254.170.23/"},
	}
	wantScannerEnvRefused(t, md, "169.254.169.254:80")
	wantScannerEnvRefused(t, md, "169.254.170.23:80")
}

// Only the operator's targets open a link-local address. A delegated agent's
// targets come from the model's spawn_agent call, which a scanned page can
// influence, so they never do; the scan context's targets (set by the root
// agent) still apply to it.
func TestCheckDialAddrIgnoresDelegatedAgentTargets(t *testing.T) {
	stubPublicDNS(t)
	child := &Agent{
		localGuard:       scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		delegatedAgentID: "sub_1",
		targets:          []string{"http://169.254.10.5/"},
	}
	wantScannerEnvRefused(t, child, "169.254.10.5:80")

	sctx := scanctx.New(t.Name(), t.TempDir())
	sctx.SetTargets([]string{"https://example.com"})
	child.scanCtx = sctx
	wantScannerEnvRefused(t, child, "169.254.10.5:80")

	sctx.SetTargets([]string{"http://169.254.10.5/"})
	child.targets = []string{"https://example.com"}
	wantDialAllowed(t, child, "169.254.10.5:80")
}

// The self-hosted local-targets opt-in, which already lets a scan reach the
// operator's own machine, also opens other link-local addresses, but never
// the cloud metadata service: a scanned page could otherwise read the
// instance's credentials on a self-hosted cloud machine.
func TestCheckDialAddrLocalTargetsOptIn(t *testing.T) {
	a := &Agent{localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137, AllowLocalTargets: true}}
	for _, addr := range []string{"169.254.10.5:80", "[fe80::1]:80"} {
		wantDialAllowed(t, a, addr)
	}
	for _, addr := range []string{"169.254.169.254:80", "100.100.100.200:80", "[fd00:ec2::254]:80"} {
		wantScannerEnvRefused(t, a, addr)
	}
	// The dashboard's own listener stays refused.
	if err := a.checkDialAddr("127.0.0.1:9137"); err == nil {
		t.Error("dashboard listener allowed through the local-targets opt-in")
	}
}

// The scan browser sends every connection through the guarded loopback proxy
// with the agent's dial guard, so a script on a scanned page that asks for the
// metadata service gets the proxy's refusal instead of the scanner's instance
// credentials. (The browser-level test in internal/tools/browser shows every
// page request reaches that proxy.)
func TestBrowserEgressProxyRefusesMetadataWithAgentGuard(t *testing.T) {
	stubPublicDNS(t)
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:    []string{"https://example.com"},
	}
	g, err := egressproxy.StartGuardedLocal(nil, egressproxy.GuardFunc(a.checkDialAddr), egressproxy.GuardedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	pu, err := url.Parse(g.URL())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(client.CloseIdleConnections)

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.170.2/v2/credentials/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.10.5/",
	} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status=%d body=%q, want the proxy's 403", target, resp.StatusCode, body)
		}
	}
	// HTTPS goes through a CONNECT tunnel, which must not open either.
	resp, err := client.Get("https://169.254.169.254/latest/meta-data/")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("CONNECT tunnel to the metadata service opened (status %d)", resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("CONNECT to the metadata service: want the proxy's 403, got %v", err)
	}
}
