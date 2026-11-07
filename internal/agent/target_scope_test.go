package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestPinnedTargetPorts(t *testing.T) {
	pins := pinnedTargetPorts([]string{"https://Pentest-Ground.com:9000/app", "http://lab.test:8080"})
	if !pins["pentest-ground.com"]["9000"] || !pins["lab.test"]["8080"] || len(pins) != 2 {
		t.Fatalf("pins = %v", pins)
	}
	// A host also given without a port is not pinned; domain scopes never pin.
	if pins := pinnedTargetPorts([]string{"https://acme.com:9000", "https://acme.com"}); len(pins) != 0 {
		t.Fatalf("mixed targets pinned: %v", pins)
	}
	if pins := pinnedTargetPorts([]string{"*.acme.com", "domain:acme.com", "acme.com"}); len(pins) != 0 {
		t.Fatalf("domain scopes pinned: %v", pins)
	}
}

func TestShouldBlockForTargetScope_PinnedPort(t *testing.T) {
	a := &Agent{targets: []string{"https://pentest-ground.com:9000"}}
	cases := []struct {
		name    string
		tool    string
		args    map[string]string
		blocked bool
	}{
		{"request to another port", "http_request", map[string]string{"url": "https://pentest-ground.com:81/search"}, true},
		{"request to the scheme's default port", "http_request", map[string]string{"url": "https://pentest-ground.com/login"}, true},
		{"request to the pinned port", "http_request", map[string]string{"url": "https://pentest-ground.com:9000/login"}, false},
		{"curl to another port", "terminal_execute", map[string]string{"command": "curl -s http://pentest-ground.com:5013/graphql"}, true},
		{"host:port token", "python_action", map[string]string{"code": "s.connect(('x', 1)); h = 'pentest-ground.com:4280'"}, true},
		{"port scan without a port list", "terminal_execute", map[string]string{"command": "nmap -sV -sC --top-ports 200 --open pentest-ground.com"}, true},
		{"port scan beyond the pinned port", "terminal_execute", map[string]string{"command": "nmap -sV -p 9000,81 pentest-ground.com"}, true},
		{"port scan of the pinned port", "terminal_execute", map[string]string{"command": "nmap -sV -sC -p 9000 pentest-ground.com"}, false},
		{"DNS lookup", "terminal_execute", map[string]string{"command": "dig +short pentest-ground.com"}, false},
		{"finding on another port", "report_vulnerability", map[string]string{"endpoint": "https://pentest-ground.com:81/search"}, true},
		{"finding on the pinned port", "report_vulnerability", map[string]string{"endpoint": "https://pentest-ground.com:9000/search"}, false},
		{"unrelated host keeps its own rules", "http_request", map[string]string{"url": "https://example.org:81/"}, false},
		{"notes may mention other ports", "add_note", map[string]string{"note": "pentest-ground.com:81 also answers"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := a.shouldBlockForTargetScope(tc.tool, tc.args)
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v (%q), want %v", blocked, reason, tc.blocked)
			}
			if blocked && !strings.Contains(reason, "port 9000") {
				t.Fatalf("reason does not name the pinned port: %q", reason)
			}
		})
	}
}

func TestShouldBlockForTargetScope_SingleHost(t *testing.T) {
	a := &Agent{targets: []string{"https://acme.com"}, singleHostScope: true}
	if blocked, _ := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": "subfinder -d acme.com -silent"}); !blocked {
		t.Fatal("subdomain discovery allowed in a single-host scan")
	}
	if blocked, _ := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": "curl -s https://acme.com/robots.txt"}); blocked {
		t.Fatal("request to the configured host blocked")
	}
	// Wildcard sub-scans and discovery runs are not single-host scans.
	a.singleHostScope = false
	if blocked, _ := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": "subfinder -d acme.com -silent"}); blocked {
		t.Fatal("subdomain discovery blocked outside a single-host scan")
	}
}

func TestTargetBoundaryObligations(t *testing.T) {
	pinned := &ScanState{ScanTargets: []string{"https://pentest-ground.com:9000"}}
	for endpoint, want := range map[string]bool{
		"https://pentest-ground.com:9000/login": true,
		"/login":                                true,
		"https://pentest-ground.com:81/search":  false,
		"http://pentest-ground.com/":            false,
	} {
		if got := endpointInTargetBoundary(pinned, endpoint); got != want {
			t.Errorf("endpointInTargetBoundary(%q) = %v, want %v", endpoint, got, want)
		}
	}
	if hostOwesContentDiscovery(pinned, "pentest-ground.com:81") {
		t.Error("another port owes content discovery")
	}
	if !hostOwesContentDiscovery(pinned, "pentest-ground.com:9000") {
		t.Error("the pinned port owes no content discovery")
	}

	RecordSurfaceObservation(pinned, SurfaceObservation{Endpoint: "https://pentest-ground.com:81/search", Promote: true})
	RecordSurfaceObservation(pinned, SurfaceObservation{Endpoint: "https://pentest-ground.com:9000/search", Promote: true})
	if len(pinned.DiscoveredEndpoints) != 1 || !strings.Contains(pinned.DiscoveredEndpoints[0], ":9000") {
		t.Errorf("inventory = %v, want only the pinned port", pinned.DiscoveredEndpoints)
	}

	single := &ScanState{ScanTargets: []string{"https://app.acme.com"}, SingleHostScope: true}
	if hostOwesContentDiscovery(single, "api.acme.com") {
		t.Error("a sibling subdomain owes content discovery in a single-host scan")
	}
	if !hostOwesContentDiscovery(single, "app.acme.com") || !hostOwesContentDiscovery(single, "www.app.acme.com") {
		t.Error("the configured host owes no content discovery")
	}
	single.SingleHostScope = false
	if !hostOwesContentDiscovery(single, "api.acme.com") {
		t.Error("sibling subdomains changed outside single-host scans")
	}
}

func TestSubdomainScopeApplicable_SingleHost(t *testing.T) {
	state := &ScanState{ScanTargets: []string{"https://pentest-ground.com:9000"}}
	if !subdomainScopeApplicable(state) {
		t.Fatal("a bare-domain target without single-host scope should keep subdomain applicability")
	}
	state.SingleHostScope = true
	if subdomainScopeApplicable(state) {
		t.Fatal("single-host scan still owes subdomain enumeration")
	}
}

func TestTargetBoundaryPromptSection(t *testing.T) {
	a := &Agent{singleHostScope: true}
	section := a.targetBoundaryPromptSection([]string{"https://pentest-ground.com:9000"})
	for _, want := range []string{"pentest-ground.com is in scope ONLY on port 9000", "`-p 9000`", "single-host scan"} {
		if !strings.Contains(section, want) {
			t.Errorf("section missing %q:\n%s", want, section)
		}
	}
	if got := (&Agent{}).targetBoundaryPromptSection([]string{"https://acme.com"}); got != "" {
		t.Errorf("unbounded scan got a boundary section: %q", got)
	}
}

func TestSystemPromptCarriesTargetBoundary(t *testing.T) {
	for _, native := range []bool{false, true} {
		a := &Agent{
			cfg:               &config.Config{RateLimitRPS: 2},
			registry:          tools.NewRegistry(),
			singleHostScope:   true,
			nativeToolCalling: native,
		}
		prompt := a.buildSystemPrompt(
			[]string{"https://pentest-ground.com:9000"},
			"Perform a full authorized assessment.",
			scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
		)
		boundary := strings.Index(prompt, "## SCAN BOUNDARY")
		mindset := strings.Index(prompt, "## YOUR HACKER MINDSET")
		if boundary < 0 || mindset < 0 || boundary > mindset {
			t.Fatalf("native=%v: boundary section at %d, mindset at %d", native, boundary, mindset)
		}
	}
}
