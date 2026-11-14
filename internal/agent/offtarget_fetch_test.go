package agent

import (
	"strings"
	"testing"
)

func TestFetchDestinationHosts_DestinationVsPayload(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{"bare curl target", "curl -s https://api.example.net/de/", []string{"api.example.net"}},
		{"quoted curl target", `curl -sk "https://api.example.net/api"`, []string{"api.example.net"}},
		{"python requests get", `requests.get("https://api.example.net")`, []string{"api.example.net"}},
		{"two curl targets", "curl https://a.example.com; curl https://b.example.net", []string{"a.example.com", "b.example.net"}},
		// Payloads: an off-target host that is only a value, never a destination.
		{"query param payload", `curl "https://target.example.com/x?next=https://evil.example.net"`, []string{"target.example.com"}},
		{"form data payload", `curl -d 'url=https://evil.example.net' https://target.example.com/proxy`, []string{"target.example.com"}},
		{"json dict payload", `curl -d '{"url":"https://evil.example.net"}' https://target.example.com/api`, []string{"target.example.com"}},
		{"python dict payload", `requests.post(T, json={'url': 'https://169.254.169.254/latest'})`, nil},
		{"header value payload", `curl -H "Referer: https://evil.example.net" https://target.example.com/`, []string{"target.example.com"}},
		// URL assigned to a shell var (after '='), then fetched via the var: the
		// literal is a payload-context assignment and the fetch has no literal
		// host, so nothing is treated as a destination (fail-open).
		{"variable url", `B=https://api.example.net; curl "$B/path"`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fetchDestinationHosts(tc.value)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("fetchDestinationHosts(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestFetchHostInScope_SingleHost(t *testing.T) {
	a := &Agent{targets: []string{"https://www.example.com"}, singleHostScope: true}
	in := []string{"www.example.com", "example.com", "abc123.oast.live"}
	out := []string{"api.example.net", "cdn.example.org", "sub.example.com"}
	for _, h := range in {
		if !a.fetchHostInScope(h) {
			t.Errorf("%s should be in scope", h)
		}
	}
	for _, h := range out {
		if a.fetchHostInScope(h) {
			t.Errorf("%s should be OUT of scope in a single-host scan", h)
		}
	}
}

func TestFetchHostInScope_BroadScanAllowsFamily(t *testing.T) {
	a := &Agent{targets: []string{"https://www.example.com"}, singleHostScope: false}
	if !a.fetchHostInScope("sub.example.com") {
		t.Error("a non-single scan should allow a host in the target's registrable domain")
	}
	if a.fetchHostInScope("api.example.net") {
		t.Error("a different registrable domain is still out of scope")
	}
}

func TestShouldBlockForTargetScope_OffTargetFetch(t *testing.T) {
	a := &Agent{targets: []string{"https://www.example.com"}, singleHostScope: true}
	cases := []struct {
		name    string
		tool    string
		args    map[string]string
		blocked bool
	}{
		{"curl to off-target backend", "terminal_execute", map[string]string{"command": "curl -sk https://api.example.net/de/"}, true},
		{"http_request to off-target", "http_request", map[string]string{"url": "https://api.example.net/api"}, true},
		{"curl to the target", "terminal_execute", map[string]string{"command": "curl -sk https://www.example.com/"}, false},
		{"curl to the apex target", "terminal_execute", map[string]string{"command": "curl -sk https://example.com/login"}, false},
		{"SSRF payload naming off-target host", "terminal_execute", map[string]string{"command": `curl -sk "https://www.example.com/proxy?url=https://api.example.net/internal"`}, false},
		{"metadata SSRF payload", "terminal_execute", map[string]string{"command": `curl -sk "https://www.example.com/fetch?u=http://169.254.169.254/latest/meta-data/"`}, false},
		{"OOB callback poll", "terminal_execute", map[string]string{"command": "curl -s https://abcdef.oast.live/x"}, false},
		{"notes may mention the backend", "add_note", map[string]string{"note": "found backend https://api.example.net in the JS"}, false},
		{"grep over local files", "terminal_execute", map[string]string{"command": "grep -r openModal tmp/routes/"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := a.shouldBlockForTargetScope(tc.tool, tc.args)
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v (%q), want %v", blocked, reason, tc.blocked)
			}
			if blocked && !strings.Contains(reason, "different host") {
				t.Fatalf("off-target reason should name the problem: %q", reason)
			}
		})
	}
}

// A broad (non-single) scan must not get the off-target fetch block, so related
// hosts in a wildcard engagement are still reachable.
func TestShouldBlockForTargetScope_BroadScanNoOffTargetBlock(t *testing.T) {
	a := &Agent{targets: []string{"https://www.example.com"}, singleHostScope: false}
	blocked, _ := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": "curl -sk https://api.example.net/"})
	if blocked {
		t.Fatal("a non-single scan must not block off-target fetches via this guard")
	}
}

func TestTargetBoundaryPromptSection_SingleHostOffTarget(t *testing.T) {
	a := &Agent{targets: []string{"https://www.example.com"}, singleHostScope: true}
	s := a.targetBoundaryPromptSection(a.targets)
	for _, want := range []string{"Test only the configured host", "different domains", "payloads"} {
		if !strings.Contains(s, want) {
			t.Fatalf("prompt section missing %q:\n%s", want, s)
		}
	}
}
