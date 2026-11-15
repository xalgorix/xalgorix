package agent

import (
	"strings"
	"testing"
)

// Fixtures use synthetic organization names; none is a real scan target.
const (
	tgtURL   = "https://app.acmecorp-target.com"
	sameOrg  = "https://api.acmecorp-target.com/v1/users"
	otherOrg = "https://api.partnervendor-backend.net/v1/users"
)

func TestFetchDestinationHosts(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{"curl target", "curl -sk " + otherOrg, []string{"api.partnervendor-backend.net"}},
		{"quoted curl target", `curl -sk "` + otherOrg + `"`, []string{"api.partnervendor-backend.net"}},
		{"python requests", `requests.get("` + otherOrg + `")`, []string{"api.partnervendor-backend.net"}},
		{"query payload", `curl "` + tgtURL + `/r?next=https://api.partnervendor-backend.net"`, []string{"app.acmecorp-target.com"}},
		{"form payload", `curl -d 'u=https://api.partnervendor-backend.net' ` + tgtURL, []string{"app.acmecorp-target.com"}},
		{"json payload", `curl -d '{"url":"https://api.partnervendor-backend.net"}' ` + tgtURL, []string{"app.acmecorp-target.com"}},
		{"header payload", `curl -H "Origin: https://api.partnervendor-backend.net" ` + tgtURL, []string{"app.acmecorp-target.com"}},
		{"templated host", `curl -sk "https://app.acmecorp-target.com$p"`, nil},
		{"shell var host", `curl -sk "https://$h/x"`, nil},
		{"format string host", `curl -sk "https://%s/x"`, nil},
		{"IPv4 literal", "curl -sk http://203.0.113.10/admin", nil},
		{"octal IP literal", "curl -sk http://0177.0.0.1/", nil},
		{"shell var assignment", `B=` + otherOrg + `; curl "$B"`, nil},
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

func TestOtherOrganizationHost(t *testing.T) {
	a := &Agent{targets: []string{tgtURL}, singleHostScope: true}
	same := []string{
		"app.acmecorp-target.com", "acmecorp-target.com", "www.acmecorp-target.com",
		"api.acmecorp-target.com", "auth.acmecorp-target.com", // the app's own subdomains
		"sso-acmecorp-target.com", "xacmecorp-target.com", // brand-embedding bypass payloads
		"evil.com", "www.example.com", "x.oast.live", "169.254.169.254.nip.io", // payloads / OOB
		"raw.githubusercontent.com", "api.osv.dev", "rdap.verisign.com", "api.mail.tm", // research / utility
		"internal.test", // reserved TLD
	}
	other := []string{"api.partnervendor-backend.net", "cdn.thirdparty-assets.org", "partner.example-unrelated.io"}
	for _, h := range same {
		if a.otherOrganizationHost(h) {
			t.Errorf("%s must NOT count as another organization", h)
		}
	}
	for _, h := range other {
		if !a.otherOrganizationHost(h) {
			t.Errorf("%s should count as another organization", h)
		}
	}
	// An IP target has no registrable domain: never guess, never block.
	ip := &Agent{targets: []string{"http://203.0.113.10:8080"}, singleHostScope: true}
	if ip.otherOrganizationHost("api.partnervendor-backend.net") {
		t.Error("with an IP target there is no organization to compare against; must not block")
	}
}

func TestShouldBlockForTargetScope_OtherOrganization(t *testing.T) {
	a := &Agent{targets: []string{tgtURL}, singleHostScope: true}
	cases := []struct {
		name    string
		tool    string
		args    map[string]string
		blocked bool
	}{
		{"curl to another org's backend", "terminal_execute", map[string]string{"command": "curl -sk " + otherOrg}, true},
		{"http_request to another org", "http_request", map[string]string{"url": otherOrg}, true},
		{"python fetch to another org", "python_action", map[string]string{"code": `requests.get("` + otherOrg + `")`}, true},
		{"the target", "terminal_execute", map[string]string{"command": "curl -sk " + tgtURL + "/login"}, false},
		{"the app's own API subdomain", "terminal_execute", map[string]string{"command": "curl -sk " + sameOrg}, false},
		{"target with templated path", "terminal_execute", map[string]string{"command": `curl -sk "https://app.acmecorp-target.com$p"`}, false},
		{"target by IP", "terminal_execute", map[string]string{"command": "curl -sk -H 'Host: app.acmecorp-target.com' http://203.0.113.10/"}, false},
		{"SSRF payload naming another org", "terminal_execute", map[string]string{"command": `curl -sk "` + tgtURL + `/fetch?url=` + otherOrg + `"`}, false},
		{"open-redirect payload loop", "terminal_execute", map[string]string{"command": `for u in https://evil.com https://www.google.com https://sso-acmecorp-target.com; do curl -sk "` + tgtURL + `/go?to=$u"; done`}, false},
		{"metadata SSRF via rebinding name", "terminal_execute", map[string]string{"command": `curl -sk "` + tgtURL + `/img?src=" http://169.254.169.254.nip.io/`}, false},
		{"OOB callback poll", "terminal_execute", map[string]string{"command": "curl -s https://abcdef.oast.live/x"}, false},
		{"PoC research fetch", "terminal_execute", map[string]string{"command": "curl -sk https://raw.githubusercontent.com/someone/poc/main/exploit.py"}, false},
		{"notes may name the backend", "add_note", map[string]string{"note": "app calls " + otherOrg}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := a.shouldBlockForTargetScope(tc.tool, tc.args)
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v (%q), want %v", blocked, reason, tc.blocked)
			}
			if blocked && !strings.Contains(reason, "different organization") {
				t.Fatalf("reason should say why: %q", reason)
			}
		})
	}
}

// A broad (wildcard/domain) scan does not get this block.
func TestShouldBlockForTargetScope_BroadScanUnaffected(t *testing.T) {
	a := &Agent{targets: []string{tgtURL}, singleHostScope: false}
	if blocked, _ := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": "curl -sk " + otherOrg}); blocked {
		t.Fatal("a non-single scan must not block other-organization fetches via this guard")
	}
}

func TestTargetBoundaryPromptSection_OtherOrganizations(t *testing.T) {
	a := &Agent{targets: []string{tgtURL}, singleHostScope: true}
	s := a.targetBoundaryPromptSection(a.targets)
	for _, want := range []string{"other organizations' domains", "own subdomains", "payloads"} {
		if !strings.Contains(s, want) {
			t.Fatalf("prompt section missing %q:\n%s", want, s)
		}
	}
}

// Shapes taken from live false blocks after the guard shipped (target names are
// synthetic). Each must be allowed, while real other-organization fetches stay
// blocked.
func TestShouldBlockForTargetScope_LiveFalseBlockShapes(t *testing.T) {
	a := &Agent{targets: []string{tgtURL}, singleHostScope: true}
	allowed := map[string]string{
		"SVG xmlns in an upload payload":   `post("/files", "probe.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")`,
		"XSD namespace in Clark notation":  `python3 -c "XS='{http://www.w3.org/2001/XMLSchema}'; print(XS)"`,
		"WSDL namespace via concatenation": `python3 -c "W='{'+'http://schemas.xmlsoap.org/wsdl/'+'}'"`,
		"crawler User-Agent string":        `curl -sk -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" ` + tgtURL,
		"DNS-over-HTTPS lookup of target":  `curl -s "https://cloudflare-dns.com/dns-query?name=app.acmecorp-target.com&type=A" -H 'accept: application/dns-json'`,
		"package CDN read":                 `curl -s https://unpkg.com/nanoid@4.0.2/index.js`,
		"temp inbox for a test account":    `curl -s "https://www.1secmail.com/api/v1/?action=getDomainList"`,
	}
	for name, cmd := range allowed {
		if blocked, reason := a.shouldBlockForTargetScope("terminal_execute", map[string]string{"command": cmd}); blocked {
			t.Errorf("%s: must be allowed, got blocked: %s", name, reason)
		}
	}
	blocked := map[string]map[string]string{
		"curl to another org":           {"terminal_execute": "curl -sk " + otherOrg},
		"requests.get(\"other org\")":   {"python_action": `requests.get("` + otherOrg + `")`},
		"python URL list then fetched":  {"python_action": `for u in ["` + otherOrg + `"]: requests.get(u)`},
		"shell loop over other-org URL": {"terminal_execute": `for u in "` + otherOrg + `" "https://cdn.thirdparty-assets.org/a.js"; do curl -sk "$u"; done`},
		"http_request to another org":   {"http_request": otherOrg},
		"ffuf against another org":      {"terminal_execute": `ffuf -u "https://stage.partnervendor-backend.net/FUZZ" -w common.txt`},
		// Tuple- and list-held URLs stay destinations: in real traffic they are
		// fetched by the following loop as often as they are payloads.
		"test-case tuple then fetched": {"python_action": `t("IAM verify","` + otherOrg + `")`},
		"second URL in a host list":    {"python_action": `for h in ["` + tgtURL + `","https://www.partnervendor-backend.net"]: s.get(h+"/robots.txt")`},
	}
	for name, call := range blocked {
		for tool, v := range call {
			key := "command"
			switch tool {
			case "python_action":
				key = "code"
			case "http_request":
				key = "url"
			}
			if ok, _ := a.shouldBlockForTargetScope(tool, map[string]string{key: v}); !ok {
				t.Errorf("%s: other-organization fetch must stay blocked", name)
			}
		}
	}
}
