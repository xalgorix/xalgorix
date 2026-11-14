package reporting

import (
	"strings"
	"testing"
)

func TestEnsureCurlPoC_AddsCurlForHTTPGet(t *testing.T) {
	args := map[string]string{"method": "GET"}
	ensureCurlPoC(args, "https://app.example.com", "https://app.example.com/users?id=1")
	if got := args["poc_script_code"]; !strings.Contains(got, "curl -sk 'https://app.example.com/users?id=1'") {
		t.Fatalf("expected a GET curl for the endpoint, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_NonGetGetsMethodAndBody(t *testing.T) {
	args := map[string]string{"method": "POST"}
	ensureCurlPoC(args, "https://api.example.com", "POST https://api.example.com/graphql (mutation login)")
	got := args["poc_script_code"]
	if !strings.Contains(got, "-X POST 'https://api.example.com/graphql'") {
		t.Fatalf("expected a POST curl to the cleaned endpoint, got:\n%s", got)
	}
	if !strings.Contains(got, "--data") {
		t.Fatalf("expected a body placeholder for a non-GET request, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_KeepsAgentCurlUnchanged(t *testing.T) {
	const existing = "curl -sk 'https://x.example.com/y' -H 'X: 1'"
	args := map[string]string{"method": "GET", "poc_script_code": existing}
	ensureCurlPoC(args, "https://x.example.com", "https://x.example.com/y")
	if args["poc_script_code"] != existing {
		t.Fatalf("an existing curl PoC must be left untouched, got:\n%s", args["poc_script_code"])
	}
}

func TestEnsureCurlPoC_PrependsAboveNonCurlScript(t *testing.T) {
	args := map[string]string{"method": "GET", "poc_script_code": "import requests  # python PoC"}
	ensureCurlPoC(args, "https://x.example.com", "https://x.example.com/y")
	got := args["poc_script_code"]
	if !strings.Contains(got, "curl -sk 'https://x.example.com/y'") {
		t.Fatalf("expected a curl command added, got:\n%s", got)
	}
	if !strings.Contains(got, "import requests") {
		t.Fatalf("expected the existing script preserved below the curl, got:\n%s", got)
	}
	if strings.Index(got, "curl -sk") > strings.Index(got, "import requests") {
		t.Fatalf("curl should come before the kept script, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_SkipsNonHTTPFindings(t *testing.T) {
	cases := []struct{ name, target, endpoint string }{
		{"redis", "redis://db.example.com:6379", "redis://db.example.com:6379 — EVAL command"},
		{"code-review", "code://my-repo", ""},
		{"no-target", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]string{"method": "GET"}
			ensureCurlPoC(args, tc.target, tc.endpoint)
			if args["poc_script_code"] != "" {
				t.Fatalf("non-HTTP finding must not get a curl PoC, got:\n%s", args["poc_script_code"])
			}
		})
	}
}

func TestEnsureCurlPoC_BareHostPortSynthesizesScheme(t *testing.T) {
	args := map[string]string{"method": "GET"}
	ensureCurlPoC(args, "host.example.com:5000", "/cgi-bin/x")
	if got := args["poc_script_code"]; !strings.Contains(got, "curl -sk 'http://host.example.com:5000/cgi-bin/x'") {
		t.Fatalf("a bare host:port should synthesize an http scheme and join the path, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_RelativeEndpointJoinsHTTPSTarget(t *testing.T) {
	args := map[string]string{"method": "GET"}
	ensureCurlPoC(args, "https://app.example.com", "/admin/export")
	if got := args["poc_script_code"]; !strings.Contains(got, "curl -sk 'https://app.example.com/admin/export'") {
		t.Fatalf("a relative endpoint should join the https target origin, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_PreservesTraversalBytes(t *testing.T) {
	args := map[string]string{"method": "GET"}
	ensureCurlPoC(args, "https://app.example.com", "https://app.example.com/static/../../../etc/passwd")
	if got := args["poc_script_code"]; !strings.Contains(got, "/static/../../../etc/passwd") {
		t.Fatalf("literal ../ traversal bytes must be preserved, got:\n%s", got)
	}
}

func TestEnsureCurlPoC_QuotesSingleQuoteInURL(t *testing.T) {
	args := map[string]string{"method": "GET"}
	ensureCurlPoC(args, "https://app.example.com", "https://app.example.com/s?q='x")
	got := args["poc_script_code"]
	if !strings.Contains(got, `'\''`) {
		t.Fatalf("a single quote in the URL must be shell-escaped, got:\n%s", got)
	}
}
