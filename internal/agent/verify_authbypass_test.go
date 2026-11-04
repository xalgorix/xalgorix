package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

func TestAuthBypassVariants(t *testing.T) {
	got := authBypassVariants("/api/admin/users")
	gotSet := map[string]bool{}
	for _, v := range got {
		if gotSet[v] {
			t.Fatalf("duplicate variant %q in %v", v, got)
		}
		gotSet[v] = true
		if v == "/api/admin/users" {
			t.Fatalf("variant list must not include the canonical path: %v", got)
		}
	}
	for _, want := range []string{
		"/API/admin/users", "/Api/admin/users", "/apI/admin/users",
		"/api/admin/users/", "/api/admin/users/..;/", "/api/admin/users%2f",
	} {
		if !gotSet[want] {
			t.Errorf("expected variant %q, got %v", want, got)
		}
	}
	if len(authBypassVariants("")) != 0 || len(authBypassVariants("/")) != 0 {
		t.Fatal("empty or root path must yield no variants")
	}
}

func TestBaselineIsDenied(t *testing.T) {
	mk := func(code int, loc string) *rawResp {
		h := http.Header{}
		if loc != "" {
			h.Set("Location", loc)
		}
		return &rawResp{code, h}
	}
	for _, tc := range []struct {
		name string
		resp *rawResp
		want bool
	}{
		{"401", mk(401, ""), true},
		{"403", mk(403, ""), true},
		{"302 to login", mk(302, "https://t/login?next=/x"), true},
		{"302 elsewhere", mk(302, "https://t/home"), false},
		{"200 public", mk(200, ""), false},
		{"404", mk(404, ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := baselineIsDenied(tc.resp.toRaw())
			if got != tc.want {
				t.Fatalf("baselineIsDenied(%d)=%v, want %v", tc.resp.code, got, tc.want)
			}
		})
	}
}

func TestAuthBypassVerdict(t *testing.T) {
	denied := rawWith(403, "Forbidden: authentication required")
	const shell = "<html><body>app shell goes here for every route</body></html>"
	for _, tc := range []struct {
		name     string
		variant  *httpRaw
		catchAll string
		want     bool
	}{
		{"served, divergent body", rawWith(200, `{"users":[{"id":1},{"id":2}]}`), "", true},
		{"served, same body as denial", rawWith(200, "Forbidden: authentication required"), "", false},
		{"still denied", rawWith(403, "Forbidden: authentication required"), "", false},
		{"served but empty", rawWith(200, ""), "", false},
		{"served, 3xx not 2xx", rawWith(302, "somewhere else entirely here"), "", false},
		{"served but matches catch-all shell", rawWith(200, shell), normalizeBodyForDiff(shell), false},
		{"served, diverges from catch-all", rawWith(200, `{"secret":"data here now"}`), normalizeBodyForDiff(shell), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authBypassVerdict(denied, tc.variant, tc.catchAll); got != tc.want {
				t.Fatalf("authBypassVerdict=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestBodyLooksSensitive(t *testing.T) {
	if !bodyLooksSensitive(`{"email":"a@b.com","role":"admin"}`) {
		t.Fatal("expected sensitive body to be flagged")
	}
	if bodyLooksSensitive(`<html>Internal dashboard: all systems nominal</html>`) {
		t.Fatal("benign body must not be flagged")
	}
}

// TestVerifyAuthBypassConfirmsCaseVariant exercises the full oracle: the
// canonical route is denied unauthenticated, a case-variant mount reaches the
// handler unauthenticated with a divergent (non-sensitive) body → medium.
func TestVerifyAuthBypassConfirmsCaseVariant(t *testing.T) {
	var sawVariant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/api/admin":
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "Forbidden: authentication required to reach this resource")
		case strings.EqualFold(p, "/api/admin"):
			sawVariant = p
			_, _ = fmt.Fprint(w, "<html><body>Internal dashboard: 5 services running, status OK</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/admin"})
	if err != nil || result.Error != "" || result.Metadata["authbypass_confirmed"] != true {
		t.Fatalf("expected confirmed bypass, result=%+v err=%v", result, err)
	}
	if sawVariant == "" || strings.EqualFold(sawVariant, "/api/admin") == false || sawVariant == "/api/admin" {
		t.Fatalf("server did not see a case-variant request, saw %q", sawVariant)
	}
	if result.Metadata["severity"] != "medium" {
		t.Fatalf("non-sensitive served body should be medium, got %v", result.Metadata["severity"])
	}
	for _, want := range []string{"CWE-288", "verification_method=exploited", "severity=medium"} {
		if !strings.Contains(result.Output, want) {
			t.Fatalf("confirmation output missing %q: %s", want, result.Output)
		}
	}
	id, _ := result.Metadata["hypothesis_id"].(string)
	h, ok := ag.scanCtx.Ledger.Get(id)
	if !ok || h.VulnClass != "auth-bypass" || h.Status != scanctx.HypothesisProven {
		t.Fatalf("ledger hypothesis not proven auth-bypass: %+v", h)
	}
	ev := lastEvidence(h)
	if ev.Kind != "exploit" || ev.Source != "verify_authbypass" || !ev.EngineExploit() ||
		!strings.Contains(ev.Summary, "CONFIRMED") {
		t.Fatalf("missing engine-authored exploit evidence: %+v", ev)
	}
}

func TestVerifyAuthBypassEscalatesOnSensitiveBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/api/users":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, "Unauthorized: a valid session is required for this endpoint")
		case strings.EqualFold(p, "/api/users"):
			_, _ = fmt.Fprint(w, `{"users":[{"email":"admin@corp.example","role":"admin"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/users"})
	if err != nil || result.Error != "" || result.Metadata["authbypass_confirmed"] != true {
		t.Fatalf("expected confirmed bypass, result=%+v err=%v", result, err)
	}
	if result.Metadata["severity"] != "high" || !strings.Contains(result.Output, "severity=high") {
		t.Fatalf("sensitive served body should escalate to high, got %v / %s", result.Metadata["severity"], result.Output)
	}
}

func TestVerifyAuthBypassCanonicalNotProtected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "public content for everyone")
	}))
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/public"})
	if err != nil || result.Error != "" || result.Metadata["authbypass_confirmed"] != false ||
		result.Metadata["reason"] != "canonical_not_protected" {
		t.Fatalf("a public canonical path must not confirm: result=%+v err=%v", result, err)
	}
}

func TestVerifyAuthBypassEnforcementHolds(t *testing.T) {
	reqs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "Forbidden: authentication required to reach this resource")
	}))
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/admin"})
	if err != nil || result.Error != "" || result.Metadata["authbypass_confirmed"] != false ||
		result.Metadata["reason"] != "enforcement_holds" {
		t.Fatalf("consistent denial must not confirm: result=%+v err=%v", result, err)
	}
	if reqs < 2 {
		t.Fatalf("expected a baseline plus variant probes, saw %d requests", reqs)
	}
}

// TestVerifyAuthBypassIgnoresCatchAll guards against the SPA/soft-404 false
// positive: the canonical route is denied, but the host serves the same 200
// app shell for every other path — including nonexistent ones — so no variant
// is a real bypass.
func TestVerifyAuthBypassIgnoresCatchAll(t *testing.T) {
	const shell = "<html><body>single-page app shell rendered for any route here</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "Forbidden: authentication required to reach this resource")
			return
		}
		_, _ = fmt.Fprint(w, shell)
	}))
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/admin"})
	if err != nil || result.Error != "" || result.Metadata["authbypass_confirmed"] != false {
		t.Fatalf("catch-all 200 shell must not be reported as a bypass: result=%+v err=%v", result, err)
	}
}

func TestVerifyAuthBypassPassiveAndScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	passive := newProbeAgent(t, srv.URL, true)
	passive.scanIntensity = "passive"
	if res, _ := passive.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/admin"}); res.Error == "" ||
		!strings.Contains(res.Error, "passive") {
		t.Fatalf("passive mode must disable the live oracle, got %+v", res)
	}

	blocked := newProbeAgent(t, srv.URL, false)
	if res, _ := blocked.verifyAuthBypassTool(map[string]string{"url": srv.URL + "/api/admin"}); res.Error == "" {
		t.Fatalf("out-of-scope loopback must be refused, got %+v", res)
	}
}

// --- small response shims so the pure-function tests don't need a live server ---

type httpRaw = httpclient.RawResponse

func rawWith(code int, body string) *httpRaw {
	return &httpRaw{StatusCode: code, Body: []byte(body), BodyLen: len(body)}
}

type rawResp struct {
	code int
	hdr  http.Header
}

func (r *rawResp) toRaw() *httpRaw {
	return &httpRaw{StatusCode: r.code, Header: r.hdr}
}
