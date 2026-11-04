package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestResolveInjectionPoint(t *testing.T) {
	ip, err := resolveInjectionPoint(map[string]string{})
	if err != nil || ip.location != "query" || ip.bodyType != "json" {
		t.Fatalf("defaults should be query/json, got %+v err=%v", ip, err)
	}
	if ip, err := resolveInjectionPoint(map[string]string{"inject_in": "body", "body_type": "form"}); err != nil ||
		ip.location != "body" || ip.bodyType != "form" {
		t.Fatalf("body/form not honored: %+v err=%v", ip, err)
	}
	if _, err := resolveInjectionPoint(map[string]string{"inject_in": "cookie"}); err == nil {
		t.Fatal("invalid inject_in must error")
	}
	if _, err := resolveInjectionPoint(map[string]string{"inject_in": "body", "body_type": "xml"}); err == nil {
		t.Fatal("invalid body_type must error")
	}
}

func TestInjectionPointDefaultMethod(t *testing.T) {
	q := injectionPoint{location: "query"}
	b := injectionPoint{location: "body"}
	cases := []struct {
		ip   injectionPoint
		in   string
		want string
	}{
		{q, "", "GET"},
		{q, "post", "POST"},
		{b, "", "POST"},
		{b, "GET", "POST"},
		{b, "put", "PUT"},
	}
	for _, c := range cases {
		if got := c.ip.defaultMethod(c.in); got != c.want {
			t.Errorf("defaultMethod(%s,%q)=%q want %q", c.ip.location, c.in, got, c.want)
		}
	}
}

func TestInjectionPointBuildRequest(t *testing.T) {
	u, _ := url.Parse("https://t.example/api/x")

	// query
	q := injectionPoint{location: "query"}
	reqURL, body, ct, err := q.buildRequest(u, "id", "1'")
	if err != nil || body != "" || ct != "" || !strings.Contains(reqURL, "id=1%27") {
		t.Fatalf("query build wrong: url=%q body=%q ct=%q err=%v", reqURL, body, ct, err)
	}

	// json with sibling fields
	j := injectionPoint{location: "body", bodyType: "json", baseBody: `{"email":"a@b.c"}`}
	_, body, ct, err = j.buildRequest(u, "id", "1'")
	if err != nil || ct != "application/json" {
		t.Fatalf("json build wrong: ct=%q err=%v", ct, err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil || m["id"] != "1'" || m["email"] != "a@b.c" {
		t.Fatalf("json body did not merge the injected field with siblings: %q (%v)", body, err)
	}

	// form
	f := injectionPoint{location: "body", bodyType: "form", baseBody: "email=a%40b.c"}
	_, body, ct, err = f.buildRequest(u, "id", "1'")
	if err != nil || ct != "application/x-www-form-urlencoded" {
		t.Fatalf("form build wrong: ct=%q err=%v", ct, err)
	}
	vals, _ := url.ParseQuery(body)
	if vals.Get("id") != "1'" || vals.Get("email") != "a@b.c" {
		t.Fatalf("form body did not carry both fields: %q", body)
	}

	// invalid base_body
	if _, _, _, err := (injectionPoint{location: "body", bodyType: "json", baseBody: "not json"}).buildRequest(u, "id", "x"); err == nil {
		t.Fatal("invalid JSON base_body must error")
	}
}

// TestVerifySQLiBodyInjection confirms error-based SQLi through a JSON body field:
// the server errors when the field value carries an odd number of quotes.
func TestVerifySQLiBodyInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		q, _ := m["q"].(string)
		if strings.Count(q, "'")%2 == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "You have an error in your SQL syntax; check the manual near ''")
			return
		}
		_, _ = fmt.Fprint(w, `{"rows":0}`)
	}))
	defer srv.Close()

	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifySQLiTool(map[string]string{
		"url": srv.URL + "/api/search", "parameter": "q", "inject_in": "body",
	})
	if err != nil || result.Error != "" || result.Metadata["sqli_confirmed"] != true {
		t.Fatalf("expected body-injection SQLi confirmation, result=%+v err=%v", result, err)
	}
	id, _ := result.Metadata["hypothesis_id"].(string)
	h, ok := ag.scanCtx.Ledger.Get(id)
	if !ok || h.VulnClass != "sqli" || h.Status != scanctx.HypothesisProven {
		t.Fatalf("ledger hypothesis not proven sqli: %+v", h)
	}
	if ev := lastEvidence(h); ev.Source != "verify_sqli" || !strings.Contains(ev.Request, "body:") {
		t.Fatalf("evidence should record a body request from the engine: %+v", ev)
	}
}

// TestVerifySSTIBodyInjection confirms SSTI through a JSON body field that the
// server renders, evaluating {{a*b}} to its product.
func TestVerifySSTIBodyInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		tpl, _ := m["tpl"].(string)
		var a, b int
		if _, scanErr := fmt.Sscanf(tpl, "{{%d*%d}}", &a, &b); scanErr == nil {
			_, _ = fmt.Fprintf(w, "<h1>%d</h1>", a*b)
			return
		}
		_, _ = fmt.Fprintf(w, "<h1>%s</h1>", tpl)
	}))
	defer srv.Close()

	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifySSTITool(map[string]string{
		"url": srv.URL + "/render", "parameter": "tpl", "inject_in": "body",
	})
	if err != nil || result.Error != "" || result.Metadata["ssti_confirmed"] != true {
		t.Fatalf("expected body-injection SSTI confirmation, result=%+v err=%v", result, err)
	}
}
