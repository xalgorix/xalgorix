package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyErrorSignature(t *testing.T) {
	a := bodyErrorSignature(`{"code":34,"message":"email is required"}`)
	b := bodyErrorSignature(`{"code":34,"message":"email is required"}`)
	c := bodyErrorSignature(`{"code":12,"message":"name is required"}`)
	if a != b {
		t.Fatalf("identical JSON errors must share a signature: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different JSON errors must differ: %q == %q", a, c)
	}
	// Non-JSON falls back to a bounded normalized prefix.
	if got := bodyErrorSignature("  Bad   Request  "); got != "bad request" {
		t.Fatalf("non-JSON signature = %q", got)
	}
}

func TestIsWorse(t *testing.T) {
	cases := []struct {
		base, now int
		want      bool
	}{
		{201, 400, true}, {200, 422, true}, {400, 400, false}, {400, 200, false}, {201, 500, false},
	}
	for _, c := range cases {
		if got := isWorse(c.base, c.now); got != c.want {
			t.Errorf("isWorse(%d,%d)=%v want %v", c.base, c.now, got, c.want)
		}
	}
}

func TestMentionsHelpers(t *testing.T) {
	if !mentionsFieldRequirement(`{"error":"email is required"}`, "email") {
		t.Fatal("named + 'required' must read as a requirement")
	}
	if !mentionsFieldRequirement(`{"error":"missing mandatory field"}`, "zzz") {
		t.Fatal("generic required/missing wording counts even without the field name")
	}
	if !mentionsUnknownField(`{"error":"unknown field: id"}`, "id") {
		t.Fatal("named + 'unknown' must read as a rejected field")
	}
	if mentionsUnknownField(`{"error":"unknown field: id"}`, "email") {
		t.Fatal("a different field name must not match the unknown-field complaint")
	}
}

func TestCandidateFields(t *testing.T) {
	base := map[string]any{"email": "x", "id": 1}
	got := candidateFields("custom_field, email ,,custom_field", base)
	set := map[string]bool{}
	for _, g := range got {
		if set[g] {
			t.Fatalf("duplicate candidate %q", g)
		}
		set[g] = true
	}
	if !set["custom_field"] {
		t.Fatal("caller-supplied field missing")
	}
	if set["email"] || set["id"] {
		t.Fatal("candidates must exclude fields already in the base body")
	}
	if len(got) > 24 {
		t.Fatalf("candidate list must stay bounded, got %d", len(got))
	}
}

func TestTypeSwap(t *testing.T) {
	if _, ok := typeSwap("hello").(int); !ok {
		t.Fatal("a string value should swap to a number")
	}
	if _, ok := typeSwap(42.0).(string); !ok {
		t.Fatal("a non-string value should swap to a string")
	}
}

// contractServer models a strict "create" endpoint: it requires `email`, accepts
// only {email,name}, and names any other field as unknown.
func contractServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if _, ok := m["email"]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":34,"error":"email is required"}`))
			return
		}
		for k := range m {
			if k != "email" && k != "name" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"unknown field: ` + k + `"}`))
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
}

func TestProbeBodyContractClassifiesFields(t *testing.T) {
	srv := contractServer(t)
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.probeBodyContractTool(map[string]string{
		"url":       srv.URL + "/api/users",
		"method":    "POST",
		"seed_body": `{"email":"a@b.c","name":"n"}`,
	})
	if err != nil || result.Error != "" {
		t.Fatalf("probe failed: result=%+v err=%v", result, err)
	}
	has := func(key, want string) bool {
		xs, _ := result.Metadata[key].([]string)
		for _, x := range xs {
			if x == want {
				return true
			}
		}
		return false
	}
	if !has("required", "email") {
		t.Fatalf("email should be required: %+v", result.Metadata)
	}
	if has("required", "name") {
		t.Fatalf("name should not be required: %+v", result.Metadata)
	}
	if !has("rejected", "id") {
		t.Fatalf("a strict schema should reject unknown candidate 'id': %+v", result.Metadata)
	}
	if result.Metadata["baseline_status"] != 201 {
		t.Fatalf("baseline should be accepted (201), got %v", result.Metadata["baseline_status"])
	}
	if !strings.Contains(result.Output, "REQUIRED") || !strings.Contains(result.Output, "email is required") {
		t.Fatalf("output should surface the required field and the app's own error: %s", result.Output)
	}
}

func TestProbeBodyContractGuards(t *testing.T) {
	srv := contractServer(t)
	defer srv.Close()

	if res, _ := newProbeAgent(t, srv.URL, true).probeBodyContractTool(map[string]string{
		"url": srv.URL + "/api/users", "method": "GET",
	}); res.Error == "" || !strings.Contains(res.Error, "POST") {
		t.Fatalf("a non-body method must be rejected, got %+v", res)
	}

	passive := newProbeAgent(t, srv.URL, true)
	passive.scanIntensity = "passive"
	if res, _ := passive.probeBodyContractTool(map[string]string{"url": srv.URL + "/api/users"}); res.Error == "" ||
		!strings.Contains(res.Error, "passive") {
		t.Fatalf("passive mode must disable the probe, got %+v", res)
	}

	if res, _ := newProbeAgent(t, srv.URL, false).probeBodyContractTool(map[string]string{
		"url": srv.URL + "/api/users",
	}); res.Error == "" {
		t.Fatalf("out-of-scope loopback must be refused, got %+v", res)
	}

	if res, _ := newProbeAgent(t, srv.URL, true).probeBodyContractTool(map[string]string{
		"url": srv.URL + "/api/users", "seed_body": "not json",
	}); res.Error == "" || !strings.Contains(res.Error, "JSON object") {
		t.Fatalf("an invalid seed_body must be rejected, got %+v", res)
	}
}
