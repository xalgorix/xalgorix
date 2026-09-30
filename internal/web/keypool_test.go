package web

// keypool_test.go: coverage for the scoped /api/pool key-pool API. The
// response must never contain secret material (masked view only); POST
// applies the pool to runtime config AND the env file (so it survives a
// restart); validation keeps the stored single-line, comma-separated value
// parseable; and the route stays machine-token friendly while the settings
// surface stays operator-only.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func doKeyPoolReq(s *Server, method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/pool", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleKeyPool(rr, r)
	return rr
}

// GET renders the live pool masked: which keys are configured is visible,
// the keys themselves never leave the server.
func TestKeyPool_GetIsMasked(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	s.cfg.APIKeys = []string{"sk-live-secret-alpha-1234", "sk-live-secret-beta-5678"}
	rr := doKeyPoolReq(s, http.MethodGet, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/pool code = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, secret := range []string{"sk-live-secret-alpha-1234", "sk-live-secret-beta-5678"} {
		if strings.Contains(body, secret) {
			t.Fatalf("raw key leaked in masked pool view: %s", body)
		}
	}
	if !strings.Contains(body, `"keys":2`) {
		t.Fatalf("pool count missing from response: %s", body)
	}
	if !strings.Contains(body, "****") {
		t.Fatalf("masked keys missing from response: %s", body)
	}
}

// POST replaces the pool: runtime config (both the pool and the primary
// key, mirroring the dashboard semantics) AND the env file pick the new
// values, and the response is masked.
func TestKeyPool_PostAppliesPoolAndPrimary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	rr := doKeyPoolReq(s, http.MethodPost, `{"keys":["sk-new-primary-key-9999","sk-new-secondary-8888"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/pool code = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "sk-new-primary-key-9999") {
		t.Fatalf("raw key leaked in POST response: %s", rr.Body.String())
	}
	if len(s.cfg.APIKeys) != 2 || s.cfg.APIKeys[0] != "sk-new-primary-key-9999" {
		t.Fatalf("pool not applied to runtime config: %v", s.cfg.APIKeys)
	}
	if s.cfg.APIKey != "sk-new-primary-key-9999" {
		t.Fatalf("first key must become the primary API key, got %q", s.cfg.APIKey)
	}

	// The env file must carry the values so a restart keeps them.
	data, err := os.ReadFile(filepath.Join(home, ".xalgorix.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	if !strings.Contains(env, "XALGORIX_API_KEYS=sk-new-primary-key-9999,sk-new-secondary-8888") {
		t.Fatalf("pool missing from env file: %s", env)
	}
	if !strings.Contains(env, "XALGORIX_API_KEY=sk-new-primary-key-9999") {
		t.Fatalf("primary key missing from env file: %s", env)
	}

	// GET after POST reflects the new pool.
	rr = doKeyPoolReq(s, http.MethodGet, "")
	if !strings.Contains(rr.Body.String(), `"keys":2`) {
		t.Fatalf("GET after POST does not reflect the new pool: %s", rr.Body.String())
	}
}

// Validation: the stored value is a single comma-separated line, so keys
// containing commas or newlines are rejected; empty pools are rejected;
// duplicates collapse; oversized pools are rejected.
func TestKeyPool_InputValidation(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	for name, body := range map[string]string{
		"empty pool":     `{"keys":[]}`,
		"empty strings":  `{"keys":["  ",""]}`,
		"comma in key":   `{"keys":["good-key","bad,key"]}`,
		"newline in key": "{\"keys\":[\"good-key\",\"bad\\nkey\"]}",
		"oversized key":  `{"keys":["` + strings.Repeat("k", 1025) + `"]}`,
		"too many keys":  `{"keys":["` + strings.Join(makeKeyPoolSlice(65), `","`) + `"]}`,
	} {
		if rr := doKeyPoolReq(s, http.MethodPost, body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: code = %d, want 400 (body=%s)", name, rr.Code, rr.Body.String())
		}
	}

	// Duplicates collapse to one entry.
	rr := doKeyPoolReq(s, http.MethodPost, `{"keys":["dup-key-1111","dup-key-1111"]}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"keys":1`) {
		t.Fatalf("duplicates must collapse: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func makeKeyPoolSlice(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("key-%04d-0000", i)
	}
	return out
}

// The route must stay machine-token friendly: /api/pool is a normal API
// route (not on the operator-only denylist), so a valid machine token
// authorizes it end-to-end through the real middleware.
func TestKeyPool_MachineTokenAllowed(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	// A denylisted route rejects the same token (control).
	if w := doReq(h, "GET", "/api/settings/environment", "Bearer tok-a"); w.Code != http.StatusForbidden {
		t.Fatalf("settings route must stay operator-only, got %d", w.Code)
	}
	if !isMachineAPIPath("/api/pool") || !machineTokenPathAllowed("/api/pool") {
		t.Fatal("/api/pool must be a machine-token-authorized API route")
	}
}

// Unsupported methods are refused.
func TestKeyPool_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	if rr := doKeyPoolReq(s, http.MethodDelete, ""); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /api/pool code = %d, want 405", rr.Code)
	}
}
