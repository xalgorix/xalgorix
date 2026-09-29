package web

// api_token_test.go: coverage for machine-to-machine API-token authentication.
// The machine flow must be independent of the human dashboard flow: bearer
// tokens authenticate API routes without sessions, CSRF, or the login limiter;
// presented-but-invalid tokens fail loudly without cookie fallback; the
// dashboard password flow keeps every existing protection.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// resetAuthStateForTest clears the package-global session and login-limiter
// state so assertions about "no sessions/failures exist" are not polluted by
// other tests in the package.
func resetAuthStateForTest() {
	authSessionsMu.Lock()
	authSessions = make(map[string]time.Time)
	authSessionsMu.Unlock()
	loginAttemptsMu.Lock()
	loginAttempts = make(map[string]*loginAttempt)
	loginAttemptsMu.Unlock()
}

// machineAuthHarness wraps a minimal handler with authMiddleware and the
// given configuration.
func machineAuthHarness(cfg *config.Config) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return authMiddleware(cfg)(h)
}

func apiTokenCfg(tokens ...string) *config.Config {
	return &config.Config{Username: "admin", Password: "secret", APITokens: tokens}
}

func doReq(h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Spec 3: a valid scanner API token authenticates an API route.
func TestMachineToken_ValidTokenAccepted(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	if w := doReq(h, "GET", "/api/version", "Bearer tok-a"); w.Code != http.StatusOK {
		t.Fatalf("valid machine token must authenticate API routes, got %d: %s", w.Code, w.Body.String())
	}
	// Case-insensitive scheme per RFC 7235.
	if w := doReq(h, "GET", "/api/version", "bearer tok-a"); w.Code != http.StatusOK {
		t.Fatalf("lowercase bearer scheme must authenticate, got %d", w.Code)
	}
}

// Spec 4: an invalid scanner API token is rejected — never a cookie fallback.
func TestMachineToken_InvalidTokenRejected(t *testing.T) {
	cfg := apiTokenCfg("tok-a")
	h := machineAuthHarness(cfg)
	for _, auth := range []string{"Bearer wrong", "Bearer ", "Bearer", "Basic tok-a", "wrong-token-directly"} {
		if w := doReq(h, "GET", "/api/version", auth); w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid presentation %q must be rejected with 401, got %d", auth, w.Code)
		}
	}
	// RFC 7235 permits 1*SP between scheme and credentials: extra whitespace
	// is normalized, not rejected.
	if w := doReq(h, "GET", "/api/version", "Bearer  tok-a"); w.Code != http.StatusOK {
		t.Fatalf("extra whitespace after the scheme is RFC-permitted, got %d", w.Code)
	}
	// Empty-token edge: a configured empty token must never match.
	h2 := machineAuthHarness(apiTokenCfg(""))
	if w := doReq(h2, "GET", "/api/version", "Bearer "); w.Code != http.StatusUnauthorized {
		t.Fatalf("an empty configured token must authenticate nothing, got %d", w.Code)
	}
}

// Spec 7: service API authentication never increments the human login
// failure counters, and 401s from bad tokens do not lock the login endpoint.
func TestMachineToken_DoesNotTouchLoginLimiter(t *testing.T) {
	resetAuthStateForTest()
	cfg := apiTokenCfg("tok-a")
	h := machineAuthHarness(cfg)
	for i := 0; i < 25; i++ {
		if w := doReq(h, "GET", "/api/version", "Bearer wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid token attempt %d: expected 401, got %d", i, w.Code)
		}
	}
	loginAttemptsMu.Lock()
	n := len(loginAttempts)
	loginAttemptsMu.Unlock()
	if n != 0 {
		t.Fatalf("machine-auth rejections must not record human login failures, recorded %d", n)
	}
	if locked, _ := loginIsLocked("192.0.2.9"); locked {
		t.Fatal("the human login endpoint must not be locked by machine-auth failures")
	}
}

// Spec 8: machine authentication must not create dashboard session cookies.
func TestMachineToken_NoSessionCookieIssued(t *testing.T) {
	resetAuthStateForTest()
	cfg := apiTokenCfg("tok-a")
	s := newTestServer(t, cfg)
	// Wire the login + status handlers through the real middleware stack.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	h := authMiddleware(cfg)(mux)
	w := doReq(h, "GET", "/api/version", "Bearer tok-a")
	if w.Code != http.StatusOK {
		t.Fatalf("valid token must reach the API, got %d", w.Code)
	}
	if set := w.Header().Get("Set-Cookie"); set != "" {
		t.Fatalf("machine authentication must not issue session cookies, got %q", set)
	}
	authSessionsMu.Lock()
	n := len(authSessions)
	authSessionsMu.Unlock()
	if n != 0 {
		t.Fatalf("machine authentication must not create sessions, created %d", n)
	}
}

// Spec 9: machine-authenticated API calls are not blocked by browser CSRF
// (a POST with no Origin/Referer and no Sec-Fetch-Site is allowed).
func TestMachineToken_BearerRequestsSkipCSRFButCookiesKeepIt(t *testing.T) {
	cfg := apiTokenCfg("tok-a")
	h := machineAuthHarness(cfg)

	// Bearer-authenticated POST with no origin metadata: allowed.
	if w := doReq(h, "POST", "/api/scan", "Bearer tok-a"); w.Code != http.StatusOK {
		t.Fatalf("bearer-authenticated POST must not be CSRF-blocked, got %d: %s", w.Code, w.Body.String())
	}

	// Spec 10: a cookie-authenticated POST without origin metadata IS blocked.
	s := newTestServer(t, cfg)
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.10:1234"
	wrec := httptest.NewRecorder()
	s.handleLogin(wrec, r)
	if wrec.Code != http.StatusOK {
		t.Fatalf("setup: login must succeed, got %d: %s", wrec.Code, wrec.Body.String())
	}
	cookieLine := wrec.Header().Get("Set-Cookie")
	if cookieLine == "" {
		t.Fatal("setup: login must set a session cookie")
	}
	cookieValue := strings.SplitN(cookieLine, ";", 2)[0]

	r2 := httptest.NewRequest("POST", "/api/scan", nil)
	r2.Header.Set("Cookie", cookieValue)
	// No Origin/Referer/Sec-Fetch-Site: a cookie-bearing state-changing
	// request without browser metadata must be refused.
	wrec2 := httptest.NewRecorder()
	h.ServeHTTP(wrec2, r2)
	if wrec2.Code != http.StatusForbidden {
		t.Fatalf("cookie-authenticated POST without origin metadata must be CSRF-blocked, got %d", wrec2.Code)
	}

	// With an Origin header matching the host, the cookie flow works.
	r3 := httptest.NewRequest("POST", "/api/scan", nil)
	r3.Host = "scanner.example.test"
	r3.Header.Set("Cookie", cookieValue)
	r3.Header.Set("Origin", "http://scanner.example.test")
	wrec3 := httptest.NewRecorder()
	h.ServeHTTP(wrec3, r3)
	if wrec3.Code != http.StatusOK {
		t.Fatalf("cookie-authenticated POST with matching Origin must pass, got %d", wrec3.Code)
	}
}

// The machine token must not authorize operator-only routes (settings, LLM
// auth profiles, chat) even though it is valid.
func TestMachineToken_OperatorRoutesDenied(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	for _, path := range []string{
		"/api/settings/llm",
		"/api/settings/environment",
		"/api/auth/profiles",
		"/api/auth/profiles/api-key",
		"/api/chat",
	} {
		if w := doReq(h, "GET", path, "Bearer tok-a"); w.Code != http.StatusUnauthorized {
			t.Fatalf("machine token must not authorize operator-only route %s, got %d", path, w.Code)
		}
	}
}

// The machine token must not grant anything extra on non-API (dashboard
// page) routes. In production the SPA shell is public for everyone; the value
// behind the dashboard is the API data, which the token DOES authenticate on
// authorized routes. So the required property is: a valid token on a page
// route behaves identically to no token — it neither bypasses the session
// check nor creates one.
func TestMachineToken_DoesNotAuthorizeDashboardPages(t *testing.T) {
	resetAuthStateForTest()
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	withToken := doReq(h, "GET", "/admin", "Bearer tok-a")
	withoutToken := doReq(h, "GET", "/admin", "")
	if withToken.Code != withoutToken.Code || withToken.Body.String() != withoutToken.Body.String() {
		t.Fatalf(
			"a machine token must not change page-route behavior (token: %d/%q, without: %d/%q)",
			withToken.Code, withToken.Body.String(), withoutToken.Code, withoutToken.Body.String(),
		)
	}
	authSessionsMu.Lock()
	n := len(authSessions)
	authSessionsMu.Unlock()
	if n != 0 {
		t.Fatalf("a page-route token must not create a session, created %d", n)
	}
	// Contrast: on an authorized API route the token DOES authenticate.
	if w := doReq(h, "GET", "/api/version", "Bearer tok-a"); w.Code != http.StatusOK {
		t.Fatalf("contrast: the same token must authenticate API routes, got %d", w.Code)
	}
}

// The WebSocket endpoint accepts machine tokens like other API routes.
func TestMachineToken_WebSocketAllowed(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	if w := doReq(h, "GET", "/ws", "Bearer tok-a"); w.Code != http.StatusOK {
		t.Fatalf("machine token must authenticate the scan-event WebSocket, got %d", w.Code)
	}
}

// Multiple tokens (rotation): every configured token authenticates.
func TestMachineToken_MultipleTokensAccepted(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-old", "tok-new"))
	for _, tok := range []string{"tok-old", "tok-new"} {
		if w := doReq(h, "GET", "/api/version", "Bearer "+tok); w.Code != http.StatusOK {
			t.Fatalf("rotated token %q must authenticate", tok)
		}
	}
}

// Spec 16: with no machine tokens configured, a bearer request never
// authenticates (backward-compatible local installs keep exact old behavior).
func TestMachineToken_UnconfiguredBearerRejected(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg())
	if w := doReq(h, "GET", "/api/version", "Bearer anything"); w.Code != http.StatusUnauthorized {
		t.Fatalf("with no tokens configured a bearer header must be rejected, got %d", w.Code)
	}
}

// Spec 5 + 6: the browser session flow keeps working, and the login rate
// limiter keeps protecting it (also proven in auth_session_test.go).
func TestMachineToken_BrowserFlowUnchanged(t *testing.T) {
	resetAuthStateForTest()
	cfg := apiTokenCfg("tok-a")
	s := newTestServer(t, cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	h := authMiddleware(cfg)(mux)

	// Bad dashboard password -> 401 (and the limiter still records it).
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"nope"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.20:9"
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("bad dashboard password must 401, got %d", w1.Code)
	}

	// Good dashboard password -> session cookie -> API access without bearer.
	r2 := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	r2.Header.Set("Content-Type", "application/json")
	r2.RemoteAddr = "192.0.2.20:9"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("dashboard login must succeed, got %d: %s", w2.Code, w2.Body.String())
	}
	var cookie string
	for _, c := range w2.Result().Cookies() {
		if c.Name == sessionCookieName {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("dashboard login must set the session cookie")
	}
	r3 := httptest.NewRequest("GET", "/api/version", nil)
	r3.Header.Set("Cookie", cookie)
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("session cookie must authenticate API routes, got %d", w3.Code)
	}

	// loginRecordSuccess cleared the failure bucket from the bad attempt.
	if locked, _ := loginIsLocked("192.0.2.20"); locked {
		t.Fatal("successful login must clear the failure history")
	}
}

// authConfigured: token-only configuration counts as authentication (headless
// API-only deployments can bind non-loopback), while nothing configured does
// not.
func TestAuthConfigured_TokenOnlyDeployment(t *testing.T) {
	if authConfigured(&config.Config{}) {
		t.Fatal("no credentials must mean auth not configured")
	}
	if !authConfigured(&config.Config{APITokens: []string{"tok"}}) {
		t.Fatal("a machine token alone must count as configured authentication")
	}
	if !authConfigured(&config.Config{Username: "u", PasswordHash: "h"}) {
		t.Fatal("dashboard credentials must count as configured authentication")
	}
	// Empty strings must never authenticate.
	if authConfigured(&config.Config{APITokens: []string{"", "  "}}) {
		t.Fatal("blank tokens must not count as configured authentication")
	}
}

// apiTokenHashes: trimming, dedup, and empty handling.
func TestAPITokenHashes_Normalization(t *testing.T) {
	hashes := apiTokenHashes([]string{" a ", "", "a", "b", "  "})
	if len(hashes) != 2 {
		t.Fatalf("expected trimmed dedup of 2 tokens, got %d", len(hashes))
	}
	if len(apiTokenHashes(nil)) != 0 {
		t.Fatal("nil tokens must produce no hashes")
	}
}

// bearerTokenFromRequest parsing edge cases.
func TestBearerTokenFromRequest_Parsing(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/version", nil)
	if _, ok := bearerTokenFromRequest(r); ok {
		t.Fatal("absent Authorization header must not parse")
	}
	for _, bad := range []string{"", "Bearer", "Bearer ", "bearer", "Basic abc", "BeareR"} {
		r.Header.Set("Authorization", bad)
		if _, ok := bearerTokenFromRequest(r); ok {
			t.Fatalf("malformed Authorization %q must not parse", bad)
		}
	}
	r.Header.Set("Authorization", "Bearer good-token")
	tok, ok := bearerTokenFromRequest(r)
	if !ok || tok != "good-token" {
		t.Fatalf("valid bearer header must parse, got %q ok=%v", tok, ok)
	}
}

// A 401 from invalid machine auth must carry a GENERIC error message and no
// token material.
func TestMachineToken_RejectionBodyIsGeneric(t *testing.T) {
	h := machineAuthHarness(apiTokenCfg("tok-a"))
	w := doReq(h, "GET", "/api/version", "Bearer secret-token-value")
	body := w.Body.String()
	if strings.Contains(body, "secret-token-value") {
		t.Fatal("the rejection body must never echo the presented token")
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil || parsed.Error != "Invalid API token" {
		t.Fatalf("rejection body must be a generic JSON error, got %q err=%v", parsed.Error, err)
	}
}
