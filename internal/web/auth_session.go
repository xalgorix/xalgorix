package web

import (
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// authSessions stores valid session tokens (token → expiry)
var (
	authSessions      = make(map[string]time.Time)
	authSessionsMu    sync.RWMutex
	sessionReaperOnce sync.Once
)

const sessionCookieName = "xalgorix_session"
const sessionDuration = 24 * time.Hour
const sessionReaperInterval = 15 * time.Minute

// generateSessionToken creates a cryptographically random session token.
// 32 bytes of crypto/rand is already overwhelmingly sufficient entropy —
// hashing it wouldn't add security and only obscured the source.
// Returns an error if the system entropy source is unavailable instead of
// terminating the whole process — callers should surface a 500 to the user.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// loginAttempts tracks failed-login backoff per source IP. We replaced the
// unconditional time.Sleep(1s) on every failure because it held an HTTP
// connection open and let an attacker tie up worker goroutines with one IP.
// Instead, we reject further attempts from an IP that has racked up too many
// failures within a short window; legitimate users on a clean IP see no
// latency hit.
var (
	loginAttempts   = make(map[string]*loginAttempt)
	loginAttemptsMu sync.Mutex
)

type loginAttempt struct {
	failures  int
	firstFail time.Time
	lockUntil time.Time
}

// Login-limiter defaults. Every threshold is operator-tunable via env (see
// loginRateLimitDisabled / loginEnvMinutes / loginEnvInt), and
// XALGORIX_LOGIN_RATE_LIMIT=off disables the limiter entirely.
const (
	defaultLoginWindow   = 15 * time.Minute
	defaultLoginMaxFails = 10
	defaultLoginLockFor  = 5 * time.Minute
)

// loginRateLimitDisabled reports whether the per-IP login limiter is fully
// disabled via XALGORIX_LOGIN_RATE_LIMIT=off (accepted spellings: off,
// disabled, false, 0, no). Intended for deployments where the login endpoint
// is not reachable from the public internet (the scanner sits behind a
// network-level allowlist or a reverse-proxy gate), or where a pooled
// reverse-proxy IP can otherwise accumulate unrelated clients' failures and
// lock out legitimate automation. Settings are read per attempt, so
// configuration changes apply on the next login without a restart.
func loginRateLimitDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XALGORIX_LOGIN_RATE_LIMIT"))) {
	case "off", "disabled", "false", "0", "no":
		return true
	}
	return false
}

// loginEnvMinutes reads a positive integer minutes value from env with a
// default; missing, unparseable, or non-positive values fall back to the
// default rather than disabling the limiter by accident.
func loginEnvMinutes(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Minute
}

// loginEnvInt reads a positive integer from env with a default; missing,
// unparseable, or non-positive values fall back to the default.
func loginEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// loginIsLocked returns (locked, retryAfterSeconds). It also garbage-collects
// stale entries opportunistically so the map cannot grow unbounded.
func loginIsLocked(ip string) (bool, int) {
	if loginRateLimitDisabled() {
		return false, 0
	}
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	window := loginEnvMinutes("XALGORIX_LOGIN_WINDOW_MINUTES", defaultLoginWindow)
	// Opportunistic GC — bounded work, runs only when this IP is queried.
	for k, v := range loginAttempts {
		if now.Sub(v.firstFail) > window && now.After(v.lockUntil) {
			delete(loginAttempts, k)
		}
	}
	a := loginAttempts[ip]
	if a == nil {
		return false, 0
	}
	if now.Before(a.lockUntil) {
		return true, int(a.lockUntil.Sub(now).Seconds()) + 1
	}
	return false, 0
}

// loginRecordFailure increments the failure counter for an IP. After
// XALGORIX_LOGIN_MAX_FAILURES (default 10) within
// XALGORIX_LOGIN_WINDOW_MINUTES (default 15), subsequent attempts are locked
// out for XALGORIX_LOGIN_LOCKOUT_MINUTES (default 5). With
// XALGORIX_LOGIN_RATE_LIMIT=off nothing is recorded at all.
func loginRecordFailure(ip string) {
	if loginRateLimitDisabled() {
		return
	}
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	window := loginEnvMinutes("XALGORIX_LOGIN_WINDOW_MINUTES", defaultLoginWindow)
	a := loginAttempts[ip]
	if a == nil || now.Sub(a.firstFail) > window {
		loginAttempts[ip] = &loginAttempt{failures: 1, firstFail: now}
		return
	}
	a.failures++
	if a.failures >= loginEnvInt("XALGORIX_LOGIN_MAX_FAILURES", defaultLoginMaxFails) {
		a.lockUntil = now.Add(loginEnvMinutes("XALGORIX_LOGIN_LOCKOUT_MINUTES", defaultLoginLockFor))
	}
}

// loginRecordSuccess clears any failure history on a successful login.
func loginRecordSuccess(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, ip)
}

// clientIP extracts a comparable client identifier from the request. We
// intentionally do not trust X-Forwarded-For; if you put xalgorix behind a
// reverse proxy you should bind it to loopback and let the proxy enforce
// auth, or extend this helper to honor a configured trusted-proxy list.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isValidSession checks if a session token is valid and not expired
func isValidSession(token string) bool {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	expiry, ok := authSessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(authSessions, token)
		return false
	}
	return true
}

// startSessionReaper sweeps expired session tokens on a fixed interval so the
// authSessions map cannot grow unbounded from abandoned cookies. Runs once
// per process.
func startSessionReaper() {
	sessionReaperOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(sessionReaperInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				authSessionsMu.Lock()
				for tok, expiry := range authSessions {
					if now.After(expiry) {
						delete(authSessions, tok)
					}
				}
				authSessionsMu.Unlock()
			}
		}()
	})
}

// isCSRFSafe returns true when a state-changing request is verifiably
// originated from this site. We use Origin (and Referer as a fallback)
// because every modern browser sends one of them on POST/PUT/PATCH/DELETE.
// SameSite=Strict on the session cookie already blocks the most common CSRF
// vectors; this is defense in depth for the Sec-Fetch-Site and
// document-form-submit edge cases.
//
// Policy:
//   - Safe methods (GET/HEAD/OPTIONS) are always allowed.
//   - Sec-Fetch-Site: same-origin/none → allow; same-site/cross-site → deny.
//   - Else fall back to Origin/Referer host == r.Host.
//   - If none of the above are present AND the request carries our session
//     cookie, the request looks like a browser navigation without the
//     metadata we expected — refuse. Cookie-less non-browser clients
//     (curl, scripts) are still allowed; an attacker has no way to forge
//     a cookie on the victim, so allowing cookie-less requests is safe.
func isCSRFSafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	// Browser hint: only "same-origin"/"none" are safe.
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "":
		// fall through to Origin/Referer checks
	case "same-origin", "none":
		return true
	default:
		// "same-site" or "cross-site" — refuse.
		return false
	}

	// Compare Origin/Referer host with request Host.
	check := func(raw string) (bool, bool) {
		if raw == "" {
			return false, false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false, true
		}
		return u.Host == r.Host, true
	}

	if ok, present := check(r.Header.Get("Origin")); present {
		return ok
	}
	if ok, present := check(r.Header.Get("Referer")); present {
		return ok
	}

	// Neither Origin nor Referer nor Sec-Fetch-Site present.
	// If the client carries our session cookie this is suspicious (a real
	// browser strips none of these on cookie-bearing POSTs in 2026) —
	// refuse. Cookie-less requests are non-browser tooling, allow.
	if _, err := r.Cookie(sessionCookieName); err == nil {
		return false
	}
	return true
}

// authConfigured returns true when the server has any authentication
// configured: dashboard credentials (username + password/hash) for human
// logins, OR at least one machine API token. A token-only configuration is a
// valid headless deployment (API access via Bearer; the dashboard cannot be
// logged into because no human credentials exist). When nothing is
// configured, the authMiddleware short-circuits and serves all routes — used
// by the bind-time safety check to refuse external interfaces without auth.
func authConfigured(cfg *config.Config) bool {
	if cfg.Username != "" && (cfg.Password != "" || cfg.PasswordHash != "") {
		return true
	}
	return len(apiTokenHashes(cfg.APITokens)) > 0
}

// authMiddleware protects routes when auth is configured. Two independent
// authentication flows pass through here:
//
//   - human: POST /api/auth/login + username/password -> xalgorix_session
//     cookie, with browser CSRF checks and the per-IP login rate limiter;
//   - machine: Authorization: Bearer <API token> -> direct API access with no
//     session, no CSRF requirement (browsers never auto-attach bearer
//     headers, so a forged cross-site request cannot carry one), no
//     dashboard-page authorization, and no interaction with the login
//     limiter.
//
// The flows do not fall back into each other: a presented-but-invalid bearer
// token is machine traffic (browsers never send Authorization), so it gets a
// clean 401 instead of silently continuing through the cookie path.
func authMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Machine tokens are immutable for the process lifetime — hash them
		// once at middleware creation, never per request.
		tokenHashes := apiTokenHashes(cfg.APITokens)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// ── Machine-to-machine authentication ──
			switch classifyMachineAuth(r, tokenHashes) {
			case machineAuthValid:
				if isMachineAPIPath(path) && machineTokenPathAllowed(path) {
					// Valid service token on an authorized API route: serve
					// directly. This skips the browser CSRF check on purpose
					// — CSRF protects cookie-based browser sessions; a bearer
					// credential is not auto-attached by browsers and a
					// valid token never needs the login limiter or a session.
					next.ServeHTTP(w, r)
					return
				}
				// Valid token, but the route is not authorized for machine
				// clients (dashboard pages or operator-only APIs): fall
				// through to the standard session flow. A service token can
				// never silently authorize the dashboard.
			case machineAuthInvalid:
				// A presented credential that matches no configured token:
				// fail loudly with a generic 401. Never fall back to cookie
				// auth (that would let a stale token hide behind a browser
				// session), never log the token, never touch the human login
				// failure counters.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Invalid API token",
				})
				return
			}

			// CSRF: validate state-changing requests on /api/* regardless of
			// whether auth is configured. This blocks an attacker page from
			// triggering a scan via the cookie even when no password is set
			// for local-loopback deployments.
			if strings.HasPrefix(path, "/api/") && path != "/api/auth/login" {
				if !isCSRFSafe(r) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "CSRF check failed: request origin does not match server host",
					})
					return
				}
			}

			// Skip auth if no credentials configured
			if !authConfigured(cfg) {
				next.ServeHTTP(w, r)
				return
			}

			// Public routes that don't need auth. The React SPA owns the
			// operator login screen, so its static assets must be reachable
			// before a session exists.
			if path == "/api/auth/login" || path == "/api/auth/status" ||
				isStaticWebAssetPath(path) || strings.HasPrefix(path, "/uploads/") {
				next.ServeHTTP(w, r)
				return
			}

			// Check for session cookie
			cookie, err := r.Cookie(sessionCookieName)
			if err == nil && isValidSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}

			// For API requests, return 401 JSON
			if strings.HasPrefix(path, "/api/") || path == "/ws" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication required",
				})
				return
			}

			// For page requests, serve the SPA shell. The client-side router
			// will show the React login page after /api/auth/status reports
			// that there is no active session.
			next.ServeHTTP(w, r)
		})
	}
}

// verifyPassword checks a presented password against the configured credential.
// Prefers a bcrypt hash (PasswordHash) when set; falls back to a constant-time
// plaintext comparison for backwards compatibility. The plaintext path logs a
// one-time deprecation warning so operators know to migrate.
var plaintextPasswordWarnOnce sync.Once

func (s *Server) verifyPassword(presented string) bool {
	if s.cfg.PasswordHash != "" {
		// bcrypt.CompareHashAndPassword is constant-time wrt password length
		// for matching hashes and is the recommended verification path.
		err := bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordHash), []byte(presented))
		return err == nil
	}
	if s.cfg.Password == "" {
		return false
	}
	plaintextPasswordWarnOnce.Do(func() {
		log.Printf("[auth] WARNING: XALGORIX_PASSWORD is set in plaintext. Migrate to XALGORIX_PASSWORD_HASH (bcrypt) — see README.")
	})
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Password)) == 1
}

// handleLogin handles POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	ip := clientIP(r)

	// Per-IP lockout — replaces the old unconditional 1s sleep so we don't
	// occupy goroutines on attacker traffic.
	if locked, retryAfter := loginIsLocked(ip); locked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Too many failed attempts. Try again in %ds.", retryAfter),
		})
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Constant-time username comparison; bcrypt for password. We always
	// run the password compare even on a username miss so the work
	// performed is independent of which side is wrong (timing-equalized).
	userMatch := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(s.cfg.Username)) == 1
	passMatch := s.verifyPassword(creds.Password)
	if !userMatch || !passMatch {
		loginRecordFailure(ip)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	loginRecordSuccess(ip)

	// Create session
	token, err := generateSessionToken()
	if err != nil {
		log.Printf("[auth] session token generation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal error generating session"})
		return
	}
	authSessionsMu.Lock()
	authSessions[token] = time.Now().Add(sessionDuration)
	authSessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	})

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// isSecureRequest returns true if the request is over TLS. Used to decide
// whether to set the Secure flag on cookies — required for HTTPS deploys,
// must be off for localhost HTTP development.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Honor an X-Forwarded-Proto header only when running behind a trusted
	// proxy; we keep it simple here and trust nothing by default. Operators
	// behind a TLS-terminating proxy should set the cookie's Secure flag
	// elsewhere if they need it.
	return false
}

// handleLogout handles POST /api/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		authSessionsMu.Lock()
		delete(authSessions, cookie.Value)
		authSessionsMu.Unlock()
	}

	// Match the attributes of the cookie we set on login so browsers
	// consistently replace/clear it. Without SameSite and Secure here,
	// some browsers treat the deletion cookie as a different cookie and
	// the original stays in the jar.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

// handleAuthStatus handles GET /api/auth/status
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authEnabled := authConfigured(s.cfg)

	authenticated := false
	if authEnabled {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && isValidSession(cookie.Value) {
			authenticated = true
		}
	} else {
		authenticated = true // No auth configured = always authenticated
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth_enabled":  authEnabled,
		"authenticated": authenticated,
	})
}
