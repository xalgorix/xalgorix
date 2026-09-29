package web

// auth_session_test.go: coverage for the env-configurable login limiter.
// The limiter map is package-global, so every test uses its own unique IP
// and clears it before finishing.

import (
	"net/http"
	"testing"
)

// Defaults: 10 failures within 15 minutes lock the IP; success clears.
func TestLoginLimiter_DefaultsLockOutAfterThreshold(t *testing.T) {
	ip := "203.0.113.10"
	loginRecordSuccess(ip)
	for i := 0; i < 10; i++ {
		loginRecordFailure(ip)
	}
	locked, retry := loginIsLocked(ip)
	if !locked || retry <= 0 {
		t.Fatalf("10 failures within the window must lock the IP, got locked=%v retry=%d", locked, retry)
	}
	loginRecordSuccess(ip)
	if locked, _ := loginIsLocked(ip); locked {
		t.Fatal("a successful login must clear the failure history")
	}
}

// Thresholds are env-tunable: MAX_FAILURES=2 + LOCKOUT_MINUTES=1.
func TestLoginLimiter_EnvTunableThresholds(t *testing.T) {
	t.Setenv("XALGORIX_LOGIN_MAX_FAILURES", "2")
	t.Setenv("XALGORIX_LOGIN_LOCKOUT_MINUTES", "1")
	ip := "203.0.113.11"
	loginRecordSuccess(ip)
	loginRecordFailure(ip)
	if locked, _ := loginIsLocked(ip); locked {
		t.Fatal("one failure must not lock even with a lowered threshold")
	}
	loginRecordFailure(ip)
	locked, retry := loginIsLocked(ip)
	if !locked {
		t.Fatal("two failures must lock with XALGORIX_LOGIN_MAX_FAILURES=2")
	}
	if retry > 61 {
		t.Fatalf("lockout must respect XALGORIX_LOGIN_LOCKOUT_MINUTES=1, got %ds", retry)
	}
	loginRecordSuccess(ip)
}

// XALGORIX_LOGIN_RATE_LIMIT=off disables the limiter entirely: no lockouts
// regardless of failure volume.
func TestLoginLimiter_DisabledViaEnvNeverLocks(t *testing.T) {
	t.Setenv("XALGORIX_LOGIN_RATE_LIMIT", "off")
	ip := "203.0.113.12"
	for i := 0; i < 100; i++ {
		loginRecordFailure(ip)
	}
	if locked, retry := loginIsLocked(ip); locked || retry != 0 {
		t.Fatalf("XALGORIX_LOGIN_RATE_LIMIT=off must disable the limiter, got locked=%v retry=%d", locked, retry)
	}
}

// While disabled, failures are not recorded at all — re-enabling the limiter
// later starts from a clean slate.
func TestLoginLimiter_DisabledDoesNotRecordFailures(t *testing.T) {
	t.Setenv("XALGORIX_LOGIN_RATE_LIMIT", "off")
	ip := "203.0.113.13"
	loginRecordFailure(ip)
	loginRecordFailure(ip)
	loginAttemptsMu.Lock()
	recorded := loginAttempts[ip] != nil
	loginAttemptsMu.Unlock()
	if recorded {
		t.Fatal("a disabled limiter must not record failure state")
	}
	t.Setenv("XALGORIX_LOGIN_RATE_LIMIT", "")
	if locked, _ := loginIsLocked(ip); locked {
		t.Fatal("failures recorded while disabled must not lock after re-enabling")
	}
	loginRecordSuccess(ip)
}

// Invalid or non-positive env values fall back to the defaults instead of
// silently disabling the limiter.
func TestLoginLimiter_InvalidEnvFallsBack(t *testing.T) {
	t.Setenv("XALGORIX_LOGIN_MAX_FAILURES", "not-a-number")
	t.Setenv("XALGORIX_LOGIN_WINDOW_MINUTES", "-5")
	ip := "203.0.113.14"
	loginRecordSuccess(ip)
	for i := 0; i < 10; i++ {
		loginRecordFailure(ip)
	}
	if locked, _ := loginIsLocked(ip); !locked {
		t.Fatal("invalid env values must fall back to the default threshold of 10")
	}
	loginRecordSuccess(ip)
}

// clientIP must never trust X-Forwarded-For — behind a reverse proxy the
// forwarded header is client-controlled; the limiter keys on the peer IP.
func TestClientIP_IgnoresForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "198.51.100.7:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP must not trust X-Forwarded-For, got %q", got)
	}
}
