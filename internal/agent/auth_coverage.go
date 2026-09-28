// Package agent — auth_coverage.go gives authentication/session testing an
// explicit, dimension-based completion contract. Previously a single generic
// access-control signal (a request to /admin, an X-Original-URL probe)
// completed the whole auth-session task via reconcilePlan, while genuinely
// untested dimensions (token expiry, password reset, logout invalidation,
// failed-login rate limiting) were invisible. Dimensions are now inferred
// from the observed surface (only applicable ones are required), completed by
// engine-detected evidence, and dispositioned typed — the model can no longer
// clear the lane with vague prose, and a missing surface marks its dimension
// N/A automatically.
package agent

import (
	"sort"
	"strings"
)

// Auth dimension identifiers (Part 10).
const (
	authDimLoginBaseline   = "login_baseline"
	authDimAuthBypass      = "auth_bypass"
	authDimSessionIdentity = "session_identity"
	authDimSessionFixation = "session_fixation"
	authDimLogout          = "logout_invalidation"
	authDimTokenIdentity   = "token_identity"
	authDimTokenExpiry     = "token_expiry"
	authDimRefreshToken    = "refresh_token"
	authDimPasswordReset   = "password_reset"
	authDimMFA             = "mfa_or_otp"
	authDimRegistration    = "registration"
	authDimLoginRateLimit  = "failed_login_rate_limit"
	authDimCookieControls  = "cookie_controls"
)

// applicableAuthDimensions returns the auth dimensions the OBSERVED surface
// makes testable, keyed by dimension. Dimensions whose surface feature is
// absent are omitted — they are never required.
func applicableAuthDimensions(state *ScanState) map[string]bool {
	dims := make(map[string]bool)
	if state == nil {
		return dims
	}
	hasLogin, hasLogout, hasReset, hasRegister, hasMFA := false, false, false, false, false
	for _, ep := range state.DiscoveredEndpoints {
		lower := strings.ToLower(ep)
		switch {
		case strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "sign-in"):
			hasLogin = true
		case strings.Contains(lower, "logout") || strings.Contains(lower, "signout"):
			hasLogout = true
		case strings.Contains(lower, "reset") && strings.Contains(lower, "password"), strings.Contains(lower, "forgot-password"):
			hasReset = true
		case strings.Contains(lower, "register") || strings.Contains(lower, "signup") || strings.Contains(lower, "sign-up"):
			hasRegister = true
		case strings.Contains(lower, "mfa") || strings.Contains(lower, "otp") || strings.Contains(lower, "2fa"):
			hasMFA = true
		}
	}
	if hasLogin {
		dims[authDimLoginBaseline] = true
		dims[authDimAuthBypass] = true
		dims[authDimLoginRateLimit] = true
	}
	if hasLogout {
		dims[authDimLogout] = true
	}
	if hasReset {
		dims[authDimPasswordReset] = true
	}
	if hasRegister {
		dims[authDimRegistration] = true
	}
	if hasMFA {
		dims[authDimMFA] = true
	}
	if state.BearerAuthObserved {
		dims[authDimTokenIdentity] = true
		dims[authDimTokenExpiry] = true
	}
	if state.CookieAuthObserved {
		dims[authDimSessionIdentity] = true
		dims[authDimSessionFixation] = true
		dims[authDimCookieControls] = true
	}
	return dims
}

// sortedAuthDimensions returns applicable dimensions in deterministic order.
func sortedAuthDimensions(state *ScanState) []string {
	dims := applicableAuthDimensions(state)
	out := make([]string, 0, len(dims))
	for d := range dims {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// markAuthDimensionComplete records engine-detected evidence for one auth
// dimension. Evidence beats dispositions: a re-observed signal always marks
// the dimension complete.
func markAuthDimensionComplete(state *ScanState, dim string) {
	if state == nil || dim == "" {
		return
	}
	if state.AuthCoverage == nil {
		state.AuthCoverage = make(map[string]string)
	}
	state.AuthCoverage[dim] = "complete"
}

// applyAuthDispositions parses typed per-dimension dispositions from an
// update_plan note on the auth-session task, e.g.:
//
//	"token_identity: blocked_missing_second_identity - two accounts needed"
//	"session_fixation: not_applicable - no pre-auth session cookies"
//
// Returns the applied dispositions for the tool-result echo.
func applyAuthDispositions(state *ScanState, notes string) []string {
	if state == nil || strings.TrimSpace(notes) == "" {
		return nil
	}
	var applied []string
	for _, rawLine := range strings.FieldsFunc(notes, func(r rune) bool { return r == '\n' || r == ';' }) {
		line := strings.TrimSpace(rawLine)
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		dim := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.ToLower(strings.TrimSpace(line[colon+1:]))
		if !applicableAuthDimensions(state)[dim] && state.AuthCoverage[dim] == "" {
			continue // unknown or not-yet-applicable dimension
		}
		status := ""
		switch {
		case strings.Contains(value, "not_applicable"), strings.Contains(value, "n/a"):
			status = "not_applicable"
		case strings.Contains(value, "blocked"):
			status = "blocked"
		default:
			continue // not a disposition line
		}
		if state.AuthCoverage == nil {
			state.AuthCoverage = make(map[string]string)
		}
		state.AuthCoverage[dim] = status
		applied = append(applied, dim+": "+status)
	}
	sort.Strings(applied)
	return applied
}

// authTaskComplete is the engine-owned completion contract for the
// auth-session task: every APPLICABLE dimension must be settled (engine-
// detected evidence, typed N/A, or typed blocked). Dimensions whose surface
// feature was never observed are not applicable and never block.
func authTaskComplete(state *ScanState) bool {
	if state == nil {
		return false
	}
	if !authSurfaceExists(state) && !state.AuthContextAvailable {
		// No auth surface at all: the lane is vacuously complete (the
		// reconcile auto-disposition handles the skip bookkeeping).
		return true
	}
	for _, dim := range sortedAuthDimensions(state) {
		switch state.AuthCoverage[dim] {
		case "complete", "not_applicable", "blocked":
			continue
		default:
			return false
		}
	}
	return true
}

// authPendingDimensions lists applicable-but-unsettled dimensions, for
// plan-brief nudges and telemetry.
func authPendingDimensions(state *ScanState) []string {
	var pending []string
	for _, dim := range sortedAuthDimensions(state) {
		switch state.AuthCoverage[dim] {
		case "complete", "not_applicable", "blocked":
		default:
			pending = append(pending, dim)
		}
	}
	return pending
}

// ── hookAuthCoverageTracker ──────────────────────────────────────────────────
// OnToolResult: detects concrete per-dimension auth evidence from request
// text and response output. Only class-specific activity marks a dimension —
// a generic request to /admin touches nothing.
func hookAuthCoverageTracker(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.ReconOnlyMode {
		return HookResult{}
	}
	toolName := args["tool_name"]
	switch toolName {
	case "terminal_execute", "python_action", "http_request", "send_request", "browser_action", "authz_matrix":
	default:
		return HookResult{}
	}
	requestText := strings.ToLower(joinedToolArgs(args))
	output := strings.ToLower(args["output"])
	requestAndOutput := requestText + "\n" + output

	if strings.Contains(requestText, "bearer ") || strings.Contains(requestText, "jwt") {
		state.BearerAuthObserved = true
	}
	if strings.Contains(requestText, "cookie:") || strings.Contains(output, "set-cookie") {
		state.CookieAuthObserved = true
	}

	// Auth-surface requests.
	authTarget := false
	for key, value := range args {
		if key == "output" || key == "error" {
			continue
		}
		if containsAnyKeyword(value, authPathKeywords) {
			authTarget = true
			break
		}
	}
	if authTarget {
		markAuthDimensionComplete(state, authDimLoginBaseline)
	}
	if strings.Contains(requestText, "exp=") || strings.Contains(requestText, `"exp":`) ||
		strings.Contains(requestText, "expired") || strings.Contains(requestText, "expiry") {
		markAuthDimensionComplete(state, authDimTokenExpiry)
	}
	if strings.Contains(requestAndOutput, "refresh_token") || strings.Contains(requestAndOutput, "refresh token") {
		markAuthDimensionComplete(state, authDimRefreshToken)
	}
	if (strings.Contains(requestText, "reset") || strings.Contains(requestText, "forgot")) && strings.Contains(requestText, "password") {
		markAuthDimensionComplete(state, authDimPasswordReset)
	}
	if strings.Contains(requestText, "register") || strings.Contains(requestText, "signup") || strings.Contains(requestText, "sign-up") {
		markAuthDimensionComplete(state, authDimRegistration)
	}
	if strings.Contains(requestText, "logout") || strings.Contains(requestText, "signout") {
		markAuthDimensionComplete(state, authDimLogout)
	}
	if strings.Contains(requestText, "mfa") || strings.Contains(requestText, "otp") || strings.Contains(requestText, "2fa") {
		markAuthDimensionComplete(state, authDimMFA)
	}
	if authTarget && (strings.Contains(output, "429") || strings.Contains(output, "too many") ||
		strings.Contains(output, "rate limit") || strings.Contains(output, "locked out") ||
		strings.Contains(output, "too many requests")) {
		markAuthDimensionComplete(state, authDimLoginRateLimit)
	}
	if strings.Contains(output, "set-cookie") && (strings.Contains(output, "httponly") ||
		strings.Contains(output, "samesite") || strings.Contains(output, "secure")) {
		markAuthDimensionComplete(state, authDimCookieControls)
	}
	return HookResult{}
}
