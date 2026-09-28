package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// ── Authentication coverage (Part 21 cases 21-24) ────────────────────────────

// Case 21: generic /admin probing must not complete auth/session coverage.
func TestAuthCoverage_AdminProbingDoesNotCompleteAuth(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"example.com/login", "example.com/admin/dashboard"}
	state.BearerAuthObserved = true

	// Generic access-control activity: an /admin probe with method swap.
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -X PUT -d "role=admin" https://example.com/admin/dashboard`,
	})
	if !state.AccessControlTested {
		t.Fatal("setup: expected the /admin probe to count as access-control activity")
	}

	state.Plan = AutoPlan(state.DiscoveredEndpoints, nil)
	reconcilePlan(state)
	task := state.Plan.Get("auth-session")
	if task == nil {
		t.Fatal("expected an auth-session task")
		return
	}
	if task.Status == TaskCompleted {
		t.Fatal("generic /admin access-control probing must not complete auth/session testing")
	}
	if got := authPendingDimensions(state); len(got) == 0 {
		t.Fatal("auth dimensions (login baseline, token identity/expiry) should still be pending")
	}
}

// Case 22: JWT expiry is tracked independently of other token dimensions.
func TestAuthCoverage_JWTExpiryIndependent(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.com/login"}
	state.BearerAuthObserved = true

	// Only token_expiry evidence observed.
	hookAuthCoverageTracker(state, map[string]string{
		"tool_name": "http_request",
		"method":    "POST",
		"url":       "https://example.com/login",
		"body":      `{"token":"eyJ...","exp":1234567890}`,
		"output":    `401 expired token`,
	})
	if state.AuthCoverage[authDimTokenExpiry] != "complete" {
		t.Fatalf("JWT expiry evidence must mark token_expiry complete, got %q", state.AuthCoverage[authDimTokenExpiry])
	}
	if state.AuthCoverage[authDimTokenIdentity] == "complete" {
		t.Fatal("token_identity must remain independently tracked (expiry evidence is not identity evidence)")
	}
	if authTaskComplete(state) {
		t.Fatal("auth task must not complete while token_identity is pending")
	}
}

// Case 23: password-reset N/A is representable when no reset surface exists.
func TestAuthCoverage_PasswordResetNotApplicable(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.com/login"} // no reset route
	if applicableAuthDimensions(state)[authDimPasswordReset] {
		t.Fatal("no reset surface means the dimension is not applicable")
	}
	// When a reset surface exists, the dimension activates and can be
	// dispositioned.
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "example.com/password-reset")
	if !applicableAuthDimensions(state)[authDimPasswordReset] {
		t.Fatal("reset route must activate password_reset")
	}
	applyAuthDispositions(state, "password_reset: not_applicable - reset flow disabled by the operator")
	if state.AuthCoverage[authDimPasswordReset] != "not_applicable" {
		t.Fatalf("typed N/A must be representable, got %q", state.AuthCoverage[authDimPasswordReset])
	}
}

// Case 24: second-account-only tests can become blocked without completing
// unrelated auth work.
func TestAuthCoverage_SecondAccountBlockedIsolation(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.com/login"}
	state.BearerAuthObserved = true
	// Only one identity available: token_identity requires two.
	applyAuthDispositions(state, "token_identity: blocked - only one account was supplied; cross-identity proof requires a second legitimate user")
	if state.AuthCoverage[authDimTokenIdentity] != "blocked" {
		t.Fatalf("token_identity must be blocked, got %q", state.AuthCoverage[authDimTokenIdentity])
	}
	if state.AuthCoverage[authDimTokenExpiry] == "blocked" || state.AuthCoverage[authDimTokenExpiry] == "not_applicable" {
		t.Fatal("blocking one dimension must not settle unrelated dimensions")
	}
	if authTaskComplete(state) {
		t.Fatal("blocked token_identity must not complete the whole auth lane while expiry is still pending")
	}
	// Settle the rest with real evidence: the login request (baseline +
	// bearer observation) and an expiry-tampering probe.
	hookAuthCoverageTracker(state, map[string]string{
		"tool_name": "http_request",
		"url":       "https://example.com/login",
		"method":    "POST",
		"body":      `{"user":"a","password":"x"}`,
		"output":    "200 OK",
	})
	hookAuthCoverageTracker(state, map[string]string{
		"tool_name": "http_request",
		"url":       "https://example.com/api/profile",
		"method":    "GET",
		"headers":   "Authorization: Bearer eyJ... (expired token, exp in the past)",
		"body":      `{"exp": 1000000000}`,
		"output":    "401 expired",
	})
	markAuthDimensionComplete(state, authDimAuthBypass)
	markAuthDimensionComplete(state, authDimLoginRateLimit)
	if !authTaskComplete(state) {
		pending := authPendingDimensions(state)
		t.Fatalf("all applicable dimensions settled (blocked counts as settled), still pending: %v", pending)
	}
}

// ── Recon (Part 21 cases 26-30) ───────────────────────────────────────────────

// Case 26: typed N/A dispositions actually mutate NAMarked.
func TestReconNA_MarkedTypedDimensions(t *testing.T) {
	state := NewScanState()
	if state.ReconCoverage.NAMarked["service_discovery"] {
		t.Fatal("setup: dimension must start pending")
	}
	applied := applyReconDispositions(state, "service_discovery: raw IP target, no ports beyond HTTP\nwayback: static target, no historical content expected")
	if len(applied) != 2 {
		t.Fatalf("expected 2 applied dispositions, got %v", applied)
	}
	if !state.ReconCoverage.NAMarked["service_discovery"] || !state.ReconCoverage.NAMarked["historical"] {
		t.Fatal("typed dispositions must set NAMarked")
	}
	if MarkReconDimensionNA(state, "made-up-dimension-xyz") {
		t.Fatal("unknown dimension names must be rejected")
	}
}

// Case 27: content discovery on host A does not complete host B.
func TestReconPerHost_DiscoveryDoesNotLeakAcrossHosts(t *testing.T) {
	state := NewScanState()
	state.EndpointInventorySaved = true
	state.ReconDone = true
	state.ReconCoverage.HTTPProbed = true
	state.ReconCoverage.TechFingerprinted = true
	state.ReconCoverage.Crawled = true
	state.ReconCoverage.APISurfaceDiscovered = true
	state.ReconCoverage.ContentDiscoveredHosts["app.example.com"] = true
	state.DirBustingDone = true
	state.DetectedTechs["flask"] = true
	state.ScanDepth = "standard"
	state.DiscoveredEndpoints = []string{
		"app.example.com/dashboard",
		"api.example.com/v1/users",
		"admin.example.com/panel",
	}
	a := &Agent{state: state}
	missing := a.reconIncompleteReasons()
	foundHostB := false
	for _, m := range missing {
		if strings.Contains(m, "api.example.com") {
			foundHostB = true
		}
	}
	if !foundHostB {
		t.Fatalf("content discovery on app.example.com must not satisfy api.example.com, missing=%v", missing)
	}
	// Typed disposition clears it.
	applyReconDispositions(state, "host api.example.com: covered_by_equivalent\nhost admin.example.com: blocked - WAF blocks enumeration")
	missing = a.reconIncompleteReasons()
	for _, m := range missing {
		if strings.Contains(m, "api.example.com") || strings.Contains(m, "admin.example.com") {
			t.Fatalf("dispositioned hosts must not be demanded, got %q", m)
		}
	}
}

// Cases 28-30: surface signals make the matching recon dimensions applicable.
func TestReconApplicability_SignalDrivenRequirements(t *testing.T) {
	state := NewScanState()
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"example.com/api/users", "example.com/login"}
	if !apiSignalsExist(state) {
		t.Fatal("an /api/ inventory must set API signals")
	}
	if !authSurfaceExists(state) {
		t.Fatal("a /login inventory must set auth signals")
	}
	state.ObservedEndpointMethods["example.com/api/users"] = "POST"
	if !parameterizedSurfaceExists(state) {
		t.Fatal("an observed POST must set parameterized signals")
	}
	a := &Agent{state: state}
	missing := a.reconIncompleteReasons()
	assertAny(t, missing, "API-surface")
	assertAny(t, missing, "auth surface")
	assertAny(t, missing, "parameter/input discovery")
	// Dispositions clear the demands.
	applyReconDispositions(state, "api_surface: no documentation or introspection surface\nauth_mapping: anonymous-only target\nparameter_discovery: no parameterized endpoints")
	missing = a.reconIncompleteReasons()
	for _, m := range missing {
		for _, banned := range []string{"API-surface", "auth mapping", "parameter/input"} {
			if strings.Contains(m, banned) {
				t.Fatalf("N/A dimension must not be demanded anymore, got %q", m)
			}
		}
	}
}

func assertAny(t *testing.T, list []string, want string) {
	t.Helper()
	for _, x := range list {
		if strings.Contains(x, want) {
			return
		}
	}
	t.Fatalf("expected an entry containing %q in %v", want, list)
}

// ── Typed dispositions (Part 21 cases 31-32) ────────────────────────────────

func newUpdatePlanTestAgent(t *testing.T, state *ScanState) *Agent {
	t.Helper()
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	return &Agent{state: state}
}

// Case 31: a vague skip reason cannot clear an engine-owned required task.
func TestTypedDispositions_VagueReasonRejected(t *testing.T) {
	state := surfaceState([]string{"example.com/search", "example.com/api/users"}, nil, nil)
	a := newUpdatePlanTestAgent(t, state)

	for _, vagueNote := range []string{
		"probably not applicable",
		"likely not vulnerable",
		"nothing interesting found there",
		"already found another bug so skipping",
	} {
		result, err := a.updatePlanTool(map[string]string{
			"task_id": "test-sqli", "status": "skipped", "notes": vagueNote,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Error == "" {
			t.Fatalf("vague reason %q must be rejected for engine-owned coverage tasks", vagueNote)
		}
	}
	task := state.Plan.Get("test-sqli")
	if task.Status != TaskPending {
		t.Fatalf("vague skip must not clear the task, got %s", task.Status)
	}
}

// Case 32: a valid typed N/A can clear a genuinely irrelevant task.
func TestTypedDispositions_ValidNAAccepted(t *testing.T) {
	// Static-only surface: no class-bearing endpoints at all.
	state := surfaceState([]string{"example.com/robots.txt"}, nil, nil)
	a := newUpdatePlanTestAgent(t, state)

	result, err := a.updatePlanTool(map[string]string{
		"task_id": "test-xxe", "status": "not_applicable",
		"notes": "no XML or SOAP input surface exists on this target",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("engine-confirmed N/A must be accepted, got: %s", result.Error)
	}
	task := state.Plan.Get("test-xxe")
	if task.Status != TaskSkipped || task.Disposition != DispositionNotApplicable {
		t.Fatalf("task must be skipped with typed disposition, got %s/%s", task.Status, task.Disposition)
	}
}

// ── Completion (Part 21 cases 33-37) ─────────────────────────────────────────

// Case 33: unresolved applicable work blocks successful completion.
func TestCompletion_UnresolvedWorkIsIncomplete(t *testing.T) {
	state := NewScanState()
	state.Plan = AutoPlan([]string{"example.com/search"}, nil)
	status, reasons := scanCompletionAssessment(state)
	if status != CompletionStatusIncomplete {
		t.Fatalf("pending plan tasks must make the scan incomplete, got %s", status)
	}
	assertAny(t, reasons, "test-sqli")
}

// Case 34: repeated finish attempts yield INCOMPLETE, never false-success.
func TestCompletion_FinishGateExhaustionIsIncomplete(t *testing.T) {
	state := NewScanState()
	state.Plan = AutoPlan([]string{"example.com/search"}, nil)
	state.FinishAttempts = 16 // beyond the default rejection ceiling
	// Settle everything except the exhaustion itself.
	for _, task := range state.Plan.Tasks {
		if task.ID != "verify" && task.ID != "report" {
			task.Status = TaskCompleted
		}
	}
	status, reasons := scanCompletionAssessment(state)
	if status != CompletionStatusIncomplete {
		t.Fatalf("gate exhaustion must read incomplete, got %s", status)
	}
	assertAny(t, reasons, "finish_gate_exhausted")
	banner := formatIncompleteSummary(status, reasons)
	if !strings.Contains(banner, "NOT fully tested") {
		t.Fatalf("the incomplete banner must never read as a full assessment: %q", banner)
	}
}

// Case 35: incomplete scans preserve the remaining work for resume.
func TestCompletion_RemainingWorkPreserved(t *testing.T) {
	state := NewScanState()
	state.Plan = AutoPlan([]string{"example.com/search"}, nil)
	status, reasons := scanCompletionAssessment(state)
	// The plan object itself is untouched...
	task := state.Plan.Get("test-ssti")
	if task == nil || task.Status != TaskPending {
		t.Fatal("the plan must retain its remaining tasks for resume")
	}
	// ...and the reasons name them.
	assertAny(t, reasons, "test-ssti")
	_ = status
}

// Cases 36-37: testing and proven-unreported hypotheses keep the scan
// incomplete and are named in the reasons.
func TestCompletion_LedgerWorkNamed(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.Plan = AutoPlan([]string{"example.com/search"}, nil)
	for _, task := range state.Plan.Tasks {
		if task.ID != "verify" && task.ID != "report" {
			task.Status = TaskCompleted
		}
	}
	state.FinishAttempts = 1

	h := ctx.Ledger.Upsert(scanctx.Hypothesis{Title: "busy", VulnClass: "sqli", Endpoint: "/search", Status: scanctx.HypothesisTesting, AssignedTo: "agent-x"})
	if h.ID == "" {
		t.Fatal("insert failed")
	}
	p := ctx.Ledger.Upsert(scanctx.Hypothesis{Title: "proven", VulnClass: "xss", Endpoint: "/search", Status: scanctx.HypothesisProven})
	if p.ID == "" {
		t.Fatal("insert failed")
	}

	// The ledger finish gate blocks while attempts are bounded...
	gate := hookLedgerFinishGate(state, nil)
	if !gate.Block {
		t.Fatal("the ledger gate must block with testing + proven-unreported work")
	}
	// ...and even after the gate gives up, the completion assessment stays
	// honest.
	state.FinishAttempts = 99
	status, reasons := scanCompletionAssessment(state)
	if status != CompletionStatusIncomplete {
		t.Fatalf("unclosed/proven-unreported hypotheses must keep the scan incomplete, got %s", status)
	}
	assertAny(t, reasons, "claimed but not closed")
	assertAny(t, reasons, "proven but unreported")
}

// Blocked-only work completes honestly with the distinct blocked status.
func TestCompletion_BlockedWorkIsDistinctStatus(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.Plan = AutoPlan([]string{"example.com/search"}, nil)
	for _, task := range state.Plan.Tasks {
		if task.ID != "verify" && task.ID != "report" {
			task.Status = TaskCompleted
		}
	}
	ctx.Ledger.Upsert(scanctx.Hypothesis{Title: "stuck", VulnClass: "idor", Endpoint: "/search", Status: scanctx.HypothesisBlocked})
	status, reasons := scanCompletionAssessment(state)
	if status != CompletionStatusCompletedWithBlocked {
		t.Fatalf("blocked-only work must read completed_with_blocked_work, got %s (reasons %v)", status, reasons)
	}
}
