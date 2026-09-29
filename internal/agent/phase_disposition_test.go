package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// TestPlanGenerationFromStructuredSurface (Part 51): given a structured
// black-box surface (checkout workflow, multipart upload, GraphQL, a
// WebSocket URL, a WordPress fingerprint, and an S3 asset reference), the
// engine must create the correct obligations with the CORRECT canonical
// Task.Phase values — no more "everything is Phase 6".
func TestPlanGenerationFromStructuredSurface(t *testing.T) {
	state := richTestState()
	p := AutoPlanFromState(state)
	classes := taskClasses(p)

	wantPhase := map[string]int{
		"graphql":         9,
		"file-upload":     10,
		"business-logic":  12,
		"race-conditions": 12,
		"cloud-storage":   16,
		"cloud-config":    16,
		"websocket":       17,
		"cms-security":    18,
		"cors":            4,
		"cookie-security": 4,
		"open-redirect":   14,
		"novel-testing":   21,
	}
	for class, phase := range wantPhase {
		task, ok := classes[class]
		if !ok {
			t.Errorf("structured surface missing task for class %q (tasks: %v)", class, testPlanTaskIDs(p))
			continue
		}
		if task.Phase != phase {
			t.Errorf("task %q has Phase %d, want %d", class, task.Phase, phase)
		}
	}
	// Generic injection lanes still exist for the same surface — under their
	// canonical phase, not mislabeled.
	for _, class := range []string{"sqli", "xss"} {
		task, ok := classes[class]
		if !ok || task.Phase != 6 {
			t.Errorf("generic class %q must remain scheduled at phase 6, got %+v", class, task)
		}
	}
}

// TestPhaseDispositionFromTasks (Part 8/9): phase status is DERIVED from
// the engine's own task states, never from prose.
func TestPhaseDispositionFromTasks(t *testing.T) {
	state := richTestState()
	state.Plan = AutoPlanFromState(state)

	// Complete the phase-12 tasks: dispositions derive "completed".
	for _, t12 := range []*Task{
		state.Plan.Get("test-business-logic"),
		state.Plan.Get("test-race-conditions"),
	} {
		if t12 == nil {
			t.Fatal("expected business-logic/race-condition tasks on the workflow surface")
		}
		t12.Status = TaskCompleted
	}
	d := ComputePhaseDispositions(state)
	if d[12].Status != PhaseCompleted {
		t.Errorf("phase 12 = %q, want completed (both tasks completed)", d[12].Status)
	}

	// One blocked task with the rest completed → the phase reads blocked,
	// with the typed reason carried.
	state.Plan.Get("test-business-logic").Status = TaskSkipped
	state.Plan.Get("test-business-logic").Disposition = DispositionBlockedMissingAuth
	d = ComputePhaseDispositions(state)
	if d[12].Status != PhaseBlocked {
		t.Errorf("phase 12 = %q, want blocked when a lane is blocked_missing_auth", d[12].Status)
	}
	if !strings.Contains(d[12].Reason, "blocked_missing_auth") {
		t.Errorf("phase 12 blocked reason %q must carry the typed disposition", d[12].Reason)
	}

	// A pending task keeps the phase pending — finish must stay blocked.
	state.Plan.Get("test-business-logic").Status = TaskPending
	state.Plan.Get("test-business-logic").Disposition = ""
	d = ComputePhaseDispositions(state)
	if d[12].Status != PhasePending {
		t.Errorf("phase 12 = %q, want pending while a lane is open", d[12].Status)
	}
}

// TestPhaseDispositionNotApplicableAndNotSelected (Part 8/37): selected
// phases with no applicable surface are explicitly not_applicable;
// excluded phases are not_selected and can never block finish.
func TestPhaseDispositionNotApplicableAndNotSelected(t *testing.T) {
	// Single explicit host, no mail/cloud/CMS surface.
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.com"}
	state.DiscoveredEndpoints = []string{"https://app.example.com/"}
	state.AllowedPhases = nil // full methodology
	state.Plan = AutoPlanFromState(state)

	d := ComputePhaseDispositions(state)
	for _, phase := range []int{13, 15, 16, 18, 19, 21} {
		got := d[phase]
		if got.Status != PhaseNotApplicable {
			t.Errorf("phase %d = %q (%s), want not_applicable on a surface without that evidence", phase, got.Status, got.Reason)
		}
		if got.Reason == "" {
			t.Errorf("phase %d N/A must carry an auditable reason", phase)
		}
	}
	if d[1].Status != PhasePending {
		t.Errorf("phase 1 = %q, want pending while the surface is mapped but recon is unsettled", d[1].Status)
	}

	// Excluded phases read not_selected.
	restricted := richTestState()
	restricted.AllowedPhases = []int{10}
	restricted.Plan = AutoPlanFromState(restricted)
	rd := ComputePhaseDispositions(restricted)
	for _, phase := range []int{6, 9, 12, 17} {
		if rd[phase].Status != PhaseNotSelected {
			t.Errorf("restricted scan phase %d = %q, want not_selected", phase, rd[phase].Status)
		}
	}
	if rd[10].Status == PhaseNotSelected {
		t.Error("phase 10 is selected and must not read not_selected")
	}
}

// TestPhaseDispositionNotApplicableBeforeSurfaceMapped: a selected phase
// with no obligation must stay PENDING while the surface is still unknown —
// never a premature N/A.
func TestPhaseDispositionNotApplicableBeforeSurfaceMapped(t *testing.T) {
	state := NewScanState()
	state.AllowedPhases = nil
	state.Plan = AutoPlanFromState(state) // no endpoints, no seeded surface, recon not done
	d := ComputePhaseDispositions(state)
	for _, phase := range []int{13, 15, 18} {
		if d[phase].Status != PhasePending {
			t.Errorf("phase %d = %q, want pending before the surface is mapped (no premature N/A)", phase, d[phase].Status)
		}
	}
}

// TestPhaseDispositionVerificationAndReport (Parts 27/29): Phase 20 derives
// from the hypothesis ledger; Phase 22 from the terminal lifecycle.
func TestPhaseDispositionVerificationAndReport(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.Plan = AutoPlanFromState(state)

	d := ComputePhaseDispositions(state)
	// Empty ledger → no candidates were raised: the cross-cutting phase is
	// explicitly not_applicable, never silently "completed".
	if d[20].Status != PhaseNotApplicable {
		t.Errorf("phase 20 = %q, want not_applicable with an empty ledger", d[20].Status)
	}
	// Running scan → report pending.
	if d[22].Status != PhasePending {
		t.Errorf("phase 22 = %q, want pending while running", d[22].Status)
	}

	// Open hypothesis → verification pending.
	stored := ctx.Ledger.Upsert(scanctx.Hypothesis{Title: "coupon reuse", VulnClass: "business-logic", Status: scanctx.HypothesisQueued})
	if d = ComputePhaseDispositions(state); d[20].Status != PhasePending {
		t.Errorf("phase 20 = %q, want pending with queued candidates", d[20].Status)
	}

	// All candidates settled → verification completed (a rejected
	// hypothesis IS a verification disposition).
	if !ctx.Ledger.SetStatus(stored.ID, scanctx.HypothesisRejected, "baseline control held") {
		t.Fatal("SetStatus failed")
	}
	if d = ComputePhaseDispositions(state); d[20].Status != PhaseCompleted {
		t.Errorf("phase 20 = %q, want completed once every candidate is dispositioned", d[20].Status)
	}

	// Finish accepted → report completed; incomplete finish → blocked.
	state.CompletionStatus = CompletionStatusCompletedWithBlocked
	if d = ComputePhaseDispositions(state); d[22].Status != PhaseCompleted {
		t.Errorf("phase 22 = %q, want completed after an accepted finish", d[22].Status)
	}
	state.CompletionStatus = CompletionStatusIncomplete
	if d = ComputePhaseDispositions(state); d[22].Status != PhaseBlocked {
		t.Errorf("phase 22 = %q, want blocked after an incomplete termination", d[22].Status)
	}
}

// TestPhaseDispositionMapsRenderCompact: the web-facing maps key by decimal
// phase id and stay in sync with the struct dispositions.
func TestPhaseDispositionMapsRenderCompact(t *testing.T) {
	state := richTestState()
	state.Plan = AutoPlanFromState(state)
	d := ComputePhaseDispositions(state)
	status := PhaseStatusMap(d)
	reasons := PhaseReasonMap(d)
	if len(status) != 22 {
		t.Fatalf("status map has %d entries, want 22", len(status))
	}
	if status["10"] != string(d[10].Status) {
		t.Errorf("status[10] = %q, want %q", status["10"], d[10].Status)
	}
	if reasons["13"] != d[13].Reason {
		t.Errorf("reasons[13] mismatch: %q vs %q", reasons["13"], d[13].Reason)
	}
}

// TestFinishGatePhaseSettlement (Part 55): the finish contract settles every
// selected/applicable phase — pending applicable work blocks, N/A and
// excluded phases never do, and finish-gate exhaustion is recorded
// INCOMPLETE rather than masquerading as success.
func TestFinishGatePhaseSettlement(t *testing.T) {
	// 1. Applicable Phase 12 task pending → finish blocked.
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.com"}
	state.DiscoveredEndpoints = []string{"https://app.example.com/checkout"}
	state.ObservedEndpointMethods = map[string]map[string]bool{
		"app.example.com/checkout": {"POST": true},
	}
	state.EndpointContentTypes = map[string]string{"app.example.com/checkout": "application/json"}
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	state.ProfessionalAssessment = true
	state.Iteration = 10
	state.TerminalCalls = 6
	state.MeaningfulTestCalls = 5
	satisfyComprehensiveRecon(state)
	// The helper seeds example.com; this fixture's host is app.example.com.
	state.ReconCoverage.ContentDiscoveredHosts["app.example.com"] = true
	state.ReconCoverage.ParamDiscovered = true
	state.ReconCoverage.AuthMapped = "not_applicable"
	state.ReconCoverage.Dispositions["auth_mapping"] = "not_applicable"
	for _, t12 := range []*Task{state.Plan.Get("test-business-logic"), state.Plan.Get("test-race-conditions")} {
		t12.Status = TaskPending
	}
	res := hookFinishGatekeeper(state, nil)
	if !res.Block || !strings.Contains(res.BlockReason, "test-business-logic") {
		t.Fatalf("pending phase-12 work must block finish; got block=%v reason=%q", res.Block, res.BlockReason)
	}

	// 2. Phase 16 N/A with valid evidence → finish allowed once the rest
	// settles: settle every task, no cloud surface → no cloud obligation
	// existed in the first place (surface has an S3 endpoint here, so
	// instead use a plain state).
	plain := NewScanState()
	plain.ScanTargets = []string{"https://app.example.com"}
	plain.DiscoveredEndpoints = []string{"https://app.example.com/"}
	plain.Plan = AutoPlanFromState(plain)
	plain.PlanBuilt = true
	plain.ProfessionalAssessment = true
	plain.ReconDone = true
	plain.MeaningfulTestCalls = 5
	satisfyComprehensiveRecon(plain)
	// The helper seeds example.com; this fixture's host is app.example.com,
	// and the parameter/auth dimensions settle via typed dispositions.
	plain.ReconCoverage.ContentDiscoveredHosts["app.example.com"] = true
	plain.ReconCoverage.ParamDiscovered = true
	plain.ReconCoverage.AuthMapped = "not_applicable"
	plain.ReconCoverage.Dispositions["auth_mapping"] = "not_applicable"
	// Pin the plan to the current surface AFTER every state mutation, so
	// the gate's freshness refresh does not rebuild it from under the
	// settled statuses.
	plain.PlanSurfaceRevision = surfaceRevision(plain)
	if plain.Plan.Get("test-cloud-config") != nil {
		t.Fatal("plain single-host surface must not owe a cloud obligation")
	}
	// All remaining tasks settle to terminal dispositions.
	for _, task := range plain.Plan.Tasks {
		switch task.Status {
		case TaskPending, TaskActive:
			task.Status = TaskSkipped
			task.Disposition = DispositionNotApplicable
			task.Notes = "no applicable surface for this class on the observed target"
		}
	}
	if res := planFinishGate(plain, 15); res.Block {
		t.Errorf("N/A-dispositioned obligations must not block finish: %v", res.BlockReason)
	}

	// 3. Phase 17 excluded → no obligation (websocket task absent).
	noselect := richTestState()
	noselect.AllowedPhases = []int{9}
	noselect.Plan = AutoPlanFromState(noselect)
	if noselect.Plan.Get("test-websocket") != nil {
		t.Error("phase-17-excluded scan must not carry a websocket obligation")
	}

	// 4. Selected Phase 17 with WebSocket surface but untested → blocked.
	ws := richTestState()
	ws.AllowedPhases = []int{17}
	ws.Plan = AutoPlanFromState(ws)
	wsTask := ws.Plan.Get("test-websocket")
	if wsTask == nil {
		t.Fatal("selected phase 17 with observed WebSocket surface must create an obligation")
	}
	if res := planFinishGate(ws, 15); !res.Block {
		t.Error("untested selected phase-17 obligation must block finish")
	}

	// 5. Finish-attempt ceiling with unfinished work → INCOMPLETE.
	exhausted := richTestState()
	exhausted.Plan = AutoPlanFromState(exhausted)
	exhausted.FinishAttempts = 20
	exhausted.MaxFinishRejections = 15
	status, reasons := scanCompletionAssessment(exhausted)
	if status != CompletionStatusIncomplete {
		t.Errorf("exhaustion with pending obligations = %q, want incomplete", status)
	}
	if !anyReasonContains(reasons, "finish_gate_exhausted") {
		t.Errorf("completion reasons must name finish_gate_exhausted: %v", reasons)
	}

	// 6. No pending selected/applicable phase → successful completion.
	settled := richTestState()
	settled.Plan = AutoPlanFromState(settled)
	for _, task := range settled.Plan.Tasks {
		if task.Status == TaskPending || task.Status == TaskActive {
			task.Status = TaskCompleted
		}
	}
	if status, reasons = scanCompletionAssessment(settled); status != CompletionStatusCompleted {
		t.Errorf("fully settled plan = %q (reasons %v), want completed", status, reasons)
	}

	// 7. Blocked required phase → completed_with_blocked_work.
	blocked := richTestState()
	blocked.Plan = AutoPlanFromState(blocked)
	for _, task := range blocked.Plan.Tasks {
		switch task.Status {
		case TaskPending, TaskActive:
			task.Status = TaskSkipped
			task.Disposition = DispositionBlockedMissingSecondID
			task.Notes = "horizontal proof requires a second account that was not supplied"
		}
	}
	if status, _ = scanCompletionAssessment(blocked); status != CompletionStatusCompletedWithBlocked {
		t.Errorf("settled-but-blocked plan = %q, want completed_with_blocked_work", status)
	}

	// 8. Excluded phases never appear as obligations at all (nothing to
	// block with): the phase-filter tests cover generation; here confirm
	// planFinishGate finds no task for an excluded phase.
	excluded := richTestState()
	excluded.AllowedPhases = []int{10}
	excluded.Plan = AutoPlanFromState(excluded)
	for _, id := range []string{"test-sqli", "test-xss", "auth-session", "idor", "test-websocket", "test-graphql"} {
		if excluded.Plan.Get(id) != nil {
			t.Errorf("excluded-phase task %q must not exist in a [10]-only plan", id)
		}
	}
}

func anyReasonContains(reasons []string, needle string) bool {
	for _, r := range reasons {
		if strings.Contains(r, needle) {
			return true
		}
	}
	return false
}

// TestPhaseRegressionWeakPhases (Part 52): direct applicability coverage for
// the historically weakest phases — 13 (dangling CNAME candidate), 15 (mail
// infrastructure in scope), 16 (cloud service evidence), 18 (CMS detected),
// 19 (broken trusted external reference), 21 (rich application after
// ordinary lanes).
func TestPhaseRegressionWeakPhases(t *testing.T) {
	// 13: domain-scope target → takeover obligation; single host → none.
	domain := NewScanState()
	domain.ScanTargets = []string{"example.com"}
	domain.DiscoveredEndpoints = []string{"https://app.example.com/"}
	if p := AutoPlanFromState(domain); p.Get("test-subdomain-takeover") == nil {
		t.Error("domain-scope target must owe a phase-13 takeover obligation")
	}
	host := NewScanState()
	host.ScanTargets = []string{"https://app.example.com"}
	host.DiscoveredEndpoints = []string{"https://app.example.com/"}
	if p := AutoPlanFromState(host); p.Get("test-subdomain-takeover") != nil {
		t.Error("single explicit host must NOT owe a phase-13 takeover obligation")
	}

	// 15: mail host discovered on a single-host scope → obligation.
	mail := NewScanState()
	mail.ScanTargets = []string{"https://app.example.com"}
	mail.DiscoveredHosts = map[string]bool{"mail.example.com": true}
	if p := AutoPlanFromState(mail); p.Get("test-email-security") == nil {
		t.Error("discovered mail host must activate the phase-15 obligation")
	}

	// 16: cloud service evidence → obligation (and NOT from a plain CDN).
	cloud := NewScanState()
	cloud.ScanTargets = []string{"https://app.example.com"}
	cloud.DiscoveredEndpoints = []string{"https://app.example.com/"}
	cloud.DetectedTechs = map[string]bool{"aws": true}
	if p := AutoPlanFromState(cloud); p.Get("test-cloud-config") == nil {
		t.Error("AWS fingerprint must activate the phase-16 obligation")
	}
	cdn := NewScanState()
	cdn.ScanTargets = []string{"https://app.example.com"}
	cdn.DiscoveredEndpoints = []string{"https://app.example.com/"}
	cdn.DetectedTechs = map[string]bool{"cloudflare": true}
	if p := AutoPlanFromState(cdn); p.Get("test-cloud-config") != nil {
		t.Error("a plain CDN is NOT cloud-infra evidence — phase 16 must stay inactive")
	}

	// 18: CMS fingerprint → obligation.
	cms := NewScanState()
	cms.ScanTargets = []string{"https://app.example.com"}
	cms.DiscoveredEndpoints = []string{"https://app.example.com/"}
	cms.DetectedTechs = map[string]bool{"wordpress": true}
	if p := AutoPlanFromState(cms); p.Get("test-cms-security") == nil {
		t.Error("WordPress fingerprint must activate the phase-18 obligation")
	}

	// 19: trusted external reference observed → obligation (plus a
	// parameterized endpoint so content-spoofing applies too).
	ext := NewScanState()
	ext.ScanTargets = []string{"https://app.example.com"}
	ext.DiscoveredEndpoints = []string{"https://app.example.com/", "https://app.example.com/search"}
	ext.ObservedEndpointParameters = map[string][]SurfaceParameter{
		"app.example.com/search": {{Name: "url", Location: "query"}},
	}
	ext.ExternalReferences = map[string]bool{"assets.legacy-vendor.example": true}
	p := AutoPlanFromState(ext)
	if p.Get("test-broken-link-hijacking") == nil {
		t.Error("observed external reference must activate the phase-19 obligation")
	}
	if p.Get("test-content-spoofing") == nil {
		t.Error("web surface with forms/parameters must activate content-spoofing for phase 19")
	}

	// 21: rich application → bounded novel obligation; static site → none.
	rich := richTestState()
	if p := AutoPlanFromState(rich); p.Get("test-novel-testing") == nil {
		t.Error("rich dynamic surface must owe a bounded phase-21 novel-testing obligation")
	}
	static := NewScanState()
	static.ScanTargets = []string{"https://app.example.com"}
	static.DiscoveredEndpoints = []string{"https://app.example.com/", "https://app.example.com/about", "https://app.example.com/contact"}
	if p := AutoPlanFromState(static); p.Get("test-novel-testing") != nil {
		t.Error("static/simple target must NOT owe a phase-21 obligation (bounded, applicability-aware)")
	}
}
