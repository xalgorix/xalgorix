package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// newSaturatedAgent builds a root agent whose scan is saturated for the
// principled finish: ConvergeFinish on, past MinIterations, broad class
// coverage, and one soft task still open.
func newSaturatedAgent(t *testing.T, idle, window int) (*Agent, *scanctx.ScanContext) {
	t.Helper()
	ctx, st := newTestCtxState(t)
	st.ConvergeFinish = true
	st.Iteration = 100
	st.MinIterations = 50
	st.VulnClassesTested = breadthState(11, true, 100).VulnClassesTested
	st.Plan = NewPlan()
	st.Plan.add(&Task{ID: "t-sqli", Phase: 6, VulnClass: "sqli", Origin: "auto", Status: TaskPending})
	st.Plan.add(&Task{ID: "done", Phase: 6, VulnClass: "xss", Origin: "auto", Status: TaskCompleted})
	if !saturatedForFinish(st) {
		t.Fatal("test fixture is not saturated")
	}
	a := &Agent{
		state:      st,
		scanCtx:    ctx,
		scanBudget: newScanBudget(),
		cfg:        &config.Config{ConvergeFinishIdle: idle, ConvergeFinishLeadWindow: window},
		events:     make(chan Event, 1024),
	}
	return a, ctx
}

// step advances one iteration and runs the finalizer.
func step(a *Agent) bool {
	a.state.Iteration++
	return a.autoFinalizeIfPlanComplete()
}

// runUntilFinal steps up to max iterations and returns how many steps it took
// to finalize (0 if it never did).
func runUntilFinal(a *Agent, max int) int {
	for i := 1; i <= max; i++ {
		if step(a) {
			return i
		}
	}
	return 0
}

func finishedContent(t *testing.T, a *Agent) string {
	t.Helper()
	for {
		select {
		case ev := <-a.events:
			if ev.Type == "finished" {
				return ev.Content
			}
		default:
			t.Fatal("no finished event emitted")
			return ""
		}
	}
}

func modelLead(endpoint string, conf float64) scanctx.Hypothesis {
	return scanctx.Hypothesis{VulnClass: "auth", Endpoint: endpoint, Origin: "coordinator", Confidence: conf, Status: scanctx.HypothesisQueued}
}

// Without leads the saturated finish fires exactly at the idle limit, closes
// the open work as untested, says so, and (zero findings) is not full.
func TestSaturatedFinishWithoutLeads(t *testing.T) {
	a, _ := newSaturatedAgent(t, 10, 5)
	if got := runUntilFinal(a, 50); got != 10 {
		t.Fatalf("finalized after %d steps, want exactly 10 (the idle limit)", got)
	}
	content := finishedContent(t, a)
	if strings.Contains(content, "fully exhausted") {
		t.Errorf("saturated finish must not claim the plan was exhausted:\n%s", content)
	}
	if !strings.Contains(content, "closed WITHOUT being executed") {
		t.Errorf("saturated finish must say tasks were closed unexecuted:\n%s", content)
	}
	for _, task := range a.state.Plan.Tasks {
		if task.ID == "t-sqli" && task.Disposition != DispositionUntestedAtFinish {
			t.Errorf("open task disposition = %q, want untested_at_finish", task.Disposition)
		}
	}
	if a.state.CompletionStatus != CompletionStatusIncomplete || a.CompletionStopReason() != StopReasonUntestedAtFinish {
		t.Errorf("completion = %q / %q, want incomplete / untested_at_finish (zero findings, unexecuted work)",
			a.state.CompletionStatus, a.CompletionStopReason())
	}
}

// A NEW model-recorded hypothesis during the tail restarts it; engine-generated
// hypotheses do not; restarts are capped so the scan still ends.
func TestNewModelHypothesisRestartsIdleTail(t *testing.T) {
	a, ctx := newSaturatedAgent(t, 10, -1)
	// A lead recorded before the tail starts is only a baseline.
	ctx.Ledger.Upsert(modelLead("/before", 0.5))
	for i := 0; i < 5; i++ {
		if step(a) {
			t.Fatal("finalized early")
		}
	}
	if a.state.LeadIdleResets != 0 || a.state.FindingIdleIterations != 5 {
		t.Fatalf("baseline consumed a restart: resets=%d idle=%d", a.state.LeadIdleResets, a.state.FindingIdleIterations)
	}

	// Engine-generated candidates never restart the tail.
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/auto", Origin: "auto-surface-param", Confidence: 0.9, Status: scanctx.HypothesisQueued})
	step(a)
	if a.state.LeadIdleResets != 0 || a.state.FindingIdleIterations != 6 {
		t.Fatalf("engine hypothesis restarted the tail: resets=%d idle=%d", a.state.LeadIdleResets, a.state.FindingIdleIterations)
	}

	// A new model-recorded hypothesis restarts it.
	ctx.Ledger.Upsert(modelLead("/new-1", 0.4))
	if step(a) {
		t.Fatal("finalized on the iteration a new lead arrived")
	}
	if a.state.LeadIdleResets != 1 || a.state.FindingIdleIterations != 0 {
		t.Fatalf("new lead did not restart the tail: resets=%d idle=%d", a.state.LeadIdleResets, a.state.FindingIdleIterations)
	}

	// Re-recording the same hypothesis (same dedup key) is not a new lead.
	step(a)
	ctx.Ledger.Upsert(modelLead("/new-1", 0.4))
	step(a)
	if a.state.LeadIdleResets != 1 {
		t.Fatalf("re-recorded hypothesis counted as new: resets=%d", a.state.LeadIdleResets)
	}

	// Restarts are capped: keep adding leads every few iterations; the scan
	// must still finalize.
	steps := 0
	for i := 0; i < 500 && steps == 0; i++ {
		if i%3 == 0 {
			ctx.Ledger.Upsert(modelLead("/spam-"+strings.Repeat("x", i+1), 0.4))
		}
		if step(a) {
			steps = i + 1
		}
	}
	if steps == 0 {
		t.Fatal("scan never finalized while the model kept recording new hypotheses")
	}
	if a.state.LeadIdleResets != maxLeadIdleResets {
		t.Errorf("resets = %d, want the cap %d", a.state.LeadIdleResets, maxLeadIdleResets)
	}
}

// When the tail elapses with a recent high-confidence unverified lead, one
// bounded verification window opens, the model is told, and the scan then
// finalizes; the open lead is listed for follow-up.
func TestLeadVerificationWindowOpensOnceAndIsBounded(t *testing.T) {
	a, ctx := newSaturatedAgent(t, 10, 5)
	lead := ctx.Ledger.Upsert(modelLead("/Api/account", 0.8)) // baseline, before the tail
	for i := 0; i < 3; i++ {
		step(a)
	}
	time.Sleep(2 * time.Millisecond)
	ctx.Ledger.SetStatus(lead.ID, scanctx.HypothesisTesting, "probe parameter contract") // touched during the tail

	for a.state.FindingIdleIterations < 9 {
		if step(a) {
			t.Fatal("finalized before the idle limit")
		}
	}
	if step(a) {
		t.Fatal("finalized at the idle limit despite an active lead; the window should have opened")
	}
	start := a.state.LeadWindowStartIteration
	if start == 0 {
		t.Fatal("verification window did not open")
	}
	last := a.messages[len(a.messages)-1]
	if last.Role != "user" || !strings.Contains(last.Content, "VERIFICATION WINDOW") || !strings.Contains(last.Content, lead.ID) {
		t.Fatalf("window directive not delivered to the model: %+v", last)
	}

	got := runUntilFinal(a, 50)
	if got != 5 {
		t.Fatalf("finalized %d steps after the window opened, want 5 (the window length)", got)
	}
	if !strings.Contains(a.state.UnverifiedLeadsAtFinish, lead.ID) {
		t.Errorf("unverified lead not recorded for follow-up: %q", a.state.UnverifiedLeadsAtFinish)
	}
	if h, _ := ctx.Ledger.Get(lead.ID); h.Status != scanctx.HypothesisExhausted {
		t.Errorf("lead status after finish = %s, want exhausted (settled residual)", h.Status)
	}
}

// The window closes early once the model concludes every lead it was opened for.
func TestLeadVerificationWindowClosesWhenLeadsSettle(t *testing.T) {
	a, ctx := newSaturatedAgent(t, 10, 50)
	lead := ctx.Ledger.Upsert(modelLead("/Api/card", 0.9))
	step(a)
	time.Sleep(2 * time.Millisecond)
	ctx.Ledger.SetStatus(lead.ID, scanctx.HypothesisTesting, "")
	for a.state.LeadWindowStartIteration == 0 {
		if step(a) {
			t.Fatal("finalized without opening the window")
		}
	}
	step(a)
	ctx.Ledger.SetStatus(lead.ID, scanctx.HypothesisRejected, "parameter validation only; no data returned")
	if !step(a) {
		t.Fatal("window stayed open after its only lead was rejected")
	}
}

// Leads that are low-confidence, engine-generated, or stale do not open the
// window, and a negative window disables it.
func TestLeadVerificationWindowIgnoresNonLeads(t *testing.T) {
	cases := []struct {
		name   string
		window int
		lead   scanctx.Hypothesis
		touch  bool
	}{
		{"low confidence", 5, modelLead("/low", 0.5), true},
		{"engine origin", 5, scanctx.Hypothesis{VulnClass: "auth", Endpoint: "/e", Origin: "auto-plan", Confidence: 0.9, Status: scanctx.HypothesisQueued}, true},
		{"stale (not touched during the tail)", 5, modelLead("/stale", 0.9), false},
		{"window disabled", -1, modelLead("/off", 0.9), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, ctx := newSaturatedAgent(t, 10, tc.window)
			h := ctx.Ledger.Upsert(tc.lead)
			step(a)
			if tc.touch {
				time.Sleep(2 * time.Millisecond)
				ctx.Ledger.SetStatus(h.ID, scanctx.HypothesisTesting, "")
			}
			if got := runUntilFinal(a, 50); got != 9 {
				t.Fatalf("finalized after %d more steps, want 9 (no window)", got)
			}
			if a.state.LeadWindowStartIteration != 0 {
				t.Error("window opened for a non-lead")
			}
		})
	}
}

// With ConvergeFinish off the legacy plan-exhausted path is unchanged: new
// model hypotheses do not restart the tail and no window opens.
func TestLegacyPlanExhaustedPathUnchanged(t *testing.T) {
	ctx, st := newTestCtxState(t)
	st.MinIterations = 0
	st.Plan = NewPlan()
	st.Plan.add(&Task{ID: "done", Phase: 6, VulnClass: "sqli", Endpoint: "/search", Status: TaskCompleted})
	a := &Agent{state: st, scanCtx: ctx, scanBudget: newScanBudget(), cfg: &config.Config{PlanCompleteFindingIdle: 5}, events: make(chan Event, 64)}
	step(a)
	ctx.Ledger.Upsert(modelLead("/x", 0.9))
	if got := runUntilFinal(a, 50); got != 4 {
		t.Fatalf("legacy finalize after %d more steps, want 4", got)
	}
	if a.state.LeadIdleResets != 0 || a.state.LeadWindowStartIteration != 0 {
		t.Error("legacy path used ConvergeFinish lead handling")
	}
	if c := finishedContent(t, a); !strings.Contains(c, "fully exhausted") {
		t.Errorf("legacy exhausted-plan message changed:\n%s", c)
	}
}

// A principled finish that closed work untested with zero validated findings is
// incomplete (scan record: partial / untested_at_finish); with a validated
// finding it stays completed. Gate exhaustion keeps precedence.
func TestUntestedAtFinishCompletion(t *testing.T) {
	for _, disp := range []string{DispositionUntestedAtFinish, DispositionCoverageSufficient} {
		t.Run(disp, func(t *testing.T) {
			ctx, st := newTestCtxState(t)
			st.Plan = &Plan{Tasks: []*Task{{ID: "t", VulnClass: "sqli", Status: TaskSkipped, Disposition: disp}}}
			status, _ := settleCompletion(st)
			if status != CompletionStatusIncomplete || st.CompletionStopReason != StopReasonUntestedAtFinish {
				t.Fatalf("zero findings: %s/%s, want incomplete/untested_at_finish", status, st.CompletionStopReason)
			}
			if err := reporting.RestoreContext(ctx.ID, t.TempDir(), []reporting.Vulnerability{
				{ID: "XALG-1", Title: "SQLi", Target: "https://t.invalid", Endpoint: "/q", Method: "GET"},
			}); err != nil {
				t.Fatal(err)
			}
			status, _ = settleCompletion(st)
			if status != CompletionStatusCompleted || st.CompletionStopReason != "" {
				t.Fatalf("one finding: %s/%q, want completed with no stop reason", status, st.CompletionStopReason)
			}
		})
	}
	if got := completionStopReason([]string{
		StopReasonUntestedAtFinish + ": x", StopReasonFinishGateExhausted + ": y",
	}); got != StopReasonFinishGateExhausted {
		t.Errorf("stop reason precedence = %q, want finish_gate_exhausted", got)
	}
}

// Phase summaries report tasks closed untested as not executed, never as
// not-applicable.
func TestPhaseDispositionReportsUntestedWork(t *testing.T) {
	st := NewScanState()
	st.ReconDone = true
	st.Plan = &Plan{Tasks: []*Task{
		{ID: "a", Phase: 7, VulnClass: "ssrf", Status: TaskSkipped, Disposition: DispositionUntestedAtFinish},
		{ID: "b", Phase: 6, VulnClass: "sqli", Status: TaskCompleted},
		{ID: "c", Phase: 6, VulnClass: "xss", Status: TaskSkipped, Disposition: DispositionUntestedAtFinish},
	}}
	d := ComputePhaseDispositions(st)
	if d[7].Status == PhaseNotApplicable || !strings.Contains(d[7].Reason, "not executed") {
		t.Errorf("phase 7 (only untested work) = %s %q, want a not-executed status, never not_applicable", d[7].Status, d[7].Reason)
	}
	if d[6].Status != PhaseCompleted || !strings.Contains(d[6].Reason, "partially executed") {
		t.Errorf("phase 6 (mixed) = %s %q, want completed with a partially-executed note", d[6].Status, d[6].Reason)
	}
}
