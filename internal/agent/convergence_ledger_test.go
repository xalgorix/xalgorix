package agent

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func TestReconcileLedgerForFinish(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ConvergeFinish = true
	h1 := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Status: scanctx.HypothesisTesting})
	h2 := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "xss", Status: scanctx.HypothesisQueued})
	h3 := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Status: scanctx.HypothesisProven})
	h4 := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "ssrf", Status: scanctx.HypothesisTesting})

	if n := reconcileLedgerForFinish(state); n != 2 {
		t.Fatalf("reconciled %d testing hypotheses, want 2", n)
	}
	chk := func(id string, want scanctx.HypothesisStatus) {
		if h, ok := ctx.Ledger.Get(id); !ok || h.Status != want {
			t.Errorf("%s status = %v, want %v", id, h.Status, want)
		}
	}
	chk(h1.ID, scanctx.HypothesisExhausted) // testing → exhausted (residual)
	chk(h4.ID, scanctx.HypothesisExhausted)
	chk(h2.ID, scanctx.HypothesisQueued) // queued never claimed: untouched
	chk(h3.ID, scanctx.HypothesisProven) // proven is a real finding: untouched

	// Flag off → no-op.
	state.ConvergeFinish = false
	h5 := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "cmdi", Status: scanctx.HypothesisTesting})
	if n := reconcileLedgerForFinish(state); n != 0 {
		t.Errorf("flag off must be a no-op, reconciled %d", n)
	}
	chk(h5.ID, scanctx.HypothesisTesting)
}

// End-to-end: a principled-finished scan (plan tasks closed) reads "incomplete"
// while a claimed hypothesis dangles, and "completed" once reconciled. The scan
// has a validated finding, so the untested-at-finish rule (zero findings) is
// not what decides the status here.
func TestReconcileLedgerMakesAssessmentCompleted(t *testing.T) {
	ctx, st := newTestCtxState(t)
	st.ConvergeFinish = true
	st.Plan = &Plan{Tasks: []*Task{
		{ID: "t-sqli", VulnClass: "sqli", Status: TaskSkipped, Disposition: DispositionUntestedAtFinish},
	}}
	if err := reporting.RestoreContext(ctx.ID, t.TempDir(), []reporting.Vulnerability{
		{ID: "XALG-1", Title: "SQLi", Target: "https://t.invalid", Endpoint: "/q", Method: "GET"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Status: scanctx.HypothesisTesting})

	if s, reasons := scanCompletionAssessment(st); s != CompletionStatusIncomplete {
		t.Fatalf("before reconcile: status=%s reasons=%v, want incomplete", s, reasons)
	}
	reconcileLedgerForFinish(st)
	if s, reasons := scanCompletionAssessment(st); s != CompletionStatusCompleted {
		t.Errorf("after reconcile: status=%s reasons=%v, want completed", s, reasons)
	}
}
