package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestCoverageProgressSignature_RisesWithWork(t *testing.T) {
	state := NewScanState()
	base := coverageProgressSignature(state)

	state.EndpointsTested = map[string]bool{"/a": true, "/b": true}
	if got := coverageProgressSignature(state); got <= base {
		t.Fatalf("signature did not rise after testing endpoints: base=%d got=%d", base, got)
	}
	afterEndpoints := coverageProgressSignature(state)

	state.VulnClassesTested = map[string]bool{"sqli": true}
	if got := coverageProgressSignature(state); got <= afterEndpoints {
		t.Fatalf("signature did not rise after a tested class: before=%d got=%d", afterEndpoints, got)
	}
}

func TestFinishFloorsMet(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 5
	state.TerminalCalls = 8
	if !finishFloorsMet(state) {
		t.Error("floors should be met with recon done, iter>=3, terminal>=5")
	}
	state.ReconDone = false
	if finishFloorsMet(state) {
		t.Error("floors must not be met without recon")
	}
}

// A scan that keeps asking to finish but covers no new ground is released early,
// well before the MaxFinishRejections deadlock ceiling, instead of burning the
// remaining laps (the finish_gate_exhausted tail).
func TestFinishGatekeeper_ReleasesStalledReloop(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 10
	state.TerminalCalls = 10
	state.EndpointInventorySaved = false // inventory gate keeps blocking (iter<50)
	state.EndpointsTested = map[string]bool{"/a": true, "/b": true, "/c": true}

	// Coverage is held constant across attempts (the stalled case).
	for attempt := 1; attempt <= finishStallReleaseStreak; attempt++ {
		if res := hookFinishGatekeeper(state, nil); !res.Block {
			t.Fatalf("attempt %d should still block while the stall streak builds", attempt)
		}
	}
	// By now the streak has reached the release threshold with floors met.
	if res := hookFinishGatekeeper(state, nil); res.Block {
		t.Fatalf("a stalled re-loop should be released before the %d-attempt ceiling", defaultMaxFinishRejections)
	}
	if state.FinishAttempts >= defaultMaxFinishRejections {
		t.Errorf("released at attempt %d — expected well before the deadlock ceiling %d",
			state.FinishAttempts, defaultMaxFinishRejections)
	}
}

// stalledLegacyState is a planless scan the coverage gate keeps blocking
// (injection and access-control coverage are missing) while its coverage
// signature stays flat across finish attempts.
func stalledLegacyState() *ScanState {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 10
	state.TerminalCalls = 10
	state.EndpointInventorySaved = true
	state.EndpointsTested = map[string]bool{"/a": true, "/b": true, "/c": true, "/d": true}
	return state
}

// The early stall release is the gate giving up while it still wanted work
// done, the same outcome as the rejection ceiling. It must carry the same
// honest label: a scan released this way is incomplete (finish_gate_exhausted),
// never a completed finish.
func TestFinishGatekeeper_StallReleaseLabelsScanIncomplete(t *testing.T) {
	state := stalledLegacyState()
	var res HookResult
	for attempt := 1; attempt <= finishStallReleaseStreak+1; attempt++ {
		res = hookFinishGatekeeper(state, nil)
		if attempt <= finishStallReleaseStreak && !res.Block {
			t.Fatalf("attempt %d: the coverage gate should still block", attempt)
		}
	}
	if res.Block {
		t.Fatal("the stalled re-loop should be released")
	}
	if state.FinishAttempts > defaultMaxFinishRejections {
		t.Fatalf("expected the stall release, not the ceiling, at attempt %d", state.FinishAttempts)
	}
	if !state.FinishGateStallReleased {
		t.Fatal("a release past a blocking gate must be recorded")
	}
	status, reasons := settleCompletion(state)
	if status != CompletionStatusIncomplete {
		t.Fatalf("status = %q (reasons %v), want %q", status, reasons, CompletionStatusIncomplete)
	}
	if state.CompletionStopReason != StopReasonFinishGateExhausted {
		t.Fatalf("stop reason = %q, want %q", state.CompletionStopReason, StopReasonFinishGateExhausted)
	}
}

// When the gate itself would let the finish through, a flat signature changes
// nothing: the finish is a satisfied one and must not be labeled incomplete.
func TestFinishGatekeeper_StallWithSatisfiedGateIsNotLabeled(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 10
	state.TerminalCalls = 10
	state.DiscoveryMode = true // discovery finish contract: >= 3 commands
	for attempt := 1; attempt <= finishStallReleaseStreak+1; attempt++ {
		if res := hookFinishGatekeeper(state, nil); res.Block {
			t.Fatalf("attempt %d: discovery gate should allow the finish: %s", attempt, res.BlockReason)
		}
	}
	if state.FinishStallStreak < finishStallReleaseStreak {
		t.Fatalf("stall streak = %d, want the release threshold to be reached", state.FinishStallStreak)
	}
	if state.FinishGateStallReleased {
		t.Fatal("an allowed finish must not be recorded as a stall release")
	}
	if status, reasons := settleCompletion(state); status != CompletionStatusCompleted {
		t.Fatalf("status = %q (reasons %v), want %q", status, reasons, CompletionStatusCompleted)
	}
}

// A stall release that a later finish hook (e.g. the ledger gate) blocked must
// not label a later finish that the gate allows on its merits.
func TestFinishGatekeeper_StallReleaseFlagIsPerAttempt(t *testing.T) {
	state := stalledLegacyState()
	for attempt := 1; attempt <= finishStallReleaseStreak+1; attempt++ {
		hookFinishGatekeeper(state, nil)
	}
	if !state.FinishGateStallReleased {
		t.Fatal("setup: expected a stall release")
	}
	state.DiscoveryMode = true // the gate now allows the finish on its merits
	if res := hookFinishGatekeeper(state, nil); res.Block {
		t.Fatalf("gate should allow the finish: %s", res.BlockReason)
	}
	if state.FinishGateStallReleased {
		t.Fatal("the flag from an earlier attempt leaked into a satisfied finish")
	}
	if status, reasons := settleCompletion(state); status != CompletionStatusCompleted {
		t.Fatalf("status = %q (reasons %v), want %q", status, reasons, CompletionStatusCompleted)
	}
}

// The gatekeeper can stall-release an attempt that the ledger gate (registered
// after it) still blocks because a proven lead is unreported. The finish is
// rejected, so the release must not survive into a later end of the scan that
// runs no finish hook (the liveness auto-finalize reads settleCompletion only).
func TestFinishGatekeeper_StallReleaseBlockedByLedgerGateIsCleared(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ReconDone = true
	state.Iteration = 10
	state.TerminalCalls = 10
	state.EndpointInventorySaved = true
	state.EndpointsTested = map[string]bool{"/a": true, "/b": true, "/c": true, "/d": true}
	lead := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/a"})
	ctx.Ledger.SetStatus(lead.ID, scanctx.HypothesisProven, "")

	reg := NewHookRegistry()
	reg.Register(OnFinishAttempt, hookFinishGatekeeper)
	reg.Register(OnFinishAttempt, hookLedgerFinishGate)

	var res HookResult
	for attempt := 1; attempt <= finishStallReleaseStreak+1; attempt++ {
		res = reg.Fire(OnFinishAttempt, state, nil)
		if !res.Block {
			t.Fatalf("attempt %d: the unreported proven lead must keep the finish blocked", attempt)
		}
		if attempt <= finishStallReleaseStreak {
			noteFinishRejected(state)
		}
	}
	if !state.FinishGateStallReleased {
		t.Fatal("setup: the gatekeeper should have stall-released the last attempt")
	}
	noteFinishRejected(state) // the agent loop's rejected-finish branch
	if state.FinishGateStallReleased {
		t.Fatal("a stall release on a rejected finish must be cleared")
	}
	_, reasons := settleCompletion(state)
	for _, r := range reasons {
		if strings.HasPrefix(r, StopReasonFinishGateExhausted+":") {
			t.Fatalf("a rejected stall release leaked into the assessment: %v", reasons)
		}
	}
}

// Evidence that only the plan reconciliation turns into progress (here a
// dirbusting run that settles the dirbust task) must count on the attempt it
// lands, so the stall check runs after reconcilePlan rather than reading a
// one-turn-old plan and releasing a lap that did real work.
func TestFinishGatekeeper_ReconciledProgressResetsStall(t *testing.T) {
	state := stalledLegacyState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "dirbust", Title: "Content discovery", Phase: 2, Status: TaskPending})
	// The first attempt records the baseline signature; the next ones stall.
	for attempt := 1; attempt <= finishStallReleaseStreak; attempt++ {
		hookFinishGatekeeper(state, nil)
	}
	if state.FinishStallStreak != finishStallReleaseStreak-1 {
		t.Fatalf("setup: stall streak = %d, want %d", state.FinishStallStreak, finishStallReleaseStreak-1)
	}

	state.DirBustingDone = true // work done this lap; only reconcilePlan records it
	if res := hookFinishGatekeeper(state, nil); !res.Block {
		t.Fatal("a lap that settled a plan task was released as a stall")
	}
	if state.FinishStallStreak != 0 {
		t.Fatalf("stall streak = %d after a lap that settled a plan task, want 0", state.FinishStallStreak)
	}
}

// The signature is not monotonic: a coverage epoch reopens completed tasks when
// new surface appears. A lap that reopens three tasks and tests one new endpoint
// lowers the signature, but it is activity, not a stall; measured against a
// high-water mark it would count toward an early release while work goes on.
func TestRecordFinishCoverageProgress_SignatureDropIsActivity(t *testing.T) {
	state := NewScanState()
	state.EndpointsTested = map[string]bool{"/a": true}
	state.Plan = NewPlan()
	for _, id := range []string{"t1", "t2", "t3", "t4"} {
		state.Plan.add(&Task{ID: id, VulnClass: "sqli", Endpoint: "/" + id, Status: TaskCompleted})
	}
	if recordFinishCoverageProgress(state) {
		t.Fatal("first attempt must not be a stall release")
	}
	before := coverageProgressSignature(state)

	for _, id := range []string{"t1", "t2", "t3"} {
		state.Plan.SetStatus(id, TaskPending)
	}
	state.EndpointsTested["/new"] = true
	if after := coverageProgressSignature(state); after >= before {
		t.Fatalf("setup: signature should drop (before %d, after %d)", before, after)
	}
	recordFinishCoverageProgress(state)
	if state.FinishStallStreak != 0 {
		t.Fatalf("a lap that changed coverage counted as stalled (streak %d)", state.FinishStallStreak)
	}

	recordFinishCoverageProgress(state) // nothing changed this time
	if state.FinishStallStreak != 1 {
		t.Fatalf("an unchanged lap should count as stalled (streak %d, want 1)", state.FinishStallStreak)
	}
}

// A scan that covers new ground on every lap must never be released early — the
// stall streak resets whenever coverage advances, so full coverage is kept.
func TestFinishGatekeeper_ProgressingScanIsNotCutShort(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 10
	state.TerminalCalls = 10
	state.EndpointInventorySaved = false
	state.EndpointsTested = map[string]bool{}

	paths := []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"}
	for i, p := range paths {
		state.EndpointsTested[p] = true // new coverage every lap
		if res := hookFinishGatekeeper(state, nil); !res.Block {
			t.Fatalf("lap %d added new coverage, so the gate must keep blocking, not release early", i+1)
		}
		if state.FinishStallStreak != 0 {
			t.Fatalf("lap %d advanced coverage but stall streak is %d, want 0", i+1, state.FinishStallStreak)
		}
	}
}
