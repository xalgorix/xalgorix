package agent

import (
	"strings"
	"testing"
)

// Reasoning-loop recovery is NUDGE-ONLY: the handler must NEVER abort before
// the (generous) consecutive threshold, and in bounded mode it force-stops only
// once NoToolCount reaches NoToolAbortAt. Compaction is no longer coupled to
// reasoning loops at all, so there is nothing to assert about it here.
func TestNoToolHandler_NudgeThenBoundedAbort(t *testing.T) {
	state := NewScanState() // abort enabled via the NoToolAbortAt default

	// Every response below the abort threshold must be a nudge, never a stop.
	for state.NoToolCount < NoToolAbortAt-1 {
		res := hookNoToolHandler(state, map[string]string{"response": "let me think"})
		if res.ForceSkip {
			t.Fatalf("ForceSkip at NoToolCount=%d, well before the abort threshold %d",
				state.NoToolCount, NoToolAbortAt)
		}
		if res.Nudge == "" {
			t.Fatalf("expected a nudge at NoToolCount=%d", state.NoToolCount)
		}
	}

	// The next response reaches NoToolAbortAt → force-stop (bounded mode).
	res := hookNoToolHandler(state, map[string]string{"response": "thinking"})
	if !res.ForceSkip {
		t.Fatalf("expected ForceSkip at NoToolCount=%d (abort=%d), got %+v",
			state.NoToolCount, NoToolAbortAt, res)
	}
}

// The nudge must escalate: a gentle reminder at NoToolSoftNudgeAt, and the firm
// "resume and act" prompt at NoToolStrongNudgeAt — but not before.
func TestNoToolHandler_NudgeEscalation(t *testing.T) {
	state := NewScanState()

	// Below the soft threshold: only the generic format reminder.
	for state.NoToolCount < NoToolSoftNudgeAt-1 {
		res := hookNoToolHandler(state, map[string]string{"response": "x"})
		if strings.Contains(res.Nudge, "MUST use tools") || strings.Contains(res.Nudge, "STOP planning") {
			t.Fatalf("escalated nudge fired too early at NoToolCount=%d: %q", state.NoToolCount, res.Nudge)
		}
	}

	// At the soft threshold: the "MUST use tools" reminder.
	res := hookNoToolHandler(state, map[string]string{"response": "x"}) // NoToolCount == NoToolSoftNudgeAt
	if state.NoToolCount != NoToolSoftNudgeAt {
		t.Fatalf("test setup: NoToolCount=%d, want %d", state.NoToolCount, NoToolSoftNudgeAt)
	}
	if !strings.Contains(res.Nudge, "MUST use tools") {
		t.Fatalf("soft nudge missing at NoToolCount=%d: %q", state.NoToolCount, res.Nudge)
	}

	// At the strong threshold: the firm resume prompt.
	for state.NoToolCount < NoToolStrongNudgeAt {
		res = hookNoToolHandler(state, map[string]string{"response": "x"})
	}
	if !strings.Contains(res.Nudge, "STOP planning") {
		t.Fatalf("strong resume nudge missing at NoToolCount=%d: %q", state.NoToolCount, res.Nudge)
	}
	// The strong nudge must NOT claim the context was compacted (it isn't).
	if strings.Contains(res.Nudge, "COMPACTED") {
		t.Errorf("resume nudge must not claim a compaction happened: %q", res.Nudge)
	}
}

// With the abort disabled (XALGORIX_NO_TOOL_ABORT_AT=0), the handler must NEVER
// ForceSkip on a no-tool loop — it keeps nudging indefinitely so the model can
// fix its own output and resume. Neither the consecutive nor the density path
// may abort.
func TestNoToolHandler_AbortDisabledNeverGivesUp(t *testing.T) {
	state := NewScanState()
	state.NoToolAbortConfigured = true
	state.NoToolAbortLimit = 0 // disabled → never give up

	for i := 0; i < 300; i++ {
		state.Iteration++
		res := hookNoToolHandler(state, map[string]string{"response": "thinking, no tool"})
		if res.ForceSkip {
			t.Fatalf("ForceSkip fired at NoToolCount=%d/Iteration=%d with abort disabled",
				state.NoToolCount, state.Iteration)
		}
		if res.Nudge == "" {
			t.Fatalf("expected a nudge at NoToolCount=%d with abort disabled", state.NoToolCount)
		}
	}
}

// The density safety net catches a NON-consecutive loop (occasional tool call
// keeps resetting NoToolCount so the consecutive path never trips) — but only
// in BOUNDED mode and only after a sustained high ratio past the warm-up gate.
func TestNoToolHandler_DensityAbortBoundedOnly(t *testing.T) {
	state := NewScanState() // abort enabled

	var sawAbort bool
	for i := 0; i < 600; i++ {
		state.Iteration++
		// Simulate a tool call (healthy turn) every 12th iteration: resets the
		// consecutive counter, keeping NoToolCount well below the consecutive
		// thresholds while the cumulative no-tool ratio stays ~0.92 (> 0.85).
		if i%12 == 0 {
			state.NoToolCount = 0
			continue
		}
		res := hookNoToolHandler(state, map[string]string{"response": "thinking"})
		if res.ForceSkip {
			sawAbort = true
			break
		}
	}
	if !sawAbort {
		t.Fatalf("density abort never fired in bounded mode: NoToolCount=%d TotalNoTool=%d Iteration=%d",
			state.NoToolCount, state.TotalNoToolResponses, state.Iteration)
	}
	if reason, _ := classifyNoToolAbort(state); reason != "llm_reasoning_loop" {
		t.Errorf("classifyNoToolAbort reason = %q, want llm_reasoning_loop", reason)
	}
}

// The same non-consecutive pattern must NOT abort when the operator disabled
// the hard abort — the density net is a bounded-mode-only safety valve.
func TestNoToolHandler_DensityNoAbortWhenUnbounded(t *testing.T) {
	state := NewScanState()
	state.NoToolAbortConfigured = true
	state.NoToolAbortLimit = 0 // disabled

	for i := 0; i < 600; i++ {
		state.Iteration++
		if i%12 == 0 {
			state.NoToolCount = 0
			continue
		}
		if res := hookNoToolHandler(state, map[string]string{"response": "thinking"}); res.ForceSkip {
			t.Fatalf("density abort fired with abort disabled at Iteration=%d", state.Iteration)
		}
	}
}

// A safety refusal must take priority over the recovery nudges.
func TestNoToolHandler_RefusalPriority(t *testing.T) {
	state := NewScanState()
	for i := 0; i < 3; i++ {
		res := hookNoToolHandler(state, map[string]string{"response": "I cannot fulfill this request"})
		if res.ForceSkip {
			t.Fatal("refusal should nudge, not abort, this early")
		}
		if !strings.Contains(res.Nudge, "AUTHORIZED") {
			t.Errorf("refusal nudge should re-assert authorization, got %q", res.Nudge)
		}
	}
	if state.RefusalCount != 3 {
		t.Errorf("RefusalCount=%d, want 3", state.RefusalCount)
	}
}

func TestNoToolHandler_MalformedProtocolIsBoundedAndClassified(t *testing.T) {
	state := NewScanState()
	state.NoToolAbortConfigured = true
	state.NoToolAbortLimit = 0 // generic no-tool abort disabled must not allow protocol retry storms

	for i := 1; i < MalformedToolAbortAt; i++ {
		res := hookNoToolHandler(state, map[string]string{
			"response":         "agent <tool_call>",
			"malformed_reason": "unparsed_tool_call",
		})
		if res.ForceSkip {
			t.Fatalf("malformed output aborted too early at %d: %+v", i, res)
		}
		if !strings.Contains(res.Nudge, "TOOL PROTOCOL RECOVERY") {
			t.Fatalf("malformed output missing protocol-recovery nudge at %d: %q", i, res.Nudge)
		}
	}

	res := hookNoToolHandler(state, map[string]string{
		"response":         "echo]<]minimax[>[",
		"malformed_reason": "provider_control_token_leak",
	})
	if !res.ForceSkip {
		t.Fatalf("expected bounded malformed-output abort at %d: %+v", state.MalformedToolOutputCount, res)
	}
	reason, detail := classifyNoToolAbort(state)
	if reason != "llm_malformed_tool_output" || !strings.Contains(strings.ToLower(detail), "stopped incomplete") {
		t.Fatalf("unexpected malformed classification: reason=%q detail=%q", reason, detail)
	}

	hookResetOnSuccess(state, nil)
	if state.MalformedToolOutputCount != 0 {
		t.Fatalf("healthy tool response did not reset malformed counter: %d", state.MalformedToolOutputCount)
	}
}

// classifyNoToolAbort must distinguish the density reasoning loop, a safety
// refusal, and the generic consecutive stall.
func TestClassifyNoToolAbort_Reasons(t *testing.T) {
	// Sustained non-consecutive loop → reasoning loop.
	dens := &ScanState{TotalNoToolResponses: 90, Iteration: 99} // 100 iters, ratio 0.9
	if reason, detail := classifyNoToolAbort(dens); reason != "llm_reasoning_loop" ||
		!strings.Contains(strings.ToLower(detail), "reasoning loop") {
		t.Errorf("density: reason=%q detail=%q, want llm_reasoning_loop", reason, detail)
	}

	// Repeated safety refusal → refusal.
	ref := &ScanState{RefusalCount: 3}
	if reason, _ := classifyNoToolAbort(ref); reason != "llm_safety_refusal" {
		t.Errorf("refusal: reason=%q, want llm_safety_refusal", reason)
	}

	// Short consecutive stall → generic no-tool-calls.
	stall := &ScanState{TotalNoToolResponses: 5, Iteration: 5}
	if reason, _ := classifyNoToolAbort(stall); reason != "llm_no_tool_calls" {
		t.Errorf("stall: reason=%q, want llm_no_tool_calls", reason)
	}
}
