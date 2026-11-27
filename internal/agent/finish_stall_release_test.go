package agent

import "testing"

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
