package reporting

import (
	"strings"
	"testing"
)

// TestMethodologyRowsFromPhaseStatus (Part 54): with authoritative derived
// dispositions, the report renders completed / not applicable / blocked /
// not selected accurately — never inferring methodology completion from
// phase number ordering.
func TestMethodologyRowsFromPhaseStatus(t *testing.T) {
	scan := &Scan{
		Phases:      nil, // full methodology selected
		PhaseStatus: map[string]string{"1": "completed", "2": "not_applicable", "5": "blocked", "6": "completed", "12": "active", "22": "pending"},
		PhaseReasons: map[string]string{
			"2":  "no anomaly/exposure obligations on the observed surface",
			"5":  "auth-session: blocked_missing_auth",
			"22": "scan still running",
		},
	}
	rows := MethodologyRows(scan)
	if len(rows) != 22 {
		t.Fatalf("rows = %d, want 22", len(rows))
	}
	byPhase := map[int]MethodologyRow{}
	for _, r := range rows {
		byPhase[r.Num] = r
	}
	if byPhase[1].Status != MethodologyStatusCompleted {
		t.Errorf("phase 1 = %q, want COMPLETED", byPhase[1].Status)
	}
	if byPhase[2].Status != MethodologyStatusNotApplicable || !strings.Contains(byPhase[2].Reason, "no anomaly") {
		t.Errorf("phase 2 = %q (%q), want NOT APPLICABLE with reason", byPhase[2].Status, byPhase[2].Reason)
	}
	if byPhase[5].Status != MethodologyStatusBlocked || !strings.Contains(byPhase[5].Reason, "blocked_missing_auth") {
		t.Errorf("phase 5 = %q (%q), want BLOCKED with the typed reason", byPhase[5].Status, byPhase[5].Reason)
	}
	if byPhase[6].Status != MethodologyStatusCompleted {
		t.Errorf("phase 6 = %q, want COMPLETED", byPhase[6].Status)
	}
	if byPhase[12].Status != MethodologyStatusPending {
		t.Errorf("phase 12 = %q, want PENDING (active at render time)", byPhase[12].Status)
	}
	// A phase with NO entry falls back to the legacy view, not "completed".
	if byPhase[9].Status != MethodologyStatusSelected {
		t.Errorf("phase 9 = %q, want SELECTED (legacy fallback: selected but not yet dispositioned)", byPhase[9].Status)
	}
}

// TestMethodologyRowsLegacyFallback (Part 53 semantics at the report
// layer): for legacy records without phase_status, CurrentPhase-style
// ordering must never mark phases executed. Phases 2,4,7,8,9,10,11,13-19
// were skipped past and must NOT render as executed even though
// phases_worked contains phase 20.
func TestMethodologyRowsLegacyFallback(t *testing.T) {
	scan := &Scan{
		Phases:       []int{1, 3, 5, 6, 12, 20, 22},
		PhasesWorked: []int{1, 3, 5, 6, 12, 20},
	}
	rows := MethodologyRows(scan)
	byPhase := map[int]MethodologyRow{}
	for _, r := range rows {
		byPhase[r.Num] = r
	}
	for _, worked := range []int{1, 3, 5, 6, 12, 20} {
		if byPhase[worked].Status != MethodologyStatusExecuted {
			t.Errorf("worked phase %d = %q, want EXECUTED", worked, byPhase[worked].Status)
		}
	}
	for _, skippedPast := range []int{2, 4, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 21} {
		if byPhase[skippedPast].Status == MethodologyStatusExecuted || byPhase[skippedPast].Status == MethodologyStatusCompleted {
			t.Errorf("phase %d was never worked but renders %q", skippedPast, byPhase[skippedPast].Status)
		}
		if byPhase[skippedPast].Status != MethodologyStatusNotSelected {
			t.Errorf("phase %d = %q, want NOT SELECTED (not in the operator's selection either)", skippedPast, byPhase[skippedPast].Status)
		}
	}
	// Phase 22 is in the selection but was never worked: selected, never
	// executed.
	if byPhase[22].Status != MethodologyStatusSelected {
		t.Errorf("phase 22 = %q, want SELECTED (selected but unworked)", byPhase[22].Status)
	}
}

// TestMethodologyRowsNeverClaimsFullExecutionFromSelection: an empty
// selection (all phases) with zero work renders SELECTED everywhere — the
// report never says "all 22 phases executed" merely because everything was
// selected.
func TestMethodologyRowsNeverClaimsFullExecutionFromSelection(t *testing.T) {
	rows := MethodologyRows(&Scan{})
	for _, r := range rows {
		if r.Status == MethodologyStatusExecuted || r.Status == MethodologyStatusCompleted {
			t.Errorf("phase %d renders %q with zero evidence", r.Num, r.Status)
		}
	}
}
