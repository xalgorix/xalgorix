package agent

import (
	"strings"
	"testing"
)

// The finish text reaches customers through hosted dashboards' scan logs, so it
// must use plain words and no engine internals, while still never reading as
// full coverage when work remains.

var engineJargon = []string{
	"⚠️", "ASSESSMENT", "untested_at_finish", "finish_gate_exhausted", "hypothesis ledger",
	"principled finish", "iterations", "diminishing-returns", "residual", "WITHOUT",
}

func assertNoJargon(t *testing.T, text string) {
	t.Helper()
	for _, term := range engineJargon {
		if strings.Contains(text, term) {
			t.Errorf("customer-facing text contains engine jargon %q:\n%s", term, text)
		}
	}
}

func TestCoverageNote_UntestedAtFinishIsPlainAndHonest(t *testing.T) {
	reasons := []string{StopReasonUntestedAtFinish + ": " + plannedChecks(22) + " closed at the finish without running"}
	note := formatIncompleteSummary(CompletionStatusIncomplete, reasons)
	assertNoJargon(t, note)
	for _, want := range []string{
		"before every planned check ran",
		"may still have issues",
		"22 planned checks were closed at the finish without running",
		"Resume or re-run the scan",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("coverage note missing %q:\n%s", want, note)
		}
	}
}

func TestCoverageNote_BlockedWorkIsPlain(t *testing.T) {
	note := formatIncompleteSummary(CompletionStatusCompletedWithBlocked, nil)
	assertNoJargon(t, note)
	if !strings.Contains(note, "blocked") {
		t.Errorf("blocked-work note must say checks were blocked:\n%s", note)
	}
}

func TestCustomerReason(t *testing.T) {
	cases := map[string]string{
		StopReasonUntestedAtFinish + ": 3 planned checks were closed at the finish without running":            "3 planned checks were closed at the finish without running",
		StopReasonFinishGateExhausted + ": the scan reached its finish limit before every check was confirmed": "the scan reached its finish limit before every check was confirmed",
		"hypotheses claimed but not closed: H-3, H-7":                                                          "leads still open: H-3, H-7",
		"hypotheses proven but unreported: H-1":                                                                "confirmed leads not yet reported: H-1",
		`plan task "test-sqli" (phase 9) pending`:                                                              `planned check "test-sqli" (phase 9) pending`,
		"something new": "something new",
	}
	for in, want := range cases {
		if got := customerReason(in); got != want {
			t.Errorf("customerReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// The reworded reason must still carry its typed prefix, or the scan record
// would lose its stop reason.
func TestUntestedReasonKeepsTypedStopReason(t *testing.T) {
	r := StopReasonUntestedAtFinish + ": " + plannedChecks(2) + " closed at the finish without running"
	if got := completionStopReason([]string{r}); got != StopReasonUntestedAtFinish {
		t.Fatalf("completionStopReason = %q, want %q", got, StopReasonUntestedAtFinish)
	}
}

func TestSaturatedCoverageSentence(t *testing.T) {
	cases := []struct {
		untested, touched, applicable int
		want                          string
	}{
		{22, 0, 2, " 22 planned checks did not run, and injection testing reached 0 of 2 routes that accept input."},
		{1, 1, 1, " 1 planned check did not run, and injection testing reached 1 of 1 route that accepts input."},
		{5, 0, 0, " 5 planned checks did not run."},
		{0, 3, 4, " Injection testing reached 3 of 4 routes that accept input."},
		{0, 0, 0, ""},
	}
	for _, c := range cases {
		got := saturatedCoverageSentence(c.untested, c.touched, c.applicable)
		if got != c.want {
			t.Errorf("saturatedCoverageSentence(%d,%d,%d) = %q, want %q", c.untested, c.touched, c.applicable, got, c.want)
		}
		assertNoJargon(t, got)
	}
}

func TestPlannedChecksPlural(t *testing.T) {
	if got := plannedChecks(1); got != "1 planned check was" {
		t.Errorf("plannedChecks(1) = %q", got)
	}
	if got := plannedChecks(4); got != "4 planned checks were" {
		t.Errorf("plannedChecks(4) = %q", got)
	}
}
