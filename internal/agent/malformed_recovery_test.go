package agent

import (
	"strings"
	"testing"
)

// malformed_recovery_test.go — regression coverage for the malformed
// tool-output recovery path: the protocol-reset example must teach a call
// that actually validates (add_note takes key/value, not content), the
// recovery temperature must break the deterministic re-emit loop, and
// recovery nudges must not stack duplicates.

func TestProtocolResetNoteExampleUsesKeyAndValue(t *testing.T) {
	state := NewScanState()
	state.MalformedToolOutputCount = MalformedToolContextResetAt
	res := hookNoToolHandler(state, map[string]string{
		"response":         "prose residue mentioning protocols",
		"malformed_reason": "unparsed_tool_call",
	})
	if !strings.Contains(res.Nudge, "PROTOCOL RESET") {
		t.Fatalf("expected the protocol-reset nudge, got %q", res.Nudge)
	}
	if strings.Contains(res.Nudge, "<parameter=content>") {
		t.Fatal("the reset example must not use add_note's nonexistent content parameter")
	}
	if !strings.Contains(res.Nudge, "<parameter=key>") || !strings.Contains(res.Nudge, "<parameter=value>") {
		t.Fatal("the reset example must use add_note's real key/value parameters")
	}
}

func TestScannerTemperatureForMalformedRecovery(t *testing.T) {
	clean := NewScanState()
	if got := scannerTemperatureFor(clean); got != 0.0 {
		t.Fatalf("clean scan temperature=%v, want 0.0", got)
	}
	malformed := NewScanState()
	malformed.MalformedToolOutputCount = 1
	if got := scannerTemperatureFor(malformed); got != 0.2 {
		t.Fatalf("malformed-recovery temperature=%v, want 0.2", got)
	}
	stuck := NewScanState()
	stuck.ConsecutiveErrors = 1
	if got := scannerTemperatureFor(stuck); got != 0.2 {
		t.Fatalf("error-retry temperature=%v, want 0.2", got)
	}
	if got := scannerTemperatureFor(nil); got != 0.0 {
		t.Fatalf("nil state temperature=%v, want 0.0", got)
	}
}

func TestAppendUserNudgeDeduplicatesBackToBackIdenticals(t *testing.T) {
	a := &Agent{}
	a.appendUserNudge("nudge A")
	a.appendUserNudge("nudge A")
	if len(a.messages) != 1 {
		t.Fatalf("identical back-to-back nudge must not stack, got %d messages", len(a.messages))
	}
	a.appendUserNudge("nudge B")
	if len(a.messages) != 2 {
		t.Fatalf("a distinct nudge must append, got %d messages", len(a.messages))
	}
	a.appendUserNudge("nudge A")
	if len(a.messages) != 3 {
		t.Fatalf("alternating nudges must all append, got %d messages", len(a.messages))
	}
}
