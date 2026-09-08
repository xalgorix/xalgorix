package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// A recovered/parsed call must be persisted in canonical <function=…> form so
// the model doesn't few-shot-mimic malformed tool-call XML. The rendered turn
// must round-trip back through ParseToolCalls to the same call.
func TestCanonicalizeAssistantTurn_RoundTrips(t *testing.T) {
	calls := []llm.ToolCall{
		{Name: "terminal_execute", Args: map[string]string{"command": "curl -sI https://t/"}},
	}
	got := canonicalizeAssistantTurn("Let me probe the target.", calls)

	if !strings.Contains(got, "Let me probe the target.") {
		t.Errorf("clean prose not preserved: %q", got)
	}
	if !strings.Contains(got, "<function=terminal_execute>") {
		t.Errorf("canonical open tag missing: %q", got)
	}

	reparsed := llm.ParseToolCalls(got)
	if len(reparsed) != 1 || reparsed[0].Name != "terminal_execute" {
		t.Fatalf("canonical form did not round-trip: %+v", reparsed)
	}
	if reparsed[0].Args["command"] != "curl -sI https://t/" {
		t.Errorf("command arg lost in round-trip: %v", reparsed[0].Args)
	}
}

// The exact flare-network shape: the model dropped "<function=" so CleanContent
// leaves the malformed residue (`terminal_execute>` + orphaned <parameter> +
// stray </function>) in the prose. The canonical turn must NOT contain that
// residue — only the clean canonical call — else the malformation leaks back
// into history and the model keeps mimicking it.
func TestCanonicalizeAssistantTurn_StripsMalformedResidue(t *testing.T) {
	residue := "terminal_execute>\n<parameter=command>curl -v https://portal.flare.network/ 2>&1 | head</parameter>\n</function>"
	calls := []llm.ToolCall{
		{Name: "terminal_execute", Args: map[string]string{"command": "curl -v https://portal.flare.network/ 2>&1 | head"}},
	}
	got := canonicalizeAssistantTurn(residue, calls)

	// Residue would show up as a DUPLICATED param block (orphaned one + the
	// canonical one) or a bare name line not preceded by "<function=".
	if strings.Count(got, "<parameter=command>") != 1 {
		t.Errorf("residue leaked — expected exactly one <parameter=command>: %q", got)
	}
	if strings.HasPrefix(got, "terminal_execute>") {
		t.Errorf("bare tool-name residue leaked at start: %q", got)
	}
	// Exactly one well-formed open tag, and it round-trips to a single call.
	if strings.Count(got, "<function=terminal_execute>") != 1 {
		t.Errorf("expected exactly one canonical open tag: %q", got)
	}
	if calls := llm.ParseToolCalls(got); len(calls) != 1 || calls[0].Args["command"] == "" {
		t.Fatalf("canonical turn did not round-trip cleanly: %+v", calls)
	}
}

// With no clean prose, the turn is just the canonical call(s), no leading blank.
func TestCanonicalizeAssistantTurn_NoProse(t *testing.T) {
	got := canonicalizeAssistantTurn("", []llm.ToolCall{
		{Name: "finish", Args: map[string]string{"summary": "done"}},
	})
	if strings.HasPrefix(got, "\n") || strings.TrimSpace(got) != got {
		t.Errorf("unexpected leading/trailing whitespace: %q", got)
	}
	if calls := llm.ParseToolCalls(got); len(calls) != 1 || calls[0].Name != "finish" {
		t.Fatalf("expected 1 finish call, got %+v", calls)
	}
}

func TestAuthoritativeFinishSummary(t *testing.T) {
	got := authoritativeFinishSummary("Completed with 24 findings.", 23)
	if !strings.HasPrefix(got, "Authoritative verified finding count: 23") {
		t.Fatalf("authoritative count missing: %q", got)
	}
	if !strings.Contains(got, "Agent narrative:\nCompleted with 24 findings.") {
		t.Fatalf("agent narrative should remain available but labeled: %q", got)
	}
}
