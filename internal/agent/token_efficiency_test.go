package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestSupersededPlanBriefPreservesOtherContext(t *testing.T) {
	old := "## Active Plan — 10% executed\nNext tasks ready to run:\n  ▶ recon"
	current := "## Active Plan — 20% executed\nNext tasks ready to run:\n  ▶ [Phase 6] test-sqli — Test input"
	other := "Collect the delegated result before finishing."
	state := NewScanState()
	state.Plan = NewPlan()
	a := &Agent{state: state, messages: []llm.Message{
		{Role: "system", Content: "system instructions"},
		{Role: "user", Content: old + "\n\n" + other},
		{Role: "assistant", Content: "tested one endpoint"},
		{Role: "user", Content: "Tool 'http_request' result:\nHTTP 200"},
	}}
	a.removeSupersededPlanBrief(old, current)
	if len(a.messages) != 4 {
		t.Fatalf("message count = %d, want 4", len(a.messages))
	}
	if a.messages[1].Content != other {
		t.Fatalf("other directive changed: %q", a.messages[1].Content)
	}
	if a.messages[0].Content != "system instructions" ||
		a.messages[2].Content != "tested one endpoint" ||
		!strings.Contains(a.messages[3].Content, "HTTP 200") {
		t.Fatal("non-plan context changed")
	}
	a.removeSupersededPlanBrief(old, current)
	if len(a.messages) != 4 || a.messages[1].Content != other {
		t.Fatal("removal must be idempotent")
	}
}

func TestSupersededPlanBriefDropsStandaloneSnapshot(t *testing.T) {
	old := "## Active Plan — 10% executed\nNext tasks ready to run:\n  ▶ [Phase 1] recon — Reconnaissance"
	current := "## Active Plan — 20% executed\nNext tasks ready to run:\n  ▶ [Phase 6] test-sqli — Test input"
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "recon", Status: TaskCompleted})
	a := &Agent{state: state, messages: []llm.Message{
		{Role: "system", Content: "system"},
		{Role: "user", Content: old},
		{Role: "user", Content: "latest tool evidence"},
	}}
	a.removeSupersededPlanBrief(old, current)
	if len(a.messages) != 2 || a.messages[1].Content != "latest tool evidence" {
		t.Fatalf("stale snapshot was retained or evidence lost: %+v", a.messages)
	}
}

func TestSupersededPlanBriefKeepsUnfinishedTaskHint(t *testing.T) {
	old := "## Active Plan — 10% executed\nNext tasks ready to run:\n  ▶ [Phase 8] idor — Test role boundary"
	current := "## Active Plan — 20% executed\nNext tasks ready to run:\n  ▶ [Phase 6] test-sqli — Test input"
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "idor", Status: TaskActive})
	a := &Agent{state: state, messages: []llm.Message{{Role: "user", Content: old}}}
	a.removeSupersededPlanBrief(old, current)
	if len(a.messages) != 1 || a.messages[0].Content != old {
		t.Fatal("unfinished task hint was removed from context")
	}
}

func TestFinishRecoveryCategoryOnlyForPendingNextRequest(t *testing.T) {
	state := NewScanState()
	state.FinishAttempts = 3
	if got := reasoningRequestCategory(state); got != scanctx.CategoryNormalReasoning {
		t.Fatalf("old finish attempts cannot classify later work: %q", got)
	}
	state.FinishRecoveryPending = true
	if got := reasoningRequestCategory(state); got != scanctx.CategoryFinishRejectionRecovery {
		t.Fatalf("immediate recovery category = %q", got)
	}
	state.FinishRecoveryPending = false
	if got := reasoningRequestCategory(state); got != scanctx.CategoryNormalReasoning {
		t.Fatalf("subsequent productive work category = %q", got)
	}
	state.FinishRecoveryPending = true
	state.PendingFailedReportCalls = 1
	if got := reasoningRequestCategory(state); got != scanctx.CategoryMalformedToolRecovery {
		t.Fatalf("report repair must take precedence: %q", got)
	}
}
