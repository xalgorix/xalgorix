package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

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

func TestPlanGuidanceKeepsExploratoryCompletionPath(t *testing.T) {
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(&Task{
		ID: "test-novel-testing", VulnClass: "novel-testing", Origin: "auto",
		WholeTarget: true, Status: TaskPending,
	})
	a := &Agent{state: state}
	result, err := a.updatePlanTool(map[string]string{
		"task_id": "test-novel-testing", "status": "completed",
		"notes": "Compared baseline and mutated parser requests on observed inputs; no reproducible anomaly remained.",
	})
	if err != nil || result.Error != "" || state.Plan.Get("test-novel-testing").Status != TaskCompleted {
		t.Fatalf("exploratory completion must remain available: result=%+v err=%v", result, err)
	}

	promptAgent, _ := newBoundedContextAgent(t, false)
	prompt := promptAgent.buildSystemPrompt([]string{"https://example.test"}, "Perform an authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"})
	if !strings.Contains(prompt, "complete an exploratory task") {
		t.Fatal("system prompt must mention explicit exploratory completion")
	}
	tool, ok := promptAgent.registry.Get("update_plan")
	if !ok || !strings.Contains(strings.ToLower(tool.Description), "exploratory completion") {
		t.Fatal("tool schema must mention explicit exploratory completion")
	}
}
