package agent

import (
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
