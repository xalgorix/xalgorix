package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// A "finished" event flagged as an abnormal LLM-side abort must be captured on
// the session so finalize records the scan as failed (not a clean completion).
// Regression guard for scans that were force-stopped by the agent (LLM refused
// to call tools, empty responses, repeated errors, rate-limit) yet showed up as
// "completed" on the dashboard.
func TestProcessEvent_AbortedFinishedCapturesReason(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("abort-capture", t.TempDir())
	defer sctx.Close()

	sess := &scanSession{
		id:         "abort-capture",
		target:     "https://example.com",
		scanDir:    t.TempDir(),
		record:     &ScanRecord{ID: "abort-capture", Target: "https://example.com", Status: "running"},
		sctx:       sctx,
		server:     s,
		instanceID: "",
	}

	s.processEvent(agent.Event{
		Type:        "finished",
		Content:     "Agent stopped: LLM refused to call tools after 15 attempts",
		Aborted:     true,
		AbortReason: "llm_no_tool_calls",
	}, sess)

	if sess.abortReason != "llm_no_tool_calls" {
		t.Fatalf("abortReason = %q, want %q", sess.abortReason, "llm_no_tool_calls")
	}
}

// A clean finish (finish tool) must NOT set an abort reason — those scans are
// genuine completions.
func TestProcessEvent_CleanFinishHasNoAbortReason(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("clean-finish", t.TempDir())
	defer sctx.Close()

	sess := &scanSession{
		id:      "clean-finish",
		target:  "https://example.com",
		scanDir: t.TempDir(),
		record:  &ScanRecord{ID: "clean-finish", Target: "https://example.com", Status: "running"},
		sctx:    sctx,
		server:  s,
	}

	s.processEvent(agent.Event{
		Type:    "finished",
		Content: "Scan complete. Reported 3 findings.",
	}, sess)

	if sess.abortReason != "" {
		t.Fatalf("abortReason = %q, want empty for a clean finish", sess.abortReason)
	}
}

// An aborted event that omits an explicit reason still marks the session as
// aborted (with a generic tag) so it is never treated as a clean completion.
func TestProcessEvent_AbortedWithoutReasonUsesFallback(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("abort-fallback", t.TempDir())
	defer sctx.Close()

	sess := &scanSession{
		id:      "abort-fallback",
		target:  "https://example.com",
		scanDir: t.TempDir(),
		record:  &ScanRecord{ID: "abort-fallback", Target: "https://example.com", Status: "running"},
		sctx:    sctx,
		server:  s,
	}

	s.processEvent(agent.Event{Type: "finished", Content: "stopped", Aborted: true}, sess)

	if sess.abortReason != "llm_aborted" {
		t.Fatalf("abortReason = %q, want %q", sess.abortReason, "llm_aborted")
	}
}

func TestProcessEvent_DelegatedAbortDoesNotAbortRootSession(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("delegated-abort", t.TempDir())
	defer sctx.Close()

	sess := &scanSession{
		id:      "delegated-abort",
		target:  "https://example.com",
		scanDir: t.TempDir(),
		record:  &ScanRecord{ID: "delegated-abort", Target: "https://example.com", Status: "running"},
		sctx:    sctx,
		server:  s,
	}

	s.processEvent(agent.Event{
		Type:        "finished",
		Content:     "specialist stopped incomplete",
		AgentID:     "sub_1",
		Aborted:     true,
		AbortReason: "llm_malformed_tool_output",
	}, sess)

	if sess.abortReason != "" {
		t.Fatalf("delegated abort poisoned root abortReason: %q", sess.abortReason)
	}
}
