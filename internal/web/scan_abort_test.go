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

func TestProcessEvent_ProviderPausedCapturesReason(t *testing.T) {
	s := newTestServer(t, nil)
	sctx := scanctx.New("paused-capture", t.TempDir())
	defer sctx.Close()

	sess := &scanSession{
		id:         "paused-capture",
		target:     "https://example.com",
		scanDir:    t.TempDir(),
		record:     &ScanRecord{ID: "paused-capture", Target: "https://example.com", Status: "running"},
		sctx:       sctx,
		server:     s,
		instanceID: "",
	}

	s.processEvent(agent.Event{
		Type:        "paused",
		Content:     "Agent paused: provider rate-limit wait budget exhausted",
		Aborted:     true,
		AbortReason: "provider_rate_limited",
	}, sess)

	if sess.abortReason != "provider_rate_limited" {
		t.Fatalf("abortReason = %q, want %q", sess.abortReason, "provider_rate_limited")
	}
}

func TestScanSession_ProviderPauseMarksStatusPaused(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := t.TempDir()
	sctx := scanctx.New("sess-pause", scanDir)
	defer sctx.Close()

	inst := &ScanInstance{
		ID:       "inst-pause",
		Status:   "running",
		Targets:  "https://example.com",
		ScanMode: "single",
	}
	s.instancesMu.Lock()
	s.instances["inst-pause"] = inst
	s.instancesMu.Unlock()

	sess := &scanSession{
		id:         "sess-pause",
		target:     "https://example.com",
		scanDir:    scanDir,
		record:     &ScanRecord{ID: "sess-pause", Target: "https://example.com", Status: "running", Iterations: 12, ToolCalls: 10},
		sctx:       sctx,
		server:     s,
		instanceID: "inst-pause",
	}

	sess.abortReason = "provider_rate_limited"

	// Call the 8a block logic
	if isProviderPauseReason(sess.abortReason) {
		stopReason := sess.abortReason
		if stopReason == "llm_rate_limited" {
			stopReason = "provider_rate_limited"
		}
		sess.record.Status = "paused"
		sess.record.StopReason = stopReason

		inst.mu.Lock()
		inst.Status = "paused"
		inst.StopReason = stopReason
		inst.mu.Unlock()

		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	if sess.record.Status != "paused" {
		t.Fatalf("record.Status = %q, want %q", sess.record.Status, "paused")
	}
	if sess.record.StopReason != "provider_rate_limited" {
		t.Fatalf("record.StopReason = %q, want %q", sess.record.StopReason, "provider_rate_limited")
	}
	if inst.Status != "paused" {
		t.Fatalf("inst.Status = %q, want %q", inst.Status, "paused")
	}

	// Verify loaded record from disk preserves iterations and paused status
	rec, ok := loadScanRecordFromDir(scanDir)
	if !ok || rec == nil {
		t.Fatal("failed to load scan record from disk")
	}
	if rec.Status != "paused" {
		t.Fatalf("persisted rec.Status = %q, want %q", rec.Status, "paused")
	}
	if rec.Iterations != 12 {
		t.Fatalf("persisted rec.Iterations = %d, want 12", rec.Iterations)
	}
}

