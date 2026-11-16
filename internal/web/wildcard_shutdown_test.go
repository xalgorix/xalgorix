package web

import (
	"context"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// A child that a shutdown or signal cut short is not an assessed host.
func TestWildcardChildInterruptedOnlyForRecoverableStops(t *testing.T) {
	tests := []struct {
		name string
		rec  *ScanRecord
		want bool
	}{
		{"nil record", nil, false},
		{"graceful shutdown", &ScanRecord{Status: "stopped", StopReason: "server_shutdown"}, true},
		{"signal", &ScanRecord{Status: "stopped", StopReason: "signal_terminated"}, true},
		{"restart placeholder", &ScanRecord{Status: "stopped", StopReason: "server_restart_resuming"}, true},
		{"recovered panic", &ScanRecord{Status: "stopped", StopReason: "panic_recovered"}, true},
		{"user stop", &ScanRecord{Status: "stopped", StopReason: "user_stopped"}, false},
		{"partial finish", &ScanRecord{Status: "finished", Completion: "partial", StopReason: "finish_gate_exhausted"}, false},
		{"full finish", &ScanRecord{Status: "finished", Completion: "full"}, false},
		{"failed", &ScanRecord{Status: "failed", StopReason: "llm_repeated_errors"}, false},
		{"still running", &ScanRecord{Status: "running"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wildcardChildInterrupted(tt.rec); got != tt.want {
				t.Fatalf("wildcardChildInterrupted(%+v) = %v, want %v", tt.rec, got, tt.want)
			}
		})
	}
}

// During a server shutdown the instance can still read "running" (the signal
// handler flips statuses after it stops the agents). The subdomain loop must
// neither dispatch nor count a host in that window, and must leave the parent
// recoverable with the resume index on the first unassessed host.
func TestWildcardLoopKeepsResumeIndexDuringServerShutdown(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "wildcard-shutdown-resume", ScanMode: "wildcard", Status: "running"}
	s.instances[inst.ID] = inst
	dir := s.makeScanDir("example.invalid")
	s.saveScanRecordTo(&ScanRecord{
		ID: "wildcard-shutdown-parent", InstanceID: inst.ID, Target: "example.invalid", ScanMode: "wildcard", Status: "running",
		SubScans: []SubScanSummary{
			{ID: "done-child", Target: "a.example.invalid", Status: "finished", Completion: "full"},
			{ID: "interrupted-child", Target: "b.example.invalid", Status: "stopped", StopReason: "server_shutdown"},
			{Target: "example.invalid", Status: "pending"},
		},
	}, dir)
	close(s.shutdownChan)

	req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true,
		ResumeSubdomains: []string{"a.example.invalid", "b.example.invalid", "example.invalid"}, ResumeSubIndex: 1}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runWildcardTarget(context.Background(), &config.Config{}, req, "example.invalid", 0, 1)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("subdomain loop dispatched a host assessment after the server began shutting down")
	}

	parent, ok := loadScanRecordFromDir(dir)
	if !ok {
		t.Fatal("parent record missing")
	}
	if parent.Status != "stopped" || parent.StopReason != "server_shutdown" || !isInterruptedRecoverableRecord(parent.Status, parent.StopReason) {
		t.Fatalf("shutdown left the parent unrecoverable: status=%q reason=%q", parent.Status, parent.StopReason)
	}
	for _, child := range parent.SubScans {
		if child.Target != "a.example.invalid" && child.Status == "finished" {
			t.Fatalf("shutdown marked %s finished: %+v", child.Target, child)
		}
	}
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(inst.ID))
	if err != nil || entry.state == nil {
		t.Fatalf("queue state missing: %v", err)
	}
	if entry.state.WildcardSubIndex != 1 {
		t.Fatalf("shutdown advanced the resume index to %d, want 1", entry.state.WildcardSubIndex)
	}
}
