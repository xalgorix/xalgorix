package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestPartialFinalizationPublishesExactStopReason(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "outcome-instance", Status: "running", ScanMode: "single"}
	s.instances[inst.ID] = inst
	sess := &scanSession{
		instanceID: inst.ID, scanDir: s.makeScanDir("example.invalid"), abortReason: "stuck_loop_limit",
		record: &ScanRecord{ID: "outcome-record", InstanceID: inst.ID, ScanMode: "single", Status: "running"},
	}
	if !s.finalizeScanSessionRecord(sess) {
		t.Fatal("partial assessment should retain its report")
	}
	if inst.Completion != "partial" || inst.StopReason != "stuck_loop_limit" {
		t.Fatal("session finalization did not publish the coordinator's partial outcome")
	}
	inst.Status = "finished"
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/"+inst.ID+"/snapshot", nil))
	var snapshot ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || snapshot.StopReason != "stuck_loop_limit" || snapshot.Completion != "partial" {
		t.Fatalf("partial terminal facts missing from exact snapshot: status=%d completion=%q reason=%q", rr.Code, snapshot.Completion, snapshot.StopReason)
	}
	durable, err := s.loadExactDispatchSnapshot(inst.ID)
	if err != nil || durable.StopReason != "stuck_loop_limit" {
		t.Fatalf("durable exact snapshot lost stop reason: %v", err)
	}
}

func TestTerminalSnapshotRecoversMissingReasonFromOwnedRecord(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "legacy-outcome-instance", Status: "finished", ScanMode: "single", Completion: "partial", PlanPresent: true, PlanTasksTotal: 2, PlanTasksUnfinished: 2}
	s.instances[inst.ID] = inst
	s.saveScanRecordTo(&ScanRecord{
		ID: "legacy-outcome-record", InstanceID: inst.ID, ScanMode: "single", Status: "finished",
		Completion: "partial", StopReason: "stuck_loop_limit", PlanPresent: true, PlanTasksTotal: 2, PlanTasksUnfinished: 2,
	}, s.makeScanDir("example.invalid"))
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		t.Fatal(err)
	}
	s.hydrateTerminalIntegrity(inst)
	if inst.StopReason != "stuck_loop_limit" {
		t.Fatal("populated completion and plan counters hid the missing terminal reason")
	}
	durable, err := s.loadExactDispatchSnapshot(inst.ID)
	if err != nil || durable.StopReason != "stuck_loop_limit" {
		t.Fatalf("recovered reason was not durable: %v", err)
	}
	delete(s.instances, inst.ID)
	durable.StopReason = ""
	if err := s.saveExactDispatchSnapshot(durable); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/"+inst.ID+"/snapshot", nil))
	var snapshot ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || snapshot.StopReason != "stuck_loop_limit" {
		t.Fatal("persisted snapshot without a live instance did not recover the owned terminal outcome")
	}
}

func TestTerminalReasonRecoveryRejectsAmbiguousOwnership(t *testing.T) {
	s := newTestServer(t, nil)
	for _, target := range []string{"a.example.invalid", "b.example.invalid"} {
		s.saveScanRecordTo(&ScanRecord{ID: target, InstanceID: "ambiguous-outcome", ScanMode: "single", Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit"}, s.makeScanDir(target))
	}
	rec := &ScanRecord{ID: "ambiguous-outcome", InstanceID: "ambiguous-outcome", Status: "finished", Completion: "partial"}
	s.reconcileTerminalStopReason(rec)
	if rec.StopReason != "" {
		t.Fatal("ambiguous physical ownership supplied an authoritative reason")
	}
}

func TestSessionReasonDoesNotOverwriteWildcardCoordinatorOrUserStop(t *testing.T) {
	for _, mode := range []string{"discovery", "child", "user-stop"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, nil)
			inst := &ScanInstance{ID: "outcome-scope", Status: "running"}
			rec := &ScanRecord{InstanceID: inst.ID, ScanMode: "wildcard", Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit"}
			if mode == "child" {
				rec.ParentTarget = "example.invalid"
			}
			if mode == "user-stop" {
				rec.ScanMode = "single"
				inst.Status, inst.StopReason = "stopped", "user_stopped"
			}
			expected := inst.StopReason
			s.instances[inst.ID] = inst
			s.mirrorScanIntegrity(inst.ID, rec)
			if inst.StopReason != expected {
				t.Fatal("session outcome overwrote an independently owned coordinator reason")
			}
		})
	}
}

func TestWildcardDiscoveryReplayPreservesChildOutcomes(t *testing.T) {
	s := newTestServer(t, nil)
	children := []SubScanSummary{
		{ID: "finished-child", Target: "a.example.invalid", Status: "finished", StartedAt: "2026-01-01T00:00:00Z", FinishedAt: "2026-01-01T01:00:00Z"},
		{ID: "failed-child", Target: "b.example.invalid", Status: "failed"},
		{ID: "stopped-child", Target: "c.example.invalid", Status: "stopped"},
		{ID: "running-child", Target: "d.example.invalid", Status: "running"},
	}
	rec := &ScanRecord{ID: "wildcard-outcomes", ScanMode: "wildcard", Target: "example.invalid", Status: "running", SubScans: cloneSubScanSummaries(children),
		Events: []WSEvent{{Type: "subdomains_discovered", Target: "example.invalid", ParentTarget: "example.invalid", SubTargetTotal: 4,
			Output: "a.example.invalid\nb.example.invalid\nc.example.invalid\nd.example.invalid"}}}
	s.attachWildcardSubScansFrom(rec, nil)
	for _, expected := range children {
		for _, actual := range rec.SubScans {
			if actual.Target == expected.Target && actual.Status != expected.Status {
				t.Errorf("discovery replay changed %s from %q to %q", expected.ID, expected.Status, actual.Status)
			}
		}
	}
	if rec.SubScanCompleted != 3 || rec.SubScanRunning != 1 || rec.SubScanRemaining != 0 {
		t.Errorf("discovery replay regressed child counters: %d completed, %d running, %d remaining", rec.SubScanCompleted, rec.SubScanRunning, rec.SubScanRemaining)
	}
}

func TestWildcardResumeWithSavedTargetsPreservesDurableOutcomes(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "wildcard-resume-outcomes", Status: "running", ScanMode: "wildcard"}
	s.instances[inst.ID] = inst
	dir := s.makeScanDir("example.invalid")
	children := []SubScanSummary{
		{ID: "finished-child", Target: "example.invalid", Status: "finished", StartedAt: "2026-01-01T00:00:00Z", FinishedAt: "2026-01-01T01:00:00Z", VulnCount: 1, TotalTokens: 100},
		{ID: "failed-child", Target: "b.example.invalid", Status: "failed", StartedAt: "2026-01-01T02:00:00Z", FinishedAt: "2026-01-01T03:00:00Z"},
		{ID: "stopped-child", Target: "c.example.invalid", Status: "stopped", StartedAt: "2026-01-01T04:00:00Z", FinishedAt: "2026-01-01T05:00:00Z"},
	}
	s.saveScanRecordTo(&ScanRecord{ID: "wildcard-parent-record", InstanceID: inst.ID, Target: "example.invalid", ScanMode: "wildcard", Status: "stopped", SubScans: children}, dir)
	req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true,
		ResumeSubdomains: []string{"example.invalid", "b.example.invalid", "c.example.invalid"}, ResumeSubIndex: 3}
	s.runWildcardTarget(context.Background(), &config.Config{}, req, "example.invalid", 0, 1)
	rec, ok := loadScanRecordFromDir(dir)
	if !ok || len(rec.SubScans) != len(children) {
		t.Fatal("resumed child inventory missing")
	}
	for i, expected := range children {
		if rec.SubScans[i] != expected {
			t.Errorf("resuming saved targets rewrote durable child facts: got %+v want %+v", rec.SubScans[i], expected)
		}
	}
}
