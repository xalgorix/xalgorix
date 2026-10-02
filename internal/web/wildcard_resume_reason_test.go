package web

import (
	"reflect"
	"testing"
)

func TestWildcardCompletedParentDropsResumeMarker(t *testing.T) {
	for _, partial := range []bool{false, true} {
		parent := fullWildcardAssessment()
		parent.StopReason = "server_restart_resuming"
		if partial {
			parent.SubScans[1].Completion = "partial"
			parent.SubScans[1].StopReason = "stuck_loop_limit"
			parent.SubScans[1].PlanTasksCompleted = 1
			parent.SubScans[1].PlanTasksUnfinished = 4
		}
		children := cloneSubScanSummaries(parent.SubScans)
		aggregateWildcardAssessment(parent)
		wantReason, wantCompletion := "", "full"
		if partial {
			wantReason, wantCompletion = "wildcard_assessment_incomplete", "partial"
		}
		if parent.StopReason != wantReason || parent.Completion != wantCompletion {
			t.Fatalf("partial=%v: got %q/%q, want %q/%q", partial, parent.Completion, parent.StopReason, wantCompletion, wantReason)
		}
		if !reflect.DeepEqual(parent.SubScans, children) {
			t.Fatal("clearing the parent recovery marker changed independent child facts")
		}
	}
}

func TestWildcardResumeMarkerRetainsRecoverableInterruption(t *testing.T) {
	for _, status := range []string{"pending", "stopped", "paused", "failed"} {
		parent := fullWildcardAssessment()
		parent.Status, parent.StopReason = status, "server_restart_resuming"
		aggregateWildcardAssessment(parent)
		if parent.StopReason != "server_restart_resuming" {
			t.Fatalf("status=%q lost its recovery marker", status)
		}
	}
}

func TestWildcardCompletedParentPreservesExplicitReason(t *testing.T) {
	for _, reason := range []string{"user_stopped", "target_unresponsive", "operator_canceled", "unknown_failure_reason"} {
		parent := fullWildcardAssessment()
		parent.StopReason = reason
		parent.SubScans[1].Completion = "partial"
		aggregateWildcardAssessment(parent)
		if parent.StopReason != reason || parent.Completion != "partial" {
			t.Fatalf("explicit reason %q was overwritten", reason)
		}
	}
}

func TestWildcardTerminalHydrationClearsStaleResumeReason(t *testing.T) {
	s := newTestServer(t, nil)
	parent := fullWildcardAssessment()
	parent.ID, parent.StopReason = parent.InstanceID, "server_restart_resuming"
	parent.StartedAt, parent.FinishedAt = "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"
	parent.SubScans = []SubScanSummary{{ID: "physical", Target: parent.Target, Status: "finished"}}
	parent.SubScanTotal, parent.Discovery = 1, nil
	if err := s.saveExactDispatchSnapshot(parent); err != nil {
		t.Fatal(err)
	}
	child := ScanRecord{
		ID: "physical", InstanceID: parent.InstanceID, ParentTarget: parent.Target, Target: parent.Target,
		Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit",
		StartedAt: "2026-01-01T00:01:00Z", FinishedAt: "2026-01-01T00:59:00Z",
		PlanPresent: true, PlanTasksTotal: 27, PlanTasksCompleted: 1, PlanTasksUnfinished: 26,
	}
	s.saveScanRecordTo(&child, s.makeScanDir("physical"))
	inst := &ScanInstance{
		ID: parent.InstanceID, Status: "finished", ScanMode: "wildcard", StopReason: "server_restart_resuming",
		StartedAt: parent.StartedAt, FinishedAt: parent.FinishedAt,
		SubScans: cloneSubScanSummaries(parent.SubScans), SubScanTotal: 1,
	}
	s.instances[inst.ID] = inst
	s.hydrateTerminalIntegrity(inst)
	if inst.Completion != "partial" || inst.StopReason != "wildcard_assessment_incomplete" ||
		inst.SubScans[0].StopReason != child.StopReason || inst.PlanTasksUnfinished != 26 ||
		inst.StartedAt != parent.StartedAt || inst.FinishedAt != parent.FinishedAt {
		t.Fatalf("terminal hydration retained a recovery marker or changed assessment facts: %+v", inst)
	}
}
