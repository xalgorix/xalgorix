package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// A finished discovery session is not proof of complete host assessments.
func TestWildcardAssessmentReconstructsPartialPhysicalChild(t *testing.T) {
	s := newTestServer(t, nil)
	parent := &ScanRecord{
		ID: "parent", InstanceID: "wildcard-assessment", Target: "example.invalid",
		ScanMode: "wildcard", Status: "finished", Completion: "full",
		StartedAt: "2026-01-01T00:00:00Z", FinishedAt: "2026-01-01T02:00:01Z",
		PlanPresent: true, PlanTasksTotal: 2, PlanTasksCompleted: 2,
		SubScanTotal: 1, SubScans: []SubScanSummary{{ID: "child", Target: "example.invalid", Status: "finished"}},
	}
	child := ScanRecord{
		ID: "child", InstanceID: parent.InstanceID, Target: parent.Target, ParentTarget: parent.Target,
		ScanMode: "wildcard", Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit",
		StartedAt: "2026-01-01T01:00:00Z", FinishedAt: "2026-01-01T02:00:00Z",
		PlanPresent: true, PlanTasksTotal: 27, PlanTasksCompleted: 1, PlanTasksUnfinished: 26,
		TotalTokens: 100, Vulns: []VulnSummary{{ID: "finding", Title: "Verified finding", Target: parent.Target}},
	}
	s.attachWildcardSubScansFrom(parent, []scanEntry{{rec: child}})
	if parent.Status != "finished" || parent.Completion != "partial" {
		t.Fatalf("parent confused lifecycle/discovery with assessment coverage: status=%q completion=%q", parent.Status, parent.Completion)
	}
	if !parent.PlanPresent || parent.PlanTasksTotal != 27 || parent.PlanTasksCompleted != 1 || parent.PlanTasksSkipped != 0 || parent.PlanTasksUnfinished != 26 {
		t.Fatalf("parent retained discovery plan instead of child assessment: %+v", parent)
	}
	if parent.StartedAt != "2026-01-01T00:00:00Z" || parent.SubScans[0].StartedAt != child.StartedAt || parent.TotalTokens != child.TotalTokens || len(parent.Vulns) != 1 {
		t.Fatal("assessment aggregation changed independent clocks, usage or findings")
	}
}

func fullWildcardAssessment() *ScanRecord {
	return &ScanRecord{
		ID: "parent", InstanceID: "wildcard-assessment-coordinator", Target: "example.invalid", ScanMode: "wildcard",
		Status: "finished", Discovery: &SubScanSummary{ID: "parent", Status: "finished", Completion: "full"},
		SubScanTotal: 2, SubScans: []SubScanSummary{
			{ID: "child-a", Target: "a.example.invalid", Status: "finished", Completion: "full", PlanPresent: true, PlanTasksTotal: 3, PlanTasksCompleted: 2, PlanTasksSkipped: 1},
			{ID: "child-b", Target: "b.example.invalid", Status: "finished", Completion: "full", PlanPresent: true, PlanTasksTotal: 5, PlanTasksCompleted: 5},
		},
	}
}

func TestWildcardAssessmentCompletionAndPlanMatrix(t *testing.T) {
	tests := []struct {
		name       string
		change     func(*ScanRecord)
		completion string
		reason     string
		planKnown  bool
	}{
		{"all known full", func(*ScanRecord) {}, "full", "", true},
		{"partial child", func(r *ScanRecord) { r.SubScans[1].Completion = "partial" }, "partial", "wildcard_assessment_incomplete", true},
		{"failed child", func(r *ScanRecord) { r.SubScans[1].Status = "failed" }, "partial", "wildcard_assessment_incomplete", true},
		{"stopped child", func(r *ScanRecord) { r.SubScans[1].Status = "stopped" }, "partial", "wildcard_assessment_incomplete", true},
		{"unfinished plan", func(r *ScanRecord) { r.SubScans[1].PlanTasksCompleted = 4; r.SubScans[1].PlanTasksUnfinished = 1 }, "partial", "wildcard_assessment_incomplete", true},
		{"unknown outcome", func(r *ScanRecord) { r.SubScans[1].Completion = "" }, "partial", "wildcard_assessment_unknown", true},
		{"descriptor without physical identity", func(r *ScanRecord) { r.SubScans[1].ID = "" }, "partial", "wildcard_assessment_unknown", true},
		{"duplicate physical identity", func(r *ScanRecord) { r.SubScans[1].ID = r.SubScans[0].ID }, "partial", "wildcard_assessment_unknown", false},
		{"missing descriptor", func(r *ScanRecord) { r.SubScanTotal = 3 }, "partial", "wildcard_assessment_unknown", false},
		{"empty inventory", func(r *ScanRecord) { r.SubScans = nil; r.SubScanTotal = 0 }, "partial", "wildcard_assessment_unknown", false},
		{"unknown discovery", func(r *ScanRecord) { r.Discovery = nil }, "partial", "wildcard_assessment_unknown", true},
		{"partial discovery", func(r *ScanRecord) { r.Discovery.Completion = "partial" }, "partial", "wildcard_discovery_incomplete", true},
		{"unfinished discovery plan", func(r *ScanRecord) {
			r.Discovery.PlanPresent = true
			r.Discovery.PlanTasksTotal = 1
			r.Discovery.PlanTasksUnfinished = 1
		}, "partial", "wildcard_discovery_incomplete", true},
		{"resource cap", func(r *ScanRecord) { r.SubScanSkipped = 9 }, "partial", "wildcard_resource_limit", true},
		{"user cancellation", func(r *ScanRecord) { r.Status = "stopped"; r.StopReason = "user_stopped" }, "partial", "user_stopped", true},
		{"unstarted child", func(r *ScanRecord) { r.SubScans[1] = SubScanSummary{Target: "b.example.invalid", Status: "pending"} }, "partial", "wildcard_assessment_incomplete", false},
		{"unknown plan", func(r *ScanRecord) {
			r.SubScans[1].PlanPresent = false
			r.SubScans[1].PlanTasksTotal = 0
			r.SubScans[1].PlanTasksCompleted = 0
		}, "full", "", false},
		{"invalid plan", func(r *ScanRecord) { r.SubScans[1].PlanTasksTotal = 1 }, "partial", "wildcard_assessment_unknown", false},
		{"running", func(r *ScanRecord) { r.Status = "running"; r.Completion = "full" }, "", "", true},
		{"resumed", func(r *ScanRecord) {
			r.Status = "pending"
			r.StopReason = "wildcard_assessment_incomplete"
			r.Completion = "partial"
		}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := fullWildcardAssessment()
			tt.change(rec)
			before := cloneSubScanSummaries(rec.SubScans)
			aggregateWildcardAssessment(rec)
			if rec.Completion != tt.completion || rec.StopReason != tt.reason || rec.PlanPresent != tt.planKnown {
				t.Fatalf("got completion=%q reason=%q plan=%v, want %q %q %v", rec.Completion, rec.StopReason, rec.PlanPresent, tt.completion, tt.reason, tt.planKnown)
			}
			if !reflect.DeepEqual(before, rec.SubScans) {
				t.Fatal("aggregation rewrote independent assessment facts")
			}
			if tt.planKnown && rec.SubScanTotal == 2 && rec.PlanTasksTotal != 8 {
				t.Fatalf("aggregate task count=%d, want 8", rec.PlanTasksTotal)
			}
			if !tt.planKnown && (rec.PlanTasksTotal != 0 || rec.PlanTasksCompleted != 0 || rec.PlanTasksSkipped != 0 || rec.PlanTasksUnfinished != 0) {
				t.Fatal("unknown aggregate plan retained enumeration or a partial sum")
			}
		})
	}
}

func TestWildcardAssessmentLegacySnapshotCannotRestoreDiscoveryFull(t *testing.T) {
	s := newTestServer(t, nil)
	parent := fullWildcardAssessment()
	parent.ID = parent.InstanceID
	parent.Completion, parent.PlanPresent, parent.PlanTasksTotal, parent.PlanTasksCompleted = "full", true, 2, 2
	parent.SubScans = []SubScanSummary{{ID: "physical", Target: parent.Target, Status: "finished"}}
	parent.SubScanTotal = 1
	parent.Discovery = nil
	if err := s.saveExactDispatchSnapshot(parent); err != nil {
		t.Fatal(err)
	}
	child := ScanRecord{ID: "physical", InstanceID: parent.InstanceID, ParentTarget: parent.Target, Target: parent.Target,
		Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit", PlanPresent: true, PlanTasksTotal: 27, PlanTasksCompleted: 1, PlanTasksUnfinished: 26}
	s.saveScanRecordTo(&child, s.makeScanDir("physical"))
	inst := &ScanInstance{ID: parent.InstanceID, Status: "finished", ScanMode: "wildcard", Completion: "partial", StopReason: "wildcard_assessment_unknown", SubScans: cloneSubScanSummaries(parent.SubScans), SubScanTotal: 1}
	s.instances[inst.ID] = inst
	s.hydrateTerminalIntegrity(inst)
	if inst.Completion != "partial" || inst.PlanTasksTotal != 27 || inst.PlanTasksUnfinished != 26 || inst.SubScans[0].Completion != "partial" {
		t.Fatalf("stale exact discovery snapshot restored a false assessment result: %+v", inst)
	}
}

func TestWildcardAssessmentDescriptorGenerationDoesNotBorrowOldOutcome(t *testing.T) {
	s := newTestServer(t, nil)
	parent := fullWildcardAssessment()
	parent.SubScans = []SubScanSummary{{ID: "current-child", Target: "a.example.invalid", Status: "finished"}}
	parent.SubScanTotal = 1
	current := ScanRecord{ID: "current-child", InstanceID: parent.InstanceID, ParentTarget: parent.Target, Target: parent.SubScans[0].Target,
		Status: "finished", Completion: "partial", PlanPresent: true, PlanTasksTotal: 27, PlanTasksCompleted: 1, PlanTasksUnfinished: 26}
	older := current
	older.ID, older.Completion, older.PlanTasksCompleted, older.PlanTasksUnfinished = "older-child", "full", 27, 0
	older.Vulns = []VulnSummary{{ID: "retained", Title: "Verified earlier finding", Target: older.Target}}
	s.attachWildcardSubScansFrom(parent, []scanEntry{{rec: current}, {rec: older}})
	if parent.Completion != "partial" || parent.SubScans[0].ID != current.ID || parent.SubScans[0].Completion != "partial" || parent.PlanTasksUnfinished != 26 || len(parent.Vulns) != 1 {
		t.Fatalf("older physical generation replaced current coverage or lost evidence: %+v", parent)
	}
}

func TestWildcardAssessmentMirrorPersistenceAndExactResponse(t *testing.T) {
	s := newTestServer(t, nil)
	parent := fullWildcardAssessment()
	parent.SubScans[1].Completion, parent.SubScans[1].StopReason = "partial", "stuck_loop_limit"
	parent.SubScans[1].PlanTasksCompleted, parent.SubScans[1].PlanTasksUnfinished = 1, 4
	aggregateWildcardAssessment(parent)
	inst := &ScanInstance{ID: parent.InstanceID, ScanMode: "wildcard", Status: "running", StartedAt: "2026-01-01T00:00:00Z", TotalTokens: 100}
	s.instances[inst.ID] = inst
	s.mirrorWildcardProgress(inst.ID, parent)
	inst.mu.Lock()
	inst.Status = "finished"
	normalizeTerminalWildcardInstanceLocked(inst)
	inst.mu.Unlock()
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		t.Fatal(err)
	}
	saved, err := s.loadExactDispatchSnapshot(inst.ID)
	if err != nil || saved.Completion != "partial" || saved.PlanTasksTotal != 8 || saved.PlanTasksUnfinished != 4 || saved.Discovery == nil {
		t.Fatalf("exact persistence lost aggregate assessment: %+v err=%v", saved, err)
	}
	parent.Discovery.Completion = "partial"
	parent.SubScans[1].PlanTasksUnfinished = 0
	if inst.Discovery.Completion != "full" || inst.SubScans[1].PlanTasksUnfinished != 4 {
		t.Fatal("live response shares mutable parent assessment data")
	}
	for _, evicted := range []bool{false, true} {
		if evicted {
			delete(s.instances, inst.ID)
		}
		rr := httptest.NewRecorder()
		s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/"+inst.ID+"/snapshot", nil))
		var response ScanRecord
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || rr.Code != http.StatusOK || response.Completion != "partial" || response.PlanTasksTotal != 8 || response.PlanTasksUnfinished != 4 || response.SubScans[1].Completion != "partial" {
			t.Fatalf("exact response lost aggregate or child assessment (evicted=%v): %s err=%v", evicted, rr.Body, err)
		}
	}
}

func TestWildcardAssessmentPhysicalScopeWinsOverEvents(t *testing.T) {
	s := newTestServer(t, nil)
	parent := fullWildcardAssessment()
	parent.SubScans = nil
	parent.SubScanTotal = 1
	child := ScanRecord{ID: "physical-child", InstanceID: parent.InstanceID, ParentTarget: parent.Target, Target: "a.example.invalid", Status: "failed", Completion: "partial", StopReason: "target_unresponsive",
		StartedAt: "2026-01-01T00:00:00Z", PlanPresent: true, PlanTasksTotal: 2, PlanTasksUnfinished: 2}
	sibling := child
	sibling.ID, sibling.ParentTarget, sibling.Target = "foreign-child", "other.invalid", "a.other.invalid"
	sibling.Completion = "full"
	parent.Events = []WSEvent{{Type: "target_completed", Target: child.Target, ParentTarget: parent.Target, AgentID: "descriptor", Timestamp: "2026-01-01T01:00:00Z"}}
	s.attachWildcardSubScansFrom(parent, []scanEntry{{rec: child}, {rec: sibling}})
	if len(parent.SubScans) != 1 || parent.SubScans[0].ID != child.ID || parent.SubScans[0].Status != "failed" || parent.SubScans[0].StartedAt != child.StartedAt || parent.SubScans[0].Completion != "partial" || parent.PlanTasksUnfinished != 2 {
		t.Fatalf("physical scope/outcome overwritten by sibling or event: %+v", parent)
	}
}

func TestWildcardAssessmentKnownZeroAndUnknownPlanJSON(t *testing.T) {
	for _, known := range []bool{false, true} {
		child := SubScanSummary{ID: "child", PlanPresent: known}
		data, err := json.Marshal(child)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"plan_tasks_total", "plan_tasks_completed", "plan_tasks_skipped", "plan_tasks_unfinished"} {
			value, present := fields[key]
			if present != known || (present && value != float64(0)) {
				t.Fatalf("known=%v field=%s value=%v present=%v", known, key, value, present)
			}
		}
	}
}

func TestWildcardAssessmentCapPreservesPhysicalChildrenAndConsumedPrefix(t *testing.T) {
	inventory := []string{"a.example.invalid", "b.example.invalid", "c.example.invalid", "d.example.invalid", "example.invalid", "e.example.invalid"}
	kept, skipped := capWildcardInventory(inventory, 1, 2, parseWildcardTarget("example.invalid"), []SubScanSummary{{ID: "physical", Target: inventory[3]}})
	want := []string{inventory[0], inventory[1], inventory[3], inventory[4]}
	if !reflect.DeepEqual(kept, want) || skipped != 2 {
		t.Fatalf("cap changed consumed positions or discarded physical/mandatory work: kept=%v skipped=%d", kept, skipped)
	}
}

func TestWildcardAssessmentRebuildAndResumeUsePhysicalPlans(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "rebuild", true: "resume"}[resume], func(t *testing.T) {
			s := newTestServer(t, nil)
			parent := fullWildcardAssessment()
			parent.Status = "stopped"
			parent.Completion = "full" // Historical enumeration outcome.
			parent.PlanPresent, parent.PlanTasksTotal, parent.PlanTasksCompleted = true, 99, 99
			parent.StartedAt = "2026-01-01T00:00:00Z"
			parent.TotalTokens = 200
			parent.SubScans = []SubScanSummary{{ID: "physical", Target: parent.Target, Status: "finished"}}
			parent.SubScanTotal = 1
			dir := s.makeScanDir(parent.Target)
			s.saveScanRecordTo(parent, dir)
			child := ScanRecord{ID: "physical", InstanceID: parent.InstanceID, Target: parent.Target, ParentTarget: parent.Target,
				ScanMode: "wildcard", Status: "finished", Completion: "partial", StopReason: "stuck_loop_limit", StartedAt: "2026-01-01T01:00:00Z",
				PlanPresent: true, PlanTasksTotal: 27, PlanTasksCompleted: 1, PlanTasksUnfinished: 26, TotalTokens: 100,
				Vulns: []VulnSummary{{ID: "finding", Title: "Verified finding", SourceScanID: "physical", Target: parent.Target}}}
			childDir := s.makeScanDir("physical-child")
			s.saveScanRecordTo(&child, childDir)
			if resume {
				inst := &ScanInstance{ID: parent.InstanceID, ScanMode: "wildcard", Status: "running", TotalTokens: 200}
				s.instances[inst.ID] = inst
				req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true,
					ResumeSubdomains: []string{parent.Target}, ResumeSubIndex: 1}
				s.runWildcardTarget(context.Background(), &config.Config{}, req, parent.Target, 0, 1)
			} else {
				s.rebuildInstancesFromDisk()
			}
			saved, ok := loadScanRecordFromDir(dir)
			if !ok || saved.Completion != "partial" || saved.PlanTasksTotal != 27 || saved.PlanTasksUnfinished != 26 || saved.StartedAt != parent.StartedAt || saved.TotalTokens < parent.TotalTokens {
				t.Fatalf("recovery lost aggregate evidence: %+v", saved)
			}
			inst := s.instances[parent.InstanceID]
			if inst == nil || inst.PlanTasksTotal != 27 || inst.PlanTasksUnfinished != 26 || (resume && inst.Completion != "partial") {
				t.Fatalf("recovery did not mirror physical plans: %+v", inst)
			}
			physical, ok := loadScanRecordFromDir(childDir)
			if !ok || !reflect.DeepEqual(physical, &child) {
				t.Fatalf("recovery rewrote physical child record: %+v", physical)
			}
		})
	}
}

func TestWildcardAssessmentResumeCannotReportUnknownChildrenFull(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "wildcard-assessment-resume", ScanMode: "wildcard", Status: "running"}
	s.instances[inst.ID] = inst
	dir := s.makeScanDir("example.invalid")
	s.saveScanRecordTo(&ScanRecord{
		ID: "parent", InstanceID: inst.ID, Target: "example.invalid", ScanMode: "wildcard", Status: "stopped", Completion: "full",
		SubScans: []SubScanSummary{{ID: "legacy-child", Target: "example.invalid", Status: "finished", TotalTokens: 100}},
	}, dir)
	req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true,
		ResumeSubdomains: []string{"example.invalid"}, ResumeSubIndex: 1}
	s.runWildcardTarget(context.Background(), &config.Config{}, req, "example.invalid", 0, 1)
	parent, ok := loadScanRecordFromDir(dir)
	if !ok || parent.Status != "finished" || parent.Completion == "full" || inst.Completion == "full" {
		t.Fatal("resuming a completed inventory inferred assessment completeness from legacy lifecycle metadata")
	}
}
