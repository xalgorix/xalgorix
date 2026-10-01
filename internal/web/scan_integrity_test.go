package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestRestoredBudgetDoesNotDoubleCountExactSnapshot(t *testing.T) {
	dir := t.TempDir()
	sctx := scanctx.New("token-continuity", dir)
	t.Cleanup(sctx.Close)
	if err := os.WriteFile(filepath.Join(dir, "execution-budget.json"), []byte(`{"version":1,"scan_id":"token-continuity","tokens":100}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inst := &ScanInstance{ID: "instance", Status: "running", TotalTokens: 100}
	s := &Server{instances: map[string]*ScanInstance{"instance": inst}}
	ag := agent.NewAgent(&config.Config{}, "coordinator", nil, scopeguard.Config{}, sctx)
	t.Cleanup(ag.Stop)
	ag.SetResumeBudget(0, 0, 80, "")
	if _, err := ag.RestoreExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	sess := &scanSession{id: "token-continuity", scanDir: dir, instanceID: "instance", scanMode: "single", agent: ag, sctx: sctx, record: &ScanRecord{TotalTokens: 80}}
	s.initializeSessionCounters(sess)
	s.processEvent(agent.Event{Type: "message", TotalTokens: 100}, sess)
	if inst.TotalTokens != 100 || sess.record.TotalTokens != 100 {
		t.Fatalf("restored usage was counted twice: instance=%d record=%d", inst.TotalTokens, sess.record.TotalTokens)
	}
	s.processEvent(agent.Event{Type: "message", TotalTokens: 120}, sess)
	s.processEvent(agent.Event{Type: "message", TotalTokens: 110}, sess)
	if inst.TotalTokens != 120 || sess.record.TotalTokens != 120 {
		t.Fatal("new token deltas or out-of-order child telemetry regressed totals")
	}
}

func TestIntegritySnapshotCarriesKnownZerosAndEnvelope(t *testing.T) {
	inst := &ScanInstance{ID: "instance", Status: "finished", Completion: "partial", PlanPresent: true, PlanTasksTotal: 2, PlanTasksSkipped: 2}
	events := []WSEvent{{Type: "finished"}}
	response := instanceResponseLocked(inst)
	response.InstanceID, response.Events = inst.ID, &events
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"plan_tasks_completed", "plan_tasks_unfinished"} {
		if value, ok := payload[key]; !ok || value != float64(0) {
			t.Fatalf("known zero %s was lost: %s", key, data)
		}
	}
	if payload["instance_id"] != "instance" || payload["completion"] != "partial" || payload["events"] == nil {
		t.Fatalf("custom marshaling dropped the exact snapshot envelope: %s", data)
	}
	legacy, err := json.Marshal(ScanRecord{ID: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(legacy, &payload); err != nil {
		t.Fatal(err)
	}
	var legacyPayload map[string]any
	if err := json.Unmarshal(legacy, &legacyPayload); err != nil {
		t.Fatal(err)
	}
	if _, known := legacyPayload["plan_tasks_completed"]; known {
		t.Fatal("unknown legacy assessment became a known zero")
	}
}

func TestWildcardResumeReconcilesDurableChildUsageExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	sctx := scanctx.New("child-usage", dir)
	t.Cleanup(sctx.Close)
	if err := os.WriteFile(filepath.Join(dir, "execution-budget.json"), []byte(`{"version":1,"scan_id":"child-usage","tokens":120,"progress":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inst := &ScanInstance{ID: "parent", Status: "running", TotalTokens: 500, AssessmentProgress: 20,
		UsageBySession: map[string]sessionUsage{"child-usage": {Tokens: 100, Progress: 5}}}
	s := &Server{instances: map[string]*ScanInstance{"parent": inst}}
	ag := agent.NewAgent(&config.Config{}, "child", nil, scopeguard.Config{}, sctx)
	t.Cleanup(ag.Stop)
	if _, err := ag.RestoreExecutionCheckpoint(); err != nil {
		t.Fatal(err)
	}
	sess := &scanSession{id: sctx.ID, scanDir: dir, instanceID: "parent", scanMode: "wildcard", parentTarget: "example.invalid",
		agent: ag, sctx: sctx, record: &ScanRecord{TotalTokens: 100, AssessmentProgress: 5}}
	s.initializeSessionCounters(sess)
	s.initializeSessionCounters(sess)
	if inst.TotalTokens != 520 || inst.AssessmentProgress != 22 {
		t.Fatalf("newer child ledger was lost or counted twice: %d tokens, %d progress", inst.TotalTokens, inst.AssessmentProgress)
	}
	s.processEvent(agent.Event{Type: "message", TotalTokens: 130}, sess)
	s.processEvent(agent.Event{Type: "message", TotalTokens: 120}, sess)
	if inst.TotalTokens != 530 || inst.AssessmentProgress != 22 {
		t.Fatal("child event replay changed the aggregated parent ledger")
	}
	snapshot := s.scanRecordFromInstance(inst)
	if snapshot.UsageBySession["child-usage"].Tokens != 130 {
		t.Fatal("exact snapshot omitted the per-session high-water mark")
	}
}
