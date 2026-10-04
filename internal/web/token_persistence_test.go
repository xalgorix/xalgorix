package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestResumeUsesPersistedRequestLedgerWhenScanRecordLags(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "resume-ledger")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{ID: "scan-1", Target: "example.invalid", Status: "paused", TotalTokens: 100}, dir)
	prior := scanctx.New("scan-1", dir)
	prior.Tokens.Record(scanctx.TokenAttribution{PromptTokens: 100, TotalTokens: 100})
	prior.Tokens.Record(scanctx.TokenAttribution{PromptTokens: 25, TotalTokens: 25})
	prior.Tokens.Close()
	prior.Close()

	restored := scanctx.New("scan-1", dir)
	t.Cleanup(restored.Close)
	if loaded := restored.Tokens.LoadPersisted(); loaded != 2 {
		t.Fatalf("loaded %d persisted requests, want 2", loaded)
	}
	sess := &scanSession{id: "scan-1", target: "example.invalid", scanDir: dir,
		scanMode: "single", sctx: restored}
	rec := s.scanRecordForSession(sess)
	if rec.TotalTokens != 125 || sess.recordTokenOffset != 125 {
		t.Fatalf("resumed budget used stale scan record: tokens=%d offset=%d", rec.TotalTokens, sess.recordTokenOffset)
	}
}

func TestQueueStateTokenFieldsSerialization(t *testing.T) {
	state := QueueState{
		InstanceID:  "inst-123",
		Targets:     []string{"https://example.com"},
		CurrentIdx:  0,
		Active:      true,
		Iterations:  42,
		TotalTokens: 152000,
		ToolCalls:   35,
		StartedAt:   time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal QueueState: %v", err)
	}

	var decoded QueueState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal QueueState: %v", err)
	}

	if decoded.Iterations != 42 {
		t.Errorf("Iterations = %d, want 42", decoded.Iterations)
	}
	if decoded.TotalTokens != 152000 {
		t.Errorf("TotalTokens = %d, want 152000", decoded.TotalTokens)
	}
	if decoded.ToolCalls != 35 {
		t.Errorf("ToolCalls = %d, want 35", decoded.ToolCalls)
	}
}

func TestScanRequestFromQueueStatePreservesTokens(t *testing.T) {
	state := &QueueState{
		InstanceID:    "inst-456",
		Targets:       []string{"https://target-a.test", "https://target-b.test"},
		CurrentIdx:    1,
		Instruction:   "test instruction",
		ScanMode:      "single",
		Active:        true,
		Iterations:    18,
		TotalTokens:   85400,
		ToolCalls:     12,
		ActiveScanDir: "/tmp/scans/test-dir",
	}

	req := scanRequestFromQueueState(state, "/tmp/queue_state_inst-456.json")
	if req.ResumeIterations != 18 {
		t.Errorf("ResumeIterations = %d, want 18", req.ResumeIterations)
	}
	if req.ResumeTotalTokens != 85400 {
		t.Errorf("ResumeTotalTokens = %d, want 85400", req.ResumeTotalTokens)
	}
	if req.ResumeToolCalls != 12 {
		t.Errorf("ResumeToolCalls = %d, want 12", req.ResumeToolCalls)
	}
	if req.ResumeScanDir != "/tmp/scans/test-dir" {
		t.Errorf("ResumeScanDir = %s, want /tmp/scans/test-dir", req.ResumeScanDir)
	}
}

func TestSaveQueueStateDurableCapturesLiveInstanceCounters(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		dataDir:   tmpDir,
		instances: make(map[string]*ScanInstance),
	}

	instanceID := "inst-token-live"
	s.instances[instanceID] = &ScanInstance{
		ID:          instanceID,
		Status:      "running",
		Iterations:  27,
		TotalTokens: 110500,
		ToolCalls:   19,
	}

	req := ScanRequest{
		InstanceID: instanceID,
		Targets:    []string{"https://example.org"},
		ScanMode:   "single",
	}

	if err := s.saveQueueStateDurable(0, req); err != nil {
		t.Fatalf("saveQueueStateDurable: %v", err)
	}

	path := s.queueStatePathForInstance(instanceID)
	entry, err := s.loadQueueStateEntry(path)
	if err != nil {
		t.Fatalf("loadQueueStateEntry: %v", err)
	}

	if entry.state.Iterations != 27 {
		t.Errorf("saved Iterations = %d, want 27", entry.state.Iterations)
	}
	if entry.state.TotalTokens != 110500 {
		t.Errorf("saved TotalTokens = %d, want 110500", entry.state.TotalTokens)
	}
	if entry.state.ToolCalls != 19 {
		t.Errorf("saved ToolCalls = %d, want 19", entry.state.ToolCalls)
	}
}

func TestUpdateQueueStateCountersMonotonic(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		dataDir:   tmpDir,
		instances: make(map[string]*ScanInstance),
	}

	instanceID := "inst-update-counters"
	req := ScanRequest{
		InstanceID: instanceID,
		Targets:    []string{"https://example.org"},
	}
	if err := s.saveQueueStateDurable(0, req); err != nil {
		t.Fatalf("initial saveQueueStateDurable: %v", err)
	}

	if err := s.updateQueueStateCounters(instanceID, 15, 60000, 10); err != nil {
		t.Fatalf("updateQueueStateCounters: %v", err)
	}

	path := s.queueStatePathForInstance(instanceID)
	entry, err := s.loadQueueStateEntry(path)
	if err != nil {
		t.Fatalf("loadQueueStateEntry: %v", err)
	}
	if entry.state.Iterations != 15 || entry.state.TotalTokens != 60000 || entry.state.ToolCalls != 10 {
		t.Fatalf("updated state mismatch: %+v", entry.state)
	}

	// Smaller values should not overwrite existing higher values
	if err := s.updateQueueStateCounters(instanceID, 5, 20000, 3); err != nil {
		t.Fatalf("updateQueueStateCounters smaller: %v", err)
	}
	entry2, _ := s.loadQueueStateEntry(path)
	if entry2.state.Iterations != 15 || entry2.state.TotalTokens != 60000 || entry2.state.ToolCalls != 10 {
		t.Errorf("counters were downgraded: %+v", entry2.state)
	}
}

func TestSeedResumeInstanceFromRecordMonotonic(t *testing.T) {
	tmpDir := t.TempDir()
	s := &Server{
		dataDir:   tmpDir,
		instances: make(map[string]*ScanInstance),
	}

	scanDir := filepath.Join(tmpDir, "test_scan")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatal(err)
	}

	rec := &ScanRecord{
		ID:          "rec-1",
		Target:      "https://example.com",
		Iterations:  20,
		TotalTokens: 75000,
		ToolCalls:   15,
		Status:      "running",
	}
	s.saveScanRecordTo(rec, scanDir)

	// Inst starts with higher counters (from parent/queue resume)
	inst := &ScanInstance{
		ID:          "inst-seed",
		Iterations:  30,
		TotalTokens: 120000,
		ToolCalls:   25,
	}

	s.seedResumeInstanceFromRecord(inst, ScanRequest{
		IsResume:      true,
		ResumeScanDir: scanDir,
	})

	// Must retain the higher counters
	if inst.Iterations != 30 {
		t.Errorf("inst.Iterations = %d, want 30", inst.Iterations)
	}
	if inst.TotalTokens != 120000 {
		t.Errorf("inst.TotalTokens = %d, want 120000", inst.TotalTokens)
	}
	if inst.ToolCalls != 25 {
		t.Errorf("inst.ToolCalls = %d, want 25", inst.ToolCalls)
	}

	// Inst with lower counters adopts record values
	instLow := &ScanInstance{
		ID: "inst-seed-low",
	}
	s.seedResumeInstanceFromRecord(instLow, ScanRequest{
		IsResume:      true,
		ResumeScanDir: scanDir,
	})
	if instLow.Iterations != 20 {
		t.Errorf("instLow.Iterations = %d, want 20", instLow.Iterations)
	}
	if instLow.TotalTokens != 75000 {
		t.Errorf("instLow.TotalTokens = %d, want 75000", instLow.TotalTokens)
	}
	if instLow.ToolCalls != 15 {
		t.Errorf("instLow.ToolCalls = %d, want 15", instLow.ToolCalls)
	}
}

func TestAttachWildcardSubScansFromAggregatesTokens(t *testing.T) {
	s := &Server{}
	parent := &ScanRecord{
		ID:       "parent-wc",
		Target:   "example.com",
		ScanMode: "wildcard",
	}

	entries := []scanEntry{
		{
			rec: ScanRecord{
				ID:           "child-1",
				ParentTarget: "example.com",
				Target:       "sub1.example.com",
				TotalTokens:  25000,
				ToolCalls:    10,
				Iterations:   12,
			},
		},
		{
			rec: ScanRecord{
				ID:           "child-2",
				ParentTarget: "example.com",
				Target:       "sub2.example.com",
				TotalTokens:  40000,
				ToolCalls:    15,
				Iterations:   18,
			},
		},
	}

	s.attachWildcardSubScansFrom(parent, entries)

	if parent.TotalTokens != 65000 {
		t.Errorf("parent.TotalTokens = %d, want 65000", parent.TotalTokens)
	}
	if parent.ToolCalls != 25 {
		t.Errorf("parent.ToolCalls = %d, want 25", parent.ToolCalls)
	}
	if parent.Iterations != 30 {
		t.Errorf("parent.Iterations = %d, want 30", parent.Iterations)
	}
}
