package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func postInstanceAction(t *testing.T, s *Server, id, action string, exact bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/"+action, nil)
	if exact {
		req.Header.Set("X-Xalgorix-Exact-Instance", "1")
	}
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, req)
	return rr
}

func readScanStatus(t *testing.T, dir string) (string, string) {
	t.Helper()
	rec, ok := readScanSummary(filepath.Join(dir, "scan.json"))
	if !ok {
		t.Fatalf("read scan.json in %s", dir)
	}
	return rec.Status, rec.StopReason
}

func saveTestDispatchSnapshot(t *testing.T, s *Server, id, target, status, stopReason string) {
	t.Helper()
	if err := s.saveExactDispatchSnapshot(&ScanRecord{
		ID: id, InstanceID: id, Target: target, Status: status, StopReason: stopReason,
		FinishedAt: "2026-11-12T11:00:00Z",
		Events:     []WSEvent{}, Vulns: []VulnSummary{}, SubScans: []SubScanSummary{},
	}); err != nil {
		t.Fatalf("save dispatch snapshot: %v", err)
	}
}

// restartedServer returns a fresh server rebuilt from s's data dir, as after a
// process restart.
func restartedServer(t *testing.T, s *Server) *Server {
	t.Helper()
	restarted := newTestServer(t, nil)
	restarted.dataDir = s.dataDir
	restarted.rebuildInstancesFromDisk()
	return restarted
}

// TestRebuildHonoursDispatchTombstone verifies that restart recovery gives a
// paused, pending or running scan.json the stop recorded in its instance's
// durable exact snapshot. On 2026-11-12 two scans stopped with an exact stop
// came back as paused after a restart, because the stop was recorded only in
// the snapshot.
func TestRebuildHonoursDispatchTombstone(t *testing.T) {
	cases := []struct {
		name                     string
		recordStatus, recordWhy  string
		snapStatus, snapWhy      string
		wantStatus, wantWhy      string
		wantFinishedFromSnapshot bool
	}{
		{"exact stop over paused", "paused", "provider_rate_limited", "stopped", "user_stopped", "stopped", "user_stopped", true},
		{"stop still draining", "running", "", "stopping", "user_stopped", "stopped", "user_stopped", true},
		{"stopping without reason", "pending", "", "stopping", "", "stopped", "user_stopped", true},
		{"failed dispatch", "running", "", "failed", "queue_state_persist_failed", "failed", "queue_state_persist_failed", true},
		{"stale recoverable reason stays final", "running", "", "finished", "server_restart_resuming", "stopped", "exact_dispatch_terminal", true},
		{"recoverable interruption is not a tombstone", "paused", "user_paused", "stopped", "signal_terminated", "paused", "user_paused", false},
		{"paused snapshot is not a tombstone", "paused", "user_paused", "paused", "user_paused", "paused", "user_paused", false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			id := "550e8400-e29b-41d4-a716-44665544010" + string(rune('0'+i))
			rel := filepath.Join("example.test", "2026-11-12", "example.test_rec")
			writeScanRecord(t, s.dataDir, rel, ScanRecord{
				ID: "example.test_rec", InstanceID: id, Target: "https://example.test",
				StartedAt: "2026-11-12T10:00:00Z", Status: tc.recordStatus, StopReason: tc.recordWhy,
			})
			saveTestDispatchSnapshot(t, s, id, "https://example.test", tc.snapStatus, tc.snapWhy)

			s.rebuildInstancesFromDisk()
			inst := s.instances[id]
			if inst == nil {
				t.Fatal("instance was not rebuilt")
			}
			if tc.wantStatus == "paused" {
				// Not a tombstone: the record keeps its own state.
				if inst.Status != "paused" || inst.StopReason != tc.wantWhy {
					t.Fatalf("rebuilt %s/%s, want the record's paused/%s", inst.Status, inst.StopReason, tc.wantWhy)
				}
				if status, _ := readScanStatus(t, filepath.Join(s.dataDir, rel)); status != "paused" {
					t.Fatalf("scan.json status = %q, want paused", status)
				}
				return
			}
			if inst.Status != tc.wantStatus || inst.StopReason != tc.wantWhy {
				t.Fatalf("rebuilt %s/%s, want %s/%s", inst.Status, inst.StopReason, tc.wantStatus, tc.wantWhy)
			}
			if tc.wantFinishedFromSnapshot && inst.FinishedAt != "2026-11-12T11:00:00Z" {
				t.Fatalf("FinishedAt = %q, want the snapshot's", inst.FinishedAt)
			}
			status, why := readScanStatus(t, filepath.Join(s.dataDir, rel))
			if status != tc.wantStatus || why != tc.wantWhy {
				t.Fatalf("scan.json %s/%s, want %s/%s", status, why, tc.wantStatus, tc.wantWhy)
			}
			if rr := postInstanceAction(t, s, id, "resume", false); rr.Code != http.StatusConflict {
				t.Fatalf("resume of a stopped scan: code=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestRebuildHonoursDispatchTombstoneForWildcardChildren verifies that child
// records of a stopped wildcard instance are stopped too, so none is left
// running for restart recovery to resume.
func TestRebuildHonoursDispatchTombstoneForWildcardChildren(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440120"
	parentRel := filepath.Join("example.test", "2026-11-12", "example.test_parent")
	childRel := filepath.Join("api.example.test", "2026-11-12", "api.example.test_child")
	writeScanRecord(t, s.dataDir, parentRel, ScanRecord{
		ID: "example.test_parent", InstanceID: id, Target: "example.test", ScanMode: "wildcard",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	writeScanRecord(t, s.dataDir, childRel, ScanRecord{
		ID: "api.example.test_child", InstanceID: id, Target: "api.example.test", ParentTarget: "example.test",
		StartedAt: "2026-11-12T10:05:00Z", Status: "running",
	})
	saveTestDispatchSnapshot(t, s, id, "example.test", "stopped", "user_stopped")

	s.rebuildInstancesFromDisk()
	if inst := s.instances[id]; inst == nil || inst.Status != "stopped" {
		t.Fatalf("wildcard parent rebuilt as %#v, want stopped", inst)
	}
	if status, why := readScanStatus(t, filepath.Join(s.dataDir, childRel)); status != "stopped" || why != "user_stopped" {
		t.Fatalf("child scan.json %s/%s, want stopped/user_stopped", status, why)
	}
}

// TestExactStopOfRebuiltPausedScanSurvivesRestart replays the 2026-11-12
// incident: a paused scan rebuilt after one restart is stopped with an exact
// stop and must still be stopped after the next restart.
func TestExactStopOfRebuiltPausedScanSurvivesRestart(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440130"
	rel := filepath.Join("example.test", "2026-11-12", "example.test_exact")
	dir := filepath.Join(s.dataDir, rel)
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_exact", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "provider_rate_limited",
		Events: []WSEvent{{Type: "tool_result", Content: "evidence before the pause"}},
	})
	s.rebuildInstancesFromDisk()
	if inst := s.instances[id]; inst == nil || inst.Status != "paused" {
		t.Fatalf("paused scan rebuilt as %#v", inst)
	}

	if rr := postInstanceAction(t, s, id, "stop", true); rr.Code != http.StatusOK {
		t.Fatalf("exact stop code=%d body=%s", rr.Code, rr.Body.String())
	}
	if status, why := readScanStatus(t, dir); status != "stopped" || why != "user_stopped" {
		t.Fatalf("scan.json after exact stop = %s/%s, want stopped/user_stopped", status, why)
	}
	if rec, ok := loadScanRecordFromDir(dir); !ok || len(rec.Events) != 1 || rec.Events[0].Content != "evidence before the pause" {
		t.Fatalf("recording the stop lost the scan's events: %#v", rec)
	}

	restarted := restartedServer(t, s)
	if inst := restarted.instances[id]; inst == nil || inst.Status != "stopped" {
		t.Fatalf("after restart the stopped scan was rebuilt as %#v", inst)
	}
	if rr := postInstanceAction(t, restarted, id, "resume", false); rr.Code != http.StatusConflict {
		t.Fatalf("resume after restart: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestStopOfRebuiltPausedScanSurvivesRestart covers the dashboard stop, which
// writes no dispatch snapshot: scan.json alone must carry the stop.
func TestStopOfRebuiltPausedScanSurvivesRestart(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440131"
	rel := filepath.Join("example.test", "2026-11-12", "example.test_ui")
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_ui", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	s.rebuildInstancesFromDisk()

	if rr := postInstanceAction(t, s, id, "stop", false); rr.Code != http.StatusOK {
		t.Fatalf("stop code=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(s.dispatchSnapshotPath(id)); !os.IsNotExist(err) {
		t.Fatalf("expected no dispatch snapshot for a dashboard stop, stat err=%v", err)
	}
	if status, why := readScanStatus(t, filepath.Join(s.dataDir, rel)); status != "stopped" || why != "user_stopped" {
		t.Fatalf("scan.json after stop = %s/%s, want stopped/user_stopped", status, why)
	}
	if inst := restartedServer(t, s).instances[id]; inst == nil || inst.Status != "stopped" {
		t.Fatalf("after restart the stopped scan was rebuilt as %#v", inst)
	}
}

// TestResumeRefusedByExactStopKeepsInstance verifies that a resume refused
// because the instance ID was stopped with an exact stop answers 409, keeps
// the instance registered, and settles it as stopped. The resume handler used
// to drop the paused instance, answer 200, and lose the refused run, so later
// resumes got 404.
func TestResumeRefusedByExactStopKeepsInstance(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440140"
	rel := filepath.Join("example.test", "2026-11-12", "example.test_refused")
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_refused", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	s.rebuildInstancesFromDisk()
	paused := s.instances[id]
	if paused == nil || paused.Status != "paused" {
		t.Fatalf("paused scan rebuilt as %#v", paused)
	}
	// An exact stop recorded only in the snapshot, as releases before this
	// fix left it.
	saveTestDispatchSnapshot(t, s, id, "https://example.test", "stopped", "user_stopped")

	rr := postInstanceAction(t, s, id, "resume", false)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "stopped") {
		t.Fatalf("resume over an exact stop: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if s.instances[id] != paused {
		t.Fatal("a refused resume removed the instance")
	}
	if paused.Status != "stopped" || paused.StopReason != "user_stopped" {
		t.Fatalf("instance after refused resume = %s/%s, want stopped/user_stopped", paused.Status, paused.StopReason)
	}
	if status, _ := readScanStatus(t, filepath.Join(s.dataDir, rel)); status != "stopped" {
		t.Fatalf("scan.json status = %q, want stopped", status)
	}
	ownership, owned, err := s.acquireQueueOwnership(id)
	if err != nil || !owned {
		t.Fatalf("a refused resume kept the queue lock: owned=%v err=%v", owned, err)
	}
	ownership.release()
}

// TestResumeWaitsForExitingPausedRun verifies that a resume, with or without
// new_id, does not start while the paused run still holds its queue lock, and
// keeps the paused instance when it gives up.
func TestResumeWaitsForExitingPausedRun(t *testing.T) {
	s := newTestServer(t, nil)
	previousWait := queueOwnershipWait
	queueOwnershipWait = 50 * time.Millisecond
	t.Cleanup(func() { queueOwnershipWait = previousWait })

	const id = "550e8400-e29b-41d4-a716-446655440150"
	writeScanRecord(t, s.dataDir, filepath.Join("example.test", "2026-11-12", "example.test_exiting"), ScanRecord{
		ID: "example.test_exiting", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	s.rebuildInstancesFromDisk()
	paused := s.instances[id]

	held, owned, err := s.acquireQueueOwnership(id)
	if err != nil || !owned {
		t.Fatalf("hold the paused run's lock: owned=%v err=%v", owned, err)
	}
	defer held.release()
	for _, action := range []string{"resume", "resume?new_id=true"} {
		rr := postInstanceAction(t, s, id, action, false)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "still shutting down") {
			t.Fatalf("%s while the paused run exits: code=%d body=%s", action, rr.Code, rr.Body.String())
		}
		if s.instances[id] != paused || paused.Status != "paused" {
			t.Fatalf("%s removed or changed the paused instance", action)
		}
		if len(s.instances) != 1 {
			t.Fatalf("%s registered another instance: %d instances", action, len(s.instances))
		}
	}
}

// TestRegisterMultiScanResumeReplacesPausedInstanceOnce verifies that a resume
// replaces the paused instance in the step that registers the new run, and
// that a second resume holding the same paused instance is refused without
// removing anything.
func TestRegisterMultiScanResumeReplacesPausedInstanceOnce(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440160"
	writeScanRecord(t, s.dataDir, filepath.Join("example.test", "2026-11-12", "example.test_once"), ScanRecord{
		ID: "example.test_once", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	s.rebuildInstancesFromDisk()
	paused := s.instances[id]
	req, ok, reason := s.scanRequestForPausedInstance(id, paused)
	if !ok {
		t.Fatalf("resume request refused: %s", reason)
	}

	first := req
	first.resumeReplaces = paused
	run, err := s.registerMultiScan(first, id)
	if err != nil {
		t.Fatalf("register resume: %v", err)
	}
	if s.instances[id] != run.instance || run.instance == paused || run.instance.Status != "pending" {
		t.Fatalf("resume did not replace the paused instance: %#v", s.instances[id])
	}
	run.ownership.release()

	for _, targetID := range []string{id, randomSlug()} {
		second := req
		second.resumeReplaces = paused
		if _, err := s.registerMultiScan(second, targetID); !errors.Is(err, errPausedInstanceGone) && !errors.Is(err, errInstanceIDInUse) {
			t.Fatalf("second resume as %s: err=%v, want a refusal", targetID, err)
		}
		if s.instances[id] != run.instance {
			t.Fatalf("second resume as %s removed the running replacement", targetID)
		}
	}
	if len(s.instances) != 1 {
		t.Fatalf("refused resumes registered instances: %d", len(s.instances))
	}
}

// TestStoppedPendingResumeRecordsStopInScanJSON verifies that a resumed scan
// stopped before it was admitted records the stop in the scan.json it was
// resuming, once its run exits.
func TestStoppedPendingResumeRecordsStopInScanJSON(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655440170"
	rel := filepath.Join("example.test", "2026-11-12", "example.test_pending")
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_pending", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	s.rebuildInstancesFromDisk()
	paused := s.instances[id]
	req, ok, reason := s.scanRequestForPausedInstance(id, paused)
	if !ok {
		t.Fatalf("resume request refused: %s", reason)
	}
	req.resumeReplaces = paused
	run, err := s.registerMultiScan(req, id)
	if err != nil {
		t.Fatalf("register resume: %v", err)
	}

	if rr := postInstanceAction(t, s, id, "stop", false); rr.Code != http.StatusOK {
		t.Fatalf("stop pending resume: code=%d body=%s", rr.Code, rr.Body.String())
	}
	cfg := *s.cfg
	s.runRegisteredMultiScan(run, &cfg)

	if status, why := readScanStatus(t, filepath.Join(s.dataDir, rel)); status != "stopped" || why != "user_stopped" {
		t.Fatalf("scan.json after the stopped resume exited = %s/%s, want stopped/user_stopped", status, why)
	}
	if inst := restartedServer(t, s).instances[id]; inst == nil || inst.Status != "stopped" {
		t.Fatalf("after restart the stopped scan was rebuilt as %#v", inst)
	}
}

// TestPausedQueueWithoutQueueStateResumesFromPausedTarget verifies that a
// paused multi-target queue without saved queue state resumes the paused
// target and the ones after it: not the finished ones before it, and not only
// the paused one when a rebuilt instance knows just its own target.
func TestPausedQueueWithoutQueueStateResumesFromPausedTarget(t *testing.T) {
	t.Run("live instance", func(t *testing.T) {
		s := newTestServer(t, nil)
		scanDir := filepath.Join(s.dataDir, "b.test", "2026-11-12", "scan-b")
		if err := os.MkdirAll(scanDir, 0o755); err != nil {
			t.Fatal(err)
		}
		s.saveScanRecordTo(&ScanRecord{ID: "scan-b", Target: "https://b.test", Status: "paused"}, scanDir)
		inst := &ScanInstance{
			ID: "inst-1", Targets: "https://a.test, https://b.test, https://c.test",
			Status: "paused", ScanMode: "single", scanDir: scanDir,
		}
		req, ok, reason := s.scanRequestForPausedInstance("inst-1", inst)
		if !ok {
			t.Fatalf("resume refused: %s", reason)
		}
		if strings.Join(req.Targets, ",") != "https://b.test,https://c.test" {
			t.Fatalf("resume targets = %#v, want the paused target and the rest", req.Targets)
		}
	})
	t.Run("rebuilt instance", func(t *testing.T) {
		s := newTestServer(t, nil)
		const id = "550e8400-e29b-41d4-a716-446655440180"
		writeScanRecord(t, s.dataDir, filepath.Join("a.test", "2026-11-12", "scan-a"), ScanRecord{
			ID: "scan-a", InstanceID: id, Target: "https://a.test",
			StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
		})
		saveTestDispatchSnapshot(t, s, id, "https://a.test, https://b.test", "paused", "user_paused")
		s.rebuildInstancesFromDisk()
		inst := s.instances[id]
		if inst == nil || inst.Targets != "https://a.test" {
			t.Fatalf("rebuilt instance = %#v", inst)
		}
		req, ok, reason := s.scanRequestForPausedInstance(id, inst)
		if !ok {
			t.Fatalf("resume refused: %s", reason)
		}
		if strings.Join(req.Targets, ",") != "https://a.test,https://b.test" {
			t.Fatalf("resume targets = %#v, want the whole queue from the dispatch snapshot", req.Targets)
		}
	})
}

// TestPersistStopToScanDir verifies which records a stop is written into, and
// that rewriting a record keeps its events.
func TestPersistStopToScanDir(t *testing.T) {
	s := newTestServer(t, nil)
	write := func(name string, rec ScanRecord) string {
		t.Helper()
		writeScanRecord(t, s.dataDir, name, rec)
		return filepath.Join(s.dataDir, name)
	}

	legacy := write("legacy", ScanRecord{ID: "legacy", Status: "paused", Events: []WSEvent{
		{Type: "tool_result", Content: "one"}, {Type: "tool_result", Content: "two"},
	}})
	if !s.persistStopToScanDir(legacy, "stopped", "user_stopped", "") {
		t.Fatal("stop was not recorded in a paused record")
	}
	if rec, ok := loadScanRecordFromDir(legacy); !ok || rec.Status != "stopped" || rec.FinishedAt == "" || len(rec.Events) != 2 {
		t.Fatalf("legacy record after stop = %#v", rec)
	}

	journal := write("journal", ScanRecord{ID: "journal", Status: "running", EventsJournal: true})
	var lines []byte
	for _, content := range []string{"one", "two", "three"} {
		line, err := json.Marshal(WSEvent{Type: "tool_result", Content: content})
		if err != nil {
			t.Fatal(err)
		}
		lines = append(append(lines, line...), '\n')
	}
	if err := os.WriteFile(filepath.Join(journal, scanEventJournalFile), lines, 0o600); err != nil {
		t.Fatal(err)
	}
	if !s.persistStopToScanDir(journal, "failed", "agent_failed", "2026-11-12T11:00:00Z") {
		t.Fatal("failure was not recorded in a running journal-backed record")
	}
	if rec, ok := loadScanRecordFromDir(journal); !ok || rec.Status != "failed" || len(rec.Events) != 3 {
		t.Fatalf("journal-backed record after stop = %#v", rec)
	}
	if data, err := os.ReadFile(filepath.Join(journal, scanEventJournalFile)); err != nil || string(data) != string(lines) {
		t.Fatalf("event journal changed: err=%v", err)
	}

	finished := write("finished", ScanRecord{ID: "finished", Status: "finished"})
	if s.persistStopToScanDir(finished, "stopped", "user_stopped", "") {
		t.Fatal("a stop overwrote a finished record")
	}
	paused := write("paused", ScanRecord{ID: "paused", Status: "paused"})
	if s.persistStopToScanDir(paused, "stopped", "server_shutdown", "") {
		t.Fatal("a recoverable interruption was recorded as a final stop")
	}
	if s.persistStopToScanDir(paused, "paused", "user_paused", "") {
		t.Fatal("a pause was recorded as a stop")
	}
	if status, _ := readScanStatus(t, paused); status != "paused" {
		t.Fatalf("paused record status = %q", status)
	}
}

// TestIdleStopSkipsReplacedOrOwnedInstance verifies that a stop is written
// into scan.json only for the registered instance, and only while no run owns
// its queue: a stop that acted on a paused instance that a resume has just
// replaced must not write into the scan.json the new run is resuming.
func TestIdleStopSkipsReplacedOrOwnedInstance(t *testing.T) {
	s := newTestServer(t, nil)
	previousWait := queueOwnershipWait
	queueOwnershipWait = 50 * time.Millisecond
	t.Cleanup(func() { queueOwnershipWait = previousWait })

	const id = "550e8400-e29b-41d4-a716-446655440190"
	rel := filepath.Join("example.test", "2026-11-12", "example.test_idle")
	dir := filepath.Join(s.dataDir, rel)
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_idle", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-12T10:00:00Z", Status: "paused", StopReason: "user_paused",
	})
	stale := &ScanInstance{ID: id, Status: "stopped", StopReason: "user_stopped", scanDir: dir}
	s.instances[id] = &ScanInstance{ID: id, Status: "pending", scanDir: dir}
	s.persistIdleInstanceStop(stale)
	if status, _ := readScanStatus(t, dir); status != "paused" {
		t.Fatalf("a stop of a replaced instance wrote %q into the resumed scan.json", status)
	}

	s.instances[id] = stale
	held, owned, err := s.acquireQueueOwnership(id)
	if err != nil || !owned {
		t.Fatalf("hold the queue lock: owned=%v err=%v", owned, err)
	}
	s.persistIdleInstanceStop(stale)
	if status, _ := readScanStatus(t, dir); status != "paused" {
		t.Fatalf("a stop wrote %q while a run owned the queue", status)
	}
	held.release()
	s.persistIdleInstanceStop(stale)
	if status, why := readScanStatus(t, dir); status != "stopped" || why != "user_stopped" {
		t.Fatalf("scan.json after the stop = %s/%s, want stopped/user_stopped", status, why)
	}
}
