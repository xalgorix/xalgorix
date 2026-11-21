package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// interruptedQueue is the on-disk state a graceful shutdown leaves for a scan
// whose queue state is kept for auto-resume.
type interruptedQueue struct {
	id, target, scanMode string
	dir                  string
}

func writeInterruptedQueue(t *testing.T, s *Server, id, scanMode string) interruptedQueue {
	t.Helper()
	q := interruptedQueue{id: id, target: "https://example.test", scanMode: scanMode}
	if scanMode == "wildcard" {
		q.target = "example.test"
	}
	rel := filepath.Join("example.test", "2026-11-20", "example.test_"+id[len(id)-4:])
	q.dir = filepath.Join(s.dataDir, rel)
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: filepath.Base(rel), InstanceID: id, Target: q.target, ScanMode: scanMode,
		StartedAt: "2026-11-20T10:00:00Z", FinishedAt: "2026-11-20T11:00:00Z",
		Status: "stopped", StopReason: "signal_terminated", WorkStarted: true,
	})
	req := ScanRequest{InstanceID: id, Targets: []string{q.target}, ScanMode: scanMode}
	s.saveQueueState(0, req, queueProgress{ActiveTarget: q.target, ActiveScanDir: q.dir, ActiveScanID: filepath.Base(rel)})
	saveTestDispatchSnapshot(t, s, id, q.target, "stopped", "signal_terminated")
	return q
}

// apiStatus returns the status and stop reason a GET on path reports, or the
// HTTP code when the request does not succeed.
func apiStatus(t *testing.T, s *Server, path string) (status, stopReason string, code int) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	switch {
	case path == "/api/scans":
		s.handleListScans(rr, req)
	case strings.HasPrefix(path, "/api/instances/"):
		s.handleInstanceAction(rr, req)
	default:
		s.handleGetScan(rr, req)
	}
	if rr.Code != http.StatusOK {
		return "", "", rr.Code
	}
	if path == "/api/scans" {
		var list []struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || len(list) != 1 {
			t.Fatalf("GET %s: %v %s", path, err, rr.Body.String())
		}
		return list[0].Status, "", rr.Code
	}
	var body struct {
		Status     string `json:"status"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: %v %s", path, err, rr.Body.String())
	}
	return body.Status, body.StopReason, rr.Code
}

func readDispatchStatus(t *testing.T, s *Server, id string) (string, string, string) {
	t.Helper()
	snapshot, err := s.loadExactDispatchSnapshot(id)
	if err != nil {
		t.Fatalf("load exact snapshot: %v", err)
	}
	return snapshot.Status, snapshot.StopReason, snapshot.FinishedAt
}

// assertEveryReadSays checks the status that every read path reports for a
// rebuilt or resumed scan: the live instance, the coordinator snapshot, the
// scan detail by instance and record ID, the scan list, the scan.json and the
// exact dispatch snapshot.
func assertEveryReadSays(t *testing.T, s *Server, q interruptedQueue, want, wantWhy string) {
	t.Helper()
	for _, path := range []string{
		"/api/instances/" + q.id,
		"/api/instances/" + q.id + "/snapshot",
		"/api/scans/" + q.id,
		"/api/scans/" + filepath.Base(q.dir),
		"/api/scans",
	} {
		status, why, code := apiStatus(t, s, path)
		if code != http.StatusOK || status != want {
			t.Errorf("GET %s = %d %q/%q, want %q", path, code, status, why, want)
		}
		if path != "/api/scans" && why != wantWhy {
			t.Errorf("GET %s stop_reason = %q, want %q", path, why, wantWhy)
		}
	}
	if status, why := readScanStatus(t, q.dir); status != want || why != wantWhy {
		t.Errorf("scan.json = %q/%q, want %q/%q", status, why, want, wantWhy)
	}
	if status, why, finished := readDispatchStatus(t, s, q.id); status != want || why != wantWhy {
		t.Errorf("exact snapshot = %q/%q (finished_at %q), want %q/%q", status, why, finished, want, wantWhy)
	}
}

// resumeOnce runs the startup auto-resume and returns the run it registered,
// without starting scan work.
func resumeOnce(t *testing.T, s *Server) *multiScanRun {
	t.Helper()
	runs := make(chan *multiScanRun, 1)
	s.runResumedQueueFn = func(run *multiScanRun, _ *config.Config) { runs <- run }
	s.autoResumeInterruptedQueues()
	select {
	case run := <-runs:
		t.Cleanup(run.ownership.release)
		return run
	case <-time.After(10 * time.Second):
		t.Fatal("auto-resume did not register the interrupted queue")
		return nil
	}
}

// TestRestartResumeIsPendingThenRunning covers the restart → resuming →
// running path. A scan that a restart interrupts and queues for auto-resume
// must never read as stopped anywhere a poller looks, and must read as
// running once the resumed run is admitted. Before the fix the exact snapshot
// kept the shutdown's stopped status until a session reached work admission,
// and a resumed wildcard parent kept the recovery marker for its whole run.
func TestRestartResumeIsPendingThenRunning(t *testing.T) {
	for i, scanMode := range []string{"quick", "wildcard"} {
		t.Run(scanMode, func(t *testing.T) {
			s := newTestServer(t, nil)
			id := "550e8400-e29b-41d4-a716-44665544100" + string(rune('0'+i))
			q := writeInterruptedQueue(t, s, id, scanMode)

			restarted := restartedServer(t, s)
			assertEveryReadSays(t, restarted, q, "pending", stopReasonRestartResuming)
			if _, _, finished := readDispatchStatus(t, restarted, id); finished != "" {
				t.Errorf("pending exact snapshot keeps finished_at %q", finished)
			}
			// With no live instance the coordinator snapshot falls back to
			// the exact snapshot; a queued resume is no news, not a stop.
			fallback := restartedServer(t, s)
			delete(fallback.instances, id)
			if status, why, code := apiStatus(t, fallback, "/api/instances/"+id+"/snapshot"); code != http.StatusNotFound {
				t.Errorf("snapshot without a live instance = %d %q/%q, want 404", code, status, why)
			}

			run := resumeOnce(t, restarted)
			if run.instanceID != id || filepath.Clean(run.placeholderDir) != filepath.Clean(q.dir) {
				t.Fatalf("resumed %q from %q, want %q from %q", run.instanceID, run.placeholderDir, id, q.dir)
			}
			if restarted.instances[id] != run.instance {
				t.Fatal("the resumed run did not replace the restart placeholder")
			}
			// Registered but not yet admitted: still queued.
			if status, why, _ := apiStatus(t, restarted, "/api/instances/"+id); status != "pending" {
				t.Errorf("registered resume reads %q/%q, want pending", status, why)
			}

			// runRegisteredMultiScan admits the run (pending → running under
			// the instance lock) and then records that the resume started.
			run.instance.mu.Lock()
			run.instance.Status = "running"
			run.instance.mu.Unlock()
			restarted.recordRestartResumeStarted(run)

			if status, why := readScanStatus(t, q.dir); status != "running" || why != "" {
				t.Errorf("scan.json after resume start = %q/%q, want running with no stop reason", status, why)
			}
			if status, why, finished := readDispatchStatus(t, restarted, id); status != "running" || why != "" || finished != "" {
				t.Errorf("exact snapshot after resume start = %q/%q/%q, want running", status, why, finished)
			}
			for _, path := range []string{"/api/instances/" + id, "/api/instances/" + id + "/snapshot", "/api/scans/" + id} {
				if status, why, code := apiStatus(t, restarted, path); code != http.StatusOK || status != "running" || why != "" {
					t.Errorf("GET %s after resume start = %d %q/%q, want running", path, code, status, why)
				}
			}
		})
	}
}

// TestRestartResumeFailureIsFinal covers a resume that cannot start. The
// placeholder must not stay pending with no run behind it: an unreadable
// durable state marks it failed, a durable exact stop gives it that stop, and
// in both cases the queue state is cleared so the next start does not retry.
func TestRestartResumeFailureIsFinal(t *testing.T) {
	cases := []struct {
		name          string
		breakDispatch func(t *testing.T, s *Server, id string)
		want, wantWhy string
	}{
		{"unreadable durable state", func(t *testing.T, s *Server, id string) {
			if err := os.WriteFile(s.dispatchSnapshotPath(id), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "failed", stopReasonRestartResumeFailed},
		{"exact stop recorded after restart", func(t *testing.T, s *Server, id string) {
			saveTestDispatchSnapshot(t, s, id, "https://example.test", "stopped", "user_stopped")
		}, "stopped", "user_stopped"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			id := "550e8400-e29b-41d4-a716-44665544110" + string(rune('0'+i))
			q := writeInterruptedQueue(t, s, id, "quick")
			restarted := restartedServer(t, s)
			tc.breakDispatch(t, restarted, id)

			restarted.runResumedQueueFn = func(*multiScanRun, *config.Config) {
				t.Error("a refused resume must not run")
			}
			restarted.autoResumeInterruptedQueues()
			deadline := time.Now().Add(10 * time.Second)
			for {
				restarted.queueResumeMu.Lock()
				launching := restarted.hasQueueResumeLaunchingLocked()
				restarted.queueResumeMu.Unlock()
				if !launching {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the refused resume never finished launching")
				}
				time.Sleep(10 * time.Millisecond)
			}

			inst := restarted.instances[id]
			inst.mu.RLock()
			status, why, finished := inst.Status, inst.StopReason, inst.FinishedAt
			inst.mu.RUnlock()
			if status != tc.want || why != tc.wantWhy || finished == "" {
				t.Fatalf("instance = %q/%q (finished_at %q), want %q/%q", status, why, finished, tc.want, tc.wantWhy)
			}
			assertEveryReadSays(t, restarted, q, tc.want, tc.wantWhy)
			for _, entry := range restarted.validQueueStateEntries(false) {
				if entry.state != nil && entry.state.InstanceID == id {
					t.Fatal("a refused resume kept its queue state, so every start retries it")
				}
			}
			// The next start keeps the final status instead of resuming.
			again := restartedServer(t, restarted)
			if inst := again.instances[id]; inst == nil || inst.Status != tc.want || inst.StopReason != tc.wantWhy {
				t.Fatalf("next start rebuilt %#v, want %q/%q", inst, tc.want, tc.wantWhy)
			}
		})
	}
}

// TestRestartResumeQueueOwnedElsewhereStaysPending verifies that a resume
// refused because another process runs the queue does not mark the scan
// failed: it is still being scanned.
func TestRestartResumeQueueOwnedElsewhereStaysPending(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655441200"
	q := writeInterruptedQueue(t, s, id, "quick")
	restarted := restartedServer(t, s)
	restarted.failRestartResume(id, errQueueOwnedElsewhere)
	assertEveryReadSays(t, restarted, q, "pending", stopReasonRestartResuming)
}

// TestRebuildFinalizesContradictoryRestartRecord verifies that a record
// saved as stopped with the restart-recovery marker and no resume state, as
// older versions wrote it, is rebuilt with a final reason instead of reading
// as both stopped and about to resume.
func TestRebuildFinalizesContradictoryRestartRecord(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655441300"
	rel := filepath.Join("example.test", "2026-11-20", "example.test_legacy")
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_legacy", InstanceID: id, Target: "https://example.test",
		StartedAt: "2026-11-20T10:00:00Z", FinishedAt: "2026-11-20T11:00:00Z",
		Status: "stopped", StopReason: stopReasonRestartResuming,
	})
	s.rebuildInstancesFromDisk()
	if inst := s.instances[id]; inst == nil || inst.Status != "stopped" || inst.StopReason != stopReasonRestartNoResumeState {
		t.Fatalf("rebuilt %#v, want stopped/%s", inst, stopReasonRestartNoResumeState)
	}
	if status, why := readScanStatus(t, filepath.Join(s.dataDir, rel)); status != "stopped" || why != stopReasonRestartNoResumeState {
		t.Fatalf("scan.json = %q/%q, want stopped/%s", status, why, stopReasonRestartNoResumeState)
	}
}

// TestWildcardStoppedParentDropsRestartMarker verifies that a completed
// wildcard parent that still carries the recovery marker and is downgraded to
// stopped because children are unresolved gets a real reason, not the marker.
func TestWildcardStoppedParentDropsRestartMarker(t *testing.T) {
	s := newTestServer(t, nil)
	parent := &ScanRecord{
		ID: "example.test_parent", InstanceID: "wildcard-restart-marker", Target: "example.test", ScanMode: "wildcard",
		Status: "finished", StopReason: stopReasonRestartResuming, FinishedAt: "2026-11-20T11:00:00Z",
		SubScans:     []SubScanSummary{{Target: "a.example.test", Status: "running"}},
		SubScanTotal: 1,
	}
	s.attachWildcardSubScansFrom(parent, nil)
	if parent.Status != "stopped" || parent.StopReason == stopReasonRestartResuming {
		t.Fatalf("parent = %q/%q, want stopped without the restart marker", parent.Status, parent.StopReason)
	}
}
