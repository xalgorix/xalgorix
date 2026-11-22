package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// saveStartupResumeQueue writes what a graceful shutdown leaves for a scan
// whose queue is kept for auto-resume: a stopped scan.json, the queue state
// and the exact snapshot, all under instance id.
func saveStartupResumeQueue(t *testing.T, s *Server, id string) string {
	t.Helper()
	slug := "example.test_" + id[len(id)-4:]
	rel := filepath.Join("example.test", "2026-11-21", slug)
	dir := filepath.Join(s.dataDir, rel)
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: slug, InstanceID: id, Target: "https://example.test/" + id[len(id)-4:], ScanMode: "quick",
		StartedAt: "2026-11-21T10:00:00Z", FinishedAt: "2026-11-21T11:00:00Z",
		Status: "stopped", StopReason: "signal_terminated", WorkStarted: true,
	})
	req := ScanRequest{InstanceID: id, Targets: []string{"https://example.test/" + id[len(id)-4:]}, ScanMode: "quick"}
	s.saveQueueState(0, req, queueProgress{ActiveTarget: req.Targets[0], ActiveScanDir: dir, ActiveScanID: slug})
	saveTestDispatchSnapshot(t, s, id, req.Targets[0], "stopped", "signal_terminated")
	return dir
}

// startLiveQueue stands in for a scan that started in the first seconds
// after a restart: it holds the queue lock, has saved its queue state, and
// is registered with status.
func startLiveQueue(t *testing.T, s *Server, id, status string) *ScanInstance {
	t.Helper()
	holdQueueLock(t, s, id)
	s.saveQueueState(0, ScanRequest{InstanceID: id, Targets: []string{"https://live.example.test"}, ScanMode: "quick"})
	inst := &ScanInstance{ID: id, Targets: "https://live.example.test", Status: status, ScanMode: "quick"}
	s.instancesMu.Lock()
	s.instances[id] = inst
	s.instancesMu.Unlock()
	return inst
}

func holdQueueLock(t *testing.T, s *Server, id string) {
	t.Helper()
	ownership, owned, err := s.acquireQueueOwnership(id)
	if err != nil || !owned {
		t.Fatalf("lock queue %s: owned=%v err=%v", id, owned, err)
	}
	t.Cleanup(ownership.release)
}

func launchingKeys(s *Server) []string {
	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()
	keys := make([]string, 0, len(s.queueResumeLaunching))
	for key := range s.queueResumeLaunching {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// startupResume runs the startup auto-resume with every registered run
// parked in runResumedQueueFn, so no scan work starts. It returns the
// launching keys right after the pass, while the runs are parked, and the
// instance IDs it registered. release lets the parked runs return.
func startupResume(t *testing.T, s *Server, wantRuns int) (keysDuring []string, registered []string, release func()) {
	t.Helper()
	runs := make(chan *multiScanRun, 16)
	gate := make(chan struct{})
	s.runResumedQueueFn = func(run *multiScanRun, _ *config.Config) {
		runs <- run
		<-gate
	}
	released := false
	release = func() {
		if !released {
			released = true
			close(gate)
		}
	}
	t.Cleanup(release)

	s.autoResumeInterruptedQueues()
	// Keys are marked under queueResumeMu before the pass returns, and a
	// registered run keeps its key while it is parked.
	for i := 0; i < wantRuns; i++ {
		select {
		case run := <-runs:
			t.Cleanup(run.ownership.release)
			registered = append(registered, run.instanceID)
		case <-time.After(10 * time.Second):
			t.Fatalf("auto-resume registered %d queue(s) %v, want %d", len(registered), registered, wantRuns)
		}
	}
	keysDuring = launchingKeys(s)
	select {
	case run := <-runs:
		t.Fatalf("auto-resume registered an unexpected queue %s", run.instanceID)
	case <-time.After(100 * time.Millisecond):
	}
	sort.Strings(registered)
	return keysDuring, registered, release
}

func waitForLaunchingKeys(t *testing.T, s *Server, want []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := launchingKeys(s)
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("launching keys = %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStartupResumeRunsBesideActiveScan covers a scan that is admitted in
// the first seconds after a restart, before the auto-resume runs. The resume
// used to skip every interrupted queue then, so the restart placeholders
// stayed pending with no run behind them. Each queue now registers and
// waits for its own admission slot, and the live scan is left alone.
func TestStartupResumeRunsBesideActiveScan(t *testing.T) {
	s := newTestServer(t, nil)
	const a = "550e8400-e29b-41d4-a716-446655441801"
	const b = "550e8400-e29b-41d4-a716-446655441802"
	saveStartupResumeQueue(t, s, a)
	saveStartupResumeQueue(t, s, b)
	restarted := restartedServer(t, s)
	for _, id := range []string{a, b} {
		if inst := restarted.instances[id]; inst == nil || !isReplaceableResumePlaceholder(inst) {
			t.Fatalf("restart did not leave a resume placeholder for %s: %#v", id, inst)
		}
	}

	const live = "550e8400-e29b-41d4-a716-446655441803"
	liveInst := startLiveQueue(t, restarted, live, "running")
	restarted.running.Store(true)

	_, registered, release := startupResume(t, restarted, 2)
	if got := strings.Join(registered, ","); got != a+","+b {
		t.Fatalf("auto-resume registered %v, want %s and %s", registered, a, b)
	}
	for _, id := range []string{a, b} {
		if inst := restarted.instances[id]; inst == nil || isReplaceableResumePlaceholder(inst) {
			t.Errorf("queue %s still has only its restart placeholder", id)
		}
	}
	if restarted.instances[live] != liveInst || liveInst.Status != "running" {
		t.Errorf("the live scan was replaced or changed: %#v", restarted.instances[live])
	}
	if !hasQueueState(restarted, live) {
		t.Error("the live scan lost its queue state")
	}
	release()
	waitForLaunchingKeys(t, restarted, nil)
}

// TestStartupResumeLeavesClaimedQueuesAlone covers the queues the startup
// auto-resume must not launch, because something already runs or resumes
// them. The other interrupted queue is still resumed in every case.
func TestStartupResumeLeavesClaimedQueuesAlone(t *testing.T) {
	const placeholder = "550e8400-e29b-41d4-a716-446655441811"
	const claimed = "550e8400-e29b-41d4-a716-446655441812"
	cases := []struct {
		name  string
		claim func(t *testing.T, s *Server)
		// wantKeys are the launching keys left once the resumed run returns.
		wantKeys []string
	}{
		{
			// /api/queue/resume (or another pass) launched it first. A second
			// launch would be refused and then clear the key the first one
			// still holds.
			name: "resume already launching",
			claim: func(t *testing.T, s *Server) {
				saveStartupResumeQueue(t, s, claimed)
				s.rebuildInstancesFromDisk()
				s.queueResumeMu.Lock()
				s.markQueueResumeLaunchingLocked(claimed)
				s.queueResumeMu.Unlock()
			},
			wantKeys: []string{claimed},
		},
		{
			// A dispatch saved its queue state and holds the queue lock but
			// has not registered its instance yet.
			name: "dispatch still starting",
			claim: func(t *testing.T, s *Server) {
				if _, reserved := s.reserveDispatchID(claimed); !reserved {
					t.Fatal("could not reserve the dispatch id")
				}
				t.Cleanup(func() { s.releaseDispatchID(claimed) })
				holdQueueLock(t, s, claimed)
				s.saveQueueState(0, ScanRequest{InstanceID: claimed, Targets: []string{"https://live.example.test"}, ScanMode: "quick"})
			},
		},
		{
			name:  "scan waiting for admission",
			claim: func(t *testing.T, s *Server) { startLiveQueue(t, s, claimed, "pending") },
		},
		{
			name:  "scan running",
			claim: func(t *testing.T, s *Server) { startLiveQueue(t, s, claimed, "running") },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			saveStartupResumeQueue(t, s, placeholder)
			restarted := restartedServer(t, s)
			tc.claim(t, restarted)
			before := restarted.instances[claimed]

			keysDuring, registered, release := startupResume(t, restarted, 1)
			if len(registered) != 1 || registered[0] != placeholder {
				t.Fatalf("auto-resume registered %v, want only %s", registered, placeholder)
			}
			wantDuring := append([]string{placeholder}, tc.wantKeys...)
			sort.Strings(wantDuring)
			if strings.Join(keysDuring, ",") != strings.Join(wantDuring, ",") {
				t.Errorf("launching keys during the pass = %v, want %v", keysDuring, wantDuring)
			}
			if restarted.instances[claimed] != before {
				t.Errorf("the claimed queue's instance was replaced: %#v", restarted.instances[claimed])
			}
			if !hasQueueState(restarted, claimed) {
				t.Error("the claimed queue lost its queue state")
			}
			release()
			waitForLaunchingKeys(t, restarted, tc.wantKeys)
		})
	}
}

// TestQueueResumeRefusedWhileStartupResumeRuns covers the other order: the
// startup auto-resume launched the interrupted queues, and /api/queue/resume
// then arrives while they run. It must refuse rather than launch the same
// queues a second time.
func TestQueueResumeRefusedWhileStartupResumeRuns(t *testing.T) {
	s := newTestServer(t, nil)
	const id = "550e8400-e29b-41d4-a716-446655441821"
	saveStartupResumeQueue(t, s, id)
	restarted := restartedServer(t, s)

	_, registered, release := startupResume(t, restarted, 1)
	if len(registered) != 1 || registered[0] != id {
		t.Fatalf("auto-resume registered %v, want %s", registered, id)
	}
	run := restarted.instances[id]

	rr := httptest.NewRecorder()
	restarted.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
	if !strings.Contains(rr.Body.String(), "pending or running") {
		t.Fatalf("/api/queue/resume during the startup resume = %s, want a refusal", rr.Body.String())
	}
	if restarted.instances[id] != run {
		t.Error("/api/queue/resume replaced the run the startup resume registered")
	}
	if got := launchingKeys(restarted); len(got) != 1 || got[0] != id {
		t.Errorf("launching keys = %v, want only %s", got, id)
	}
	release()
	waitForLaunchingKeys(t, restarted, nil)
}
