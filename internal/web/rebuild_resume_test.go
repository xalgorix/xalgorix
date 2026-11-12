package web

import (
	"path/filepath"
	"testing"
)

// TestRebuiltPausedInstanceCanResumeFromScanDir verifies that a paused
// single-target scan rebuilt from disk after a restart, with no saved queue
// state, can still be resumed from its scan dir. Rebuilt instances used to drop
// their scan dir, so every resume answered 409 "no persisted scan state found".
func TestRebuiltPausedInstanceCanResumeFromScanDir(t *testing.T) {
	s := newTestServer(t, nil)
	rel := filepath.Join("example.test", "2026-11-04", "example.test_abc")
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "example.test_abc", InstanceID: "573708e2", Target: "https://example.test",
		StartedAt: "2026-11-04T20:30:00Z", Status: "paused", StopReason: "provider_rate_limited",
	})

	s.rebuildInstancesFromDisk()
	inst := s.instances["573708e2"]
	if inst == nil {
		t.Fatal("paused instance was not rebuilt")
	}
	if inst.Status != "paused" {
		t.Fatalf("rebuilt status = %q, want paused", inst.Status)
	}

	req, ok, reason := s.scanRequestForPausedInstance("573708e2", inst)
	if !ok {
		t.Fatalf("resume refused: %s", reason)
	}
	if want := filepath.Join(s.dataDir, rel); req.ResumeScanDir != want {
		t.Fatalf("ResumeScanDir = %q, want %q", req.ResumeScanDir, want)
	}
	if req.ResumeActiveTarget != "https://example.test" {
		t.Fatalf("ResumeActiveTarget = %q, want the scan's target", req.ResumeActiveTarget)
	}
	if !s.scanFolderHasRunningScan(filepath.Join(s.dataDir, "example.test")) {
		t.Fatal("a paused scan's folder must count as in use")
	}
}

// TestClaimInstanceEntryAllowsOneResume verifies that only one of several
// resume requests holding the same paused instance can claim it, and that an
// entry since replaced under the same ID (the first request's live
// replacement) is never removed by a stale request.
func TestClaimInstanceEntryAllowsOneResume(t *testing.T) {
	s := newTestServer(t, nil)
	paused := &ScanInstance{ID: "573708e2", Status: "paused"}
	s.instancesMu.Lock()
	s.instances[paused.ID] = paused
	s.instancesMu.Unlock()

	if !s.claimInstanceEntry(paused) {
		t.Fatal("first claim failed")
	}
	if s.claimInstanceEntry(paused) {
		t.Fatal("a second claim of the same paused instance succeeded")
	}

	replacement := &ScanInstance{ID: paused.ID, Status: "running"}
	s.instancesMu.Lock()
	s.instances[paused.ID] = replacement
	s.instancesMu.Unlock()
	if s.claimInstanceEntry(paused) {
		t.Fatal("a stale claim removed the live replacement")
	}
	s.instancesMu.RLock()
	kept := s.instances[paused.ID] == replacement
	s.instancesMu.RUnlock()
	if !kept {
		t.Fatal("the live replacement is no longer registered")
	}
	if s.claimInstanceEntry(nil) {
		t.Fatal("claimed a nil instance")
	}
}
