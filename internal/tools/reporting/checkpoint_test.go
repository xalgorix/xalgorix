package reporting

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindingCheckpointPreservesLegacyCollisionsAndSequenceGaps(t *testing.T) {
	ctxID := "finding-continuity"
	dir := t.TempDir()
	t.Cleanup(func() { CleanupContext(ctxID) })
	legacy := []Vulnerability{
		{ID: "XALG-1", Title: "first", Target: "https://example.invalid", Endpoint: "/first"},
		{ID: "XALG-1", Title: "second", Target: "https://example.invalid", Endpoint: "/second"},
		{ID: "XALG-90", Title: "last", Target: "https://example.invalid", Endpoint: "/last"},
	}
	if err := RestoreContext(ctxID, dir, legacy); err != nil {
		t.Fatal(err)
	}
	CleanupContext(ctxID)
	if err := RestoreContext(ctxID, dir, legacy); err != nil {
		t.Fatal(err)
	}
	store := getStoreByID(ctxID)
	store.mu.Lock()
	if len(store.vulns) != 3 || nextFindingIDLocked(store) != "XALG-91" {
		t.Fatal("restart lost colliding records or reused an existing numeric sequence")
	}
	store.mu.Unlock()
}

func TestFindingCheckpointRejectsDuplicateAfterRestart(t *testing.T) {
	ctxID := "finding-dedup-continuity"
	dir := t.TempDir()
	t.Cleanup(func() { CleanupContext(ctxID) })
	if err := RestoreContext(ctxID, dir, nil); err != nil {
		t.Fatal(err)
	}
	args := validReportArgs()
	result, err := reportVulnWithContextID(ctxID, args)
	if err != nil || result.Error != "" || len(GetVulnerabilitiesForContext(ctxID)) != 1 {
		t.Fatalf("initial report failed: %+v %v", result, err)
	}
	CleanupContext(ctxID)
	if err := RestoreContext(ctxID, dir, nil); err != nil {
		t.Fatal(err)
	}
	result, err = reportVulnWithContextID(ctxID, args)
	if err != nil || result.Metadata["duplicate"] != true || len(GetVulnerabilitiesForContext(ctxID)) != 1 {
		t.Fatalf("restart accepted a duplicate: %+v %v", result, err)
	}
}

func TestFindingPersistenceFailureDoesNotReturnSavedReceipt(t *testing.T) {
	ctxID := "finding-durability-failure"
	dir := t.TempDir()
	t.Cleanup(func() { CleanupContext(ctxID) })
	if err := RestoreContext(ctxID, dir, nil); err != nil {
		t.Fatal(err)
	}
	// An unwritable destination is deterministic even when tests run as root.
	store := getStoreByID(ctxID)
	store.persistPath = filepath.Join(dir, "missing", "findings.json")
	result, err := reportVulnWithContextID(ctxID, validReportArgs())
	if err != nil || result.Error == "" || len(GetVulnerabilitiesForContext(ctxID)) != 0 {
		t.Fatalf("failed persistence returned a saved finding: %+v %v", result, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil || len(data) == 0 {
		t.Fatal("failed append damaged the prior durable checkpoint")
	}
}
