package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedScanRecord writes a minimal scan.json at the real Data_Dir depth
// (<folder>/<date>/<slug>/scan.json) so folder holds one discovered scan.
func seedScanRecord(t *testing.T, folder string) string {
	t.Helper()
	dir := filepath.Join(folder, "2026-01-01", "scan-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed scan dir %q: %v", dir, err)
	}
	p := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(p, []byte(`{"id":"scan-1","target":"example.com"}`), 0o644); err != nil {
		t.Fatalf("seed scan.json %q: %v", p, err)
	}
	return p
}

// seedFile creates path (and its parents) with fixed content.
func seedFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("seed parent of %q: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seed file %q: %v", path, err)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%q should still exist: %v", path, err)
	}
}

// nonScanLayout seeds the directories under Data_Dir that are NOT scan output:
// the uploaded scan-context store, the uploaded source store, an operator's
// stray folder, and an empty folder. It returns one file inside each that
// must survive any delete attempt.
func nonScanLayout(t *testing.T, root string) map[string]string {
	t.Helper()
	keep := map[string]string{
		"context":      filepath.Join(root, "context", "1700000000000_abc", "openapi.json"),
		"sources":      filepath.Join(root, "sources", "1700000000000_repo", "main.go"),
		"stray-folder": filepath.Join(root, "stray-folder", "notes.txt"),
	}
	for _, p := range keep {
		seedFile(t, p)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty-folder"), 0o755); err != nil {
		t.Fatalf("seed empty folder: %v", err)
	}
	return keep
}

// TestResolveDeletableDataDir_RefusesNonScanFolders: only a top-level folder
// that holds scan output may be resolved for deletion. The upload stores are
// reserved (403) and any other folder without a scan record is "not a scan
// directory" (400).
func TestResolveDeletableDataDir_RefusesNonScanFolders(t *testing.T) {
	s := newTestServer(t, nil)
	nonScanLayout(t, s.dataDir)
	seedScanRecord(t, filepath.Join(s.dataDir, "example.com"))

	tests := []struct {
		name    string
		wantErr error
	}{
		{"example.com", nil},
		{"context", errProtectedDataDir},
		{"sources", errProtectedDataDir},
		{"stray-folder", errNotAScanDir},
		{"empty-folder", errNotAScanDir},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.resolveDeletableDataDir(tc.name)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("resolveDeletableDataDir(%q) unexpected error: %v", tc.name, err)
				}
				if want := filepath.Join(s.dataDir, tc.name); got != want {
					t.Fatalf("resolveDeletableDataDir(%q) = %q, want %q", tc.name, got, want)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("resolveDeletableDataDir(%q) error = %v, want %v", tc.name, err, tc.wantErr)
			}
			if got != "" {
				t.Fatalf("resolveDeletableDataDir(%q) returned path %q on error", tc.name, got)
			}
		})
	}
}

// TestHandleDeleteDataDir_NonScanFoldersSurvive drives the handler with the
// names of non-scan folders and asserts each request is refused and nothing
// is removed. Before the fix every one of these returned 200 and RemoveAll'd
// the folder.
func TestHandleDeleteDataDir_NonScanFoldersSurvive(t *testing.T) {
	s := newTestServer(t, nil)
	keep := nonScanLayout(t, s.dataDir)

	want := map[string]int{
		"context":      http.StatusForbidden,
		"sources":      http.StatusForbidden,
		"stray-folder": http.StatusBadRequest,
		"empty-folder": http.StatusBadRequest,
	}
	for name, code := range want {
		rec := callDeleteDataDir(s, http.MethodDelete, name)
		if rec.Code != code {
			t.Errorf("DELETE %q status = %d, want %d (body %q)", name, rec.Code, code, rec.Body.String())
		}
	}
	for _, p := range keep {
		mustExist(t, p)
	}
	mustExist(t, filepath.Join(s.dataDir, "empty-folder"))
}

// TestHandleDeleteDataDir_ScanFolderStillDeletes keeps the intended behavior:
// a target folder holding scan output is removed with a 200.
func TestHandleDeleteDataDir_ScanFolderStillDeletes(t *testing.T) {
	s := newTestServer(t, nil)
	folder := filepath.Join(s.dataDir, "example.com")
	seedScanRecord(t, folder)

	rec := callDeleteDataDir(s, http.MethodDelete, "example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if _, err := os.Lstat(folder); !os.IsNotExist(err) {
		t.Fatalf("scan folder %q should be deleted, Lstat err = %v", folder, err)
	}
}

// TestInitDataDir_StartupCleanupOnlyRemovesScanOutput: the startup sweep of
// folders untouched for 30+ days must age out scan output only. Before the fix
// it removed every top-level directory not starting with "_" and not named
// "logos" — the uploaded scan-context and source stores, operator folders and
// dot-prefixed state directories included.
func TestInitDataDir_StartupCleanupOnlyRemovesScanOutput(t *testing.T) {
	s := newTestServer(t, nil)
	root := s.dataDir
	keep := nonScanLayout(t, root)
	lockDir := filepath.Join(root, ".queue-locks")
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		t.Fatalf("seed %q: %v", lockDir, err)
	}
	oldScan := filepath.Join(root, "old.example.com")
	seedScanRecord(t, oldScan)
	freshScan := filepath.Join(root, "fresh.example.com")
	seedScanRecord(t, freshScan)

	// Age every top-level entry except the fresh scan past the 30-day cutoff.
	// Children are seeded first: creating them bumps the parent's mtime.
	old := time.Now().AddDate(0, 0, -45)
	for _, name := range []string{"context", "sources", "stray-folder", "empty-folder", ".queue-locks", "old.example.com"} {
		if err := os.Chtimes(filepath.Join(root, name), old, old); err != nil {
			t.Fatalf("age %q: %v", name, err)
		}
	}

	s.initDataDir()

	for _, p := range keep {
		mustExist(t, p)
	}
	mustExist(t, filepath.Join(root, "empty-folder"))
	mustExist(t, lockDir)
	mustExist(t, freshScan)
	if _, err := os.Lstat(oldScan); !os.IsNotExist(err) {
		t.Fatalf("old scan folder %q should be cleaned up, Lstat err = %v", oldScan, err)
	}
}

// writeScanJSON writes a scan.json with the given body at dir/scan.json.
func writeScanJSON(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write scan.json in %q: %v", dir, err)
	}
}

// TestResolveDeletableDataDir_ScanRecordShapes pins which folder shapes count
// as scan output: a legacy folder with scan.json at its top level and a
// URL-shaped nested target do; a symlinked subfolder pointing at a real scan
// folder, a symlink named scan.json, or a record buried past the depth cap do
// not. Reserved names are refused regardless of letter case.
func TestResolveDeletableDataDir_ScanRecordShapes(t *testing.T) {
	s := newTestServer(t, nil)
	root := s.dataDir

	writeScanJSON(t, filepath.Join(root, "legacy-scan"), `{"id":"legacy"}`)
	writeScanJSON(t, filepath.Join(root, "https:", "a.test", "app", "2026-01-01", "a.test_x"), `{"id":"url"}`)

	real := filepath.Join(root, "example.com")
	seedScanRecord(t, real)
	if err := os.MkdirAll(filepath.Join(root, "linkfolder"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "linkfolder", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "linkrecord"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "2026-01-01", "scan-1", "scan.json"), filepath.Join(root, "linkrecord", "scan.json")); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "deep")
	for i := 0; i <= scanRecordMaxDepth; i++ {
		deep = filepath.Join(deep, "d")
	}
	writeScanJSON(t, deep, `{"id":"deep"}`)

	nonScanLayout(t, root)

	tests := []struct {
		name    string
		wantErr error
	}{
		{"legacy-scan", nil},
		{"https:", errInvalidScanName}, // ':' is outside the name class; listed to document it
		{"linkfolder", errNotAScanDir},
		{"linkrecord", errNotAScanDir},
		{"deep", errNotAScanDir},
		{"Context", errProtectedDataDir},
		{"SOURCES", errProtectedDataDir},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.resolveDeletableDataDir(tc.name)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("resolveDeletableDataDir(%q) unexpected error: %v", tc.name, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("resolveDeletableDataDir(%q) error = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
	if !dirHoldsScanRecord(filepath.Join(root, "https:")) {
		t.Fatal("URL-shaped nested target should hold a scan record")
	}
	mustExist(t, filepath.Join(real, "2026-01-01", "scan-1", "scan.json"))
}

// TestInitDataDir_KeepsReservedFolderHoldingScanJSON: an upload store that
// happens to contain a file named scan.json is still reserved and survives the
// startup sweep.
func TestInitDataDir_KeepsReservedFolderHoldingScanJSON(t *testing.T) {
	s := newTestServer(t, nil)
	root := s.dataDir
	writeScanJSON(t, filepath.Join(root, "context", "1700000000000_abc"), `{"id":"uploaded"}`)
	old := time.Now().AddDate(0, 0, -45)
	if err := os.Chtimes(filepath.Join(root, "context"), old, old); err != nil {
		t.Fatal(err)
	}

	s.initDataDir()

	mustExist(t, filepath.Join(root, "context", "1700000000000_abc", "scan.json"))
}

// TestPruneExpiredScans_SkipsUploadStores: the retention sweeper discovers
// scans by walking Data_Dir, which descends into the upload stores. A file
// named scan.json inside an uploaded context artifact or source archive must
// not be pruned as an expired scan; a real expired scan still is.
func TestPruneExpiredScans_SkipsUploadStores(t *testing.T) {
	s := newTestServer(t, nil)
	root := s.dataDir

	ctxDir := filepath.Join(root, "context", "1700000000000_abc")
	srcDir := filepath.Join(root, "sources", "1700000000000_repo", "testdata")
	writeScanJSON(t, ctxDir, `{"id":"ctx","target":"example.com","started_at":"2020-01-01T00:00:00Z"}`)
	writeScanJSON(t, srcDir, `{"id":"src","target":"example.com","started_at":"2020-01-01T00:00:00Z"}`)
	realDir := filepath.Join(root, "old.example.com", "2020-01-01", "old.example.com_x")
	writeScanJSON(t, realDir, `{"id":"real","target":"old.example.com","started_at":"2020-01-01T00:00:00Z","finished_at":"2020-01-01T01:00:00Z"}`)

	removed := s.pruneExpiredScans(30)

	mustExist(t, filepath.Join(ctxDir, "scan.json"))
	mustExist(t, filepath.Join(srcDir, "scan.json"))
	if _, err := os.Lstat(realDir); !os.IsNotExist(err) {
		t.Fatalf("expired scan %q should be pruned, Lstat err = %v", realDir, err)
	}
	if removed != 1 {
		t.Fatalf("pruneExpiredScans removed %d scans, want 1", removed)
	}
}

// TestHandleDeleteScan_LeavesUploadStoreContent: a scan.json inside an
// uploaded source archive is discovered as a scan record, but deleting that
// record through DELETE /api/scans/{id} must not remove upload content. A real
// scan is still deleted from disk.
func TestHandleDeleteScan_LeavesUploadStoreContent(t *testing.T) {
	s := newTestServer(t, nil)
	root := s.dataDir
	srcDir := filepath.Join(root, "sources", "1700000000000_repo", "testdata")
	writeScanJSON(t, srcDir, `{"id":"uploaded-record","target":"example.com"}`)
	seedFile(t, filepath.Join(srcDir, "fixture.txt"))
	realDir := filepath.Join(root, "example.com", "2026-01-01", "example.com_x")
	writeScanJSON(t, realDir, `{"id":"real-record","target":"example.com"}`)

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/uploaded-record", nil))
	mustExist(t, filepath.Join(srcDir, "scan.json"))
	mustExist(t, filepath.Join(srcDir, "fixture.txt"))

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/real-record", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete real scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Lstat(realDir); !os.IsNotExist(err) {
		t.Fatalf("real scan dir %q should be deleted, Lstat err = %v", realDir, err)
	}
}
