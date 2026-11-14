package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dataDirLayout records the paths seeded by seedDataDirLayout so individual
// tests can reference them without re-deriving filepath.Join calls. The layout
// mirrors the real Data_Dir shape (a scan folder, the reserved logos dir, a
// stray regular file, and a symlink whose target lives inside the temp dir).
//
// Task 8's handler tests reuse this same helper, so keep the seeded names
// stable and self-describing.
type dataDirLayout struct {
	root         string // s.dataDir
	scanFolder   string // <root>/example.com   (deletable directory)
	logosFolder  string // <root>/logos         (reserved directory)
	regularFile  string // <root>/stray.txt     (regular file → not-a-dir)
	symlink      string // <root>/symlinked     (symlink → symlinkTarget)
	symlinkName  string // "symlinked"
	symlinkTgt   string // <root>/realtarget    (symlink target dir, must survive)
	scanFolderNm string // "example.com"
}

// seedDataDirLayout builds the on-disk layout described in the design's Testing
// Strategy under s.dataDir and returns the resulting paths. It is shared by the
// resolution/guard tests (Task 7) and the handler tests (Task 8).
func seedDataDirLayout(t *testing.T, s *Server) dataDirLayout {
	t.Helper()
	root := s.dataDir

	l := dataDirLayout{
		root:         root,
		scanFolder:   filepath.Join(root, "example.com"),
		logosFolder:  filepath.Join(root, "logos"),
		regularFile:  filepath.Join(root, "stray.txt"),
		symlink:      filepath.Join(root, "symlinked"),
		symlinkName:  "symlinked",
		symlinkTgt:   filepath.Join(root, "realtarget"),
		scanFolderNm: "example.com",
	}

	for _, dir := range []string{l.scanFolder, l.logosFolder, l.symlinkTgt} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("seed dir %q: %v", dir, err)
		}
	}
	// A Scan_Folder holds scan output; an empty folder is not deletable.
	seedScanRecord(t, l.scanFolder)
	if err := os.WriteFile(l.regularFile, []byte("not a scan dir"), 0o644); err != nil {
		t.Fatalf("seed file %q: %v", l.regularFile, err)
	}
	// Symlink whose target is inside the temp dir. Resolution must refuse to
	// follow it (errInvalidScanName) and must leave the target intact.
	if err := os.Symlink(l.symlinkTgt, l.symlink); err != nil {
		t.Fatalf("seed symlink %q -> %q: %v", l.symlink, l.symlinkTgt, err)
	}
	return l
}

func TestResolveDeletableDataDir(t *testing.T) {
	s := newTestServer(t, nil)
	l := seedDataDirLayout(t, s)

	tests := []struct {
		name    string // the {name} path segment
		desc    string
		wantErr error // nil means a non-error (path) result is expected
	}{
		// Happy path.
		{name: l.scanFolderNm, desc: "existing scan folder resolves", wantErr: nil},

		// Traversal / syntactically invalid names → errInvalidScanName (R2.1/R2.2).
		{name: "..", desc: "dotdot", wantErr: errInvalidScanName},
		{name: "a/b", desc: "embedded slash", wantErr: errInvalidScanName},
		{name: "/etc/passwd", desc: "absolute path", wantErr: errInvalidScanName},
		{name: `foo\bar`, desc: "embedded backslash", wantErr: errInvalidScanName},
		{name: "bad\x00name", desc: "NUL byte", wantErr: errInvalidScanName},
		{name: "", desc: "empty name", wantErr: errInvalidScanName},
		{name: "../escape", desc: "parent traversal", wantErr: errInvalidScanName},

		// Reserved / system entries → errProtectedDataDir (R3.1).
		{name: "logos", desc: "reserved logos", wantErr: errProtectedDataDir},
		{name: "_schedules", desc: "reserved _schedules", wantErr: errProtectedDataDir},
		{name: "_saved", desc: "reserved _saved", wantErr: errProtectedDataDir},
		{name: "auth-profiles.json", desc: "reserved auth-profiles.json", wantErr: errProtectedDataDir},
		{name: "auth-profiles.json.lock", desc: "reserved auth-profiles.json.lock", wantErr: errProtectedDataDir},
		{name: "llm_keys.json", desc: "reserved llm_keys.json", wantErr: errProtectedDataDir},
		{name: "queue_state.json", desc: "reserved queue_state.json", wantErr: errProtectedDataDir},
		{name: "queue_state_x.json", desc: "reserved queue_state_x.json wildcard", wantErr: errProtectedDataDir},
		{name: ".legacy-imported", desc: "reserved .legacy-imported dotfile", wantErr: errProtectedDataDir},
		{name: ".x", desc: "arbitrary dotfile", wantErr: errProtectedDataDir},

		// Existence / type / symlink checks.
		{name: "does-not-exist", desc: "missing entry", wantErr: errScanDirNotFound},
		{name: "stray.txt", desc: "regular file is not a scan dir", wantErr: errNotAScanDir},
		{name: l.symlinkName, desc: "symlink is refused not followed", wantErr: errInvalidScanName},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := s.resolveDeletableDataDir(tc.name)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("resolveDeletableDataDir(%q) unexpected error: %v", tc.name, err)
				}
				want := filepath.Join(s.dataDir, tc.name)
				if got != want {
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

	// R2.4 — the symlink must not have been followed/deleted: its target dir
	// (and the symlink itself) must still exist after resolution.
	if _, err := os.Lstat(l.symlink); err != nil {
		t.Fatalf("symlink %q should still exist: %v", l.symlink, err)
	}
	if fi, err := os.Stat(l.symlinkTgt); err != nil || !fi.IsDir() {
		t.Fatalf("symlink target %q should still exist as a dir (err=%v)", l.symlinkTgt, err)
	}
}

// TestResolveDeletableDataDir_ContainmentProperty is a property-style loop: for
// every crafted name, whenever resolveDeletableDataDir returns a non-error
// path, that path MUST equal filepath.Join(dataDir, name) and MUST be a strict
// descendant of dataDir (never escapes, never equals the root).
//
// **Validates: Requirements 2.1, 2.2**
func TestResolveDeletableDataDir_ContainmentProperty(t *testing.T) {
	s := newTestServer(t, nil)

	// Seed several legitimate scan folders so the "non-error" branch is
	// actually exercised, alongside a pile of hostile/crafted names that must
	// all be rejected.
	valid := []string{
		"example.com",
		"api_example_com",
		"a",
		"Z9._-name",
		"sub.domain.example",
		strings.Repeat("a", 200),
	}
	for _, name := range valid {
		seedScanRecord(t, filepath.Join(s.dataDir, name))
	}

	crafted := []string{
		// valid (seeded) — should resolve
		"example.com", "api_example_com", "a", "Z9._-name",
		"sub.domain.example", strings.Repeat("a", 200),
		// hostile / crafted — should error
		"", ".", "..", "...", "a/b", "a/../b", "../etc", "../../root",
		"/etc/passwd", `C:\Windows`, `foo\bar`, "bad\x00null",
		".hidden", ".", "logos", "_saved", "queue_state_99.json",
		"name/", "/leading", "two/seg/ments", strings.Repeat("a", 300),
		"-leading-dash", "with space",
	}

	root := filepath.Clean(s.dataDir)
	for _, name := range crafted {
		got, err := s.resolveDeletableDataDir(name)
		if err != nil {
			// Rejected: must not return a path.
			if got != "" {
				t.Fatalf("name %q: error %v but returned path %q", name, err, got)
			}
			continue
		}
		// Non-error: containment invariants must hold.
		want := filepath.Join(s.dataDir, name)
		if got != want {
			t.Fatalf("name %q: resolved %q, want %q", name, got, want)
		}
		rel, relErr := filepath.Rel(root, got)
		if relErr != nil {
			t.Fatalf("name %q: filepath.Rel(%q,%q) error %v", name, root, got, relErr)
		}
		if rel != name {
			t.Fatalf("name %q: rel = %q, want exactly the name", name, rel)
		}
		if rel == "." || rel == ".." || strings.ContainsRune(rel, os.PathSeparator) {
			t.Fatalf("name %q: resolved path %q escapes or is not single-segment (rel=%q)", name, got, rel)
		}
		if !isPathUnder(root, got) || got == root {
			t.Fatalf("name %q: resolved path %q is not a strict descendant of %q", name, got, root)
		}
	}
}

func TestInstanceIsActive(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"running", true},
		{"paused", true},
		{"RUNNING", true},
		{"  Paused  ", true},
		{"finished", false},
		{"stopped", false},
		{"failed", false},
		{"saved", false},
		{"", false},
		{"queued", false},
	}
	for _, tc := range tests {
		if got := instanceIsActive(tc.status); got != tc.want {
			t.Errorf("instanceIsActive(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestScanFolderHasRunningScan(t *testing.T) {
	s := newTestServer(t, nil)
	folder := filepath.Join(s.dataDir, "example.com")
	otherFolder := filepath.Join(s.dataDir, "other.com")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("running instance under folder returns true", func(t *testing.T) {
		s.instances = map[string]*ScanInstance{
			"inst-run": {
				ID:      "inst-run",
				Status:  "running",
				scanDir: filepath.Join(folder, "2026-05-14", "slug-a"),
			},
		}
		if !s.scanFolderHasRunningScan(folder) {
			t.Fatalf("expected running scan under %q to report true", folder)
		}
	})

	t.Run("finished instance under folder returns false", func(t *testing.T) {
		s.instances = map[string]*ScanInstance{
			"inst-fin": {
				ID:      "inst-fin",
				Status:  "finished",
				scanDir: filepath.Join(folder, "2026-05-14", "slug-b"),
			},
		}
		if s.scanFolderHasRunningScan(folder) {
			t.Fatalf("finished scan under %q must not block deletion", folder)
		}
	})

	t.Run("running instance under different folder returns false", func(t *testing.T) {
		s.instances = map[string]*ScanInstance{
			"inst-other": {
				ID:      "inst-other",
				Status:  "running",
				scanDir: filepath.Join(otherFolder, "2026-05-14", "slug-c"),
			},
		}
		if s.scanFolderHasRunningScan(folder) {
			t.Fatalf("running scan under a different folder must not block deleting %q", folder)
		}
	})

	t.Run("nil instances are skipped", func(t *testing.T) {
		s.instances = map[string]*ScanInstance{"nil-inst": nil}
		if s.scanFolderHasRunningScan(folder) {
			t.Fatalf("nil instance must not report a running scan")
		}
	})
}

// TestPruneInstancesUnder verifies the in-memory cleanup cancels and drops
// instances rooted under the deleted folder while leaving others intact (R1.2).
func TestPruneInstancesUnder(t *testing.T) {
	s := newTestServer(t, nil)
	folder := filepath.Join(s.dataDir, "example.com")
	otherFolder := filepath.Join(s.dataDir, "other.com")

	_, cancelUnder := context.WithCancel(context.Background())
	canceled := false
	s.instances = map[string]*ScanInstance{
		"under": {
			ID:      "under",
			Status:  "finished",
			scanDir: filepath.Join(folder, "2026-05-14", "slug-a"),
			cancel:  func() { canceled = true; cancelUnder() },
		},
		"outside": {
			ID:      "outside",
			Status:  "finished",
			scanDir: filepath.Join(otherFolder, "2026-05-14", "slug-b"),
		},
		"nil-inst": nil,
	}

	s.pruneInstancesUnder(folder)

	if _, ok := s.instances["under"]; ok {
		t.Fatalf("instance rooted under %q should have been pruned", folder)
	}
	if !canceled {
		t.Fatalf("pruned instance's cancel func should have been invoked")
	}
	if _, ok := s.instances["outside"]; !ok {
		t.Fatalf("instance outside the folder must be retained")
	}
}

// TestReservedNamesAllRefused asserts the endpoint and the retention sweeper
// share one protected set: every name in reservedTopLevelNames is refused by
// resolveDeletableDataDir with errProtectedDataDir (R3.2 — single source of
// truth, cannot diverge).
func TestReservedNamesAllRefused(t *testing.T) {
	s := newTestServer(t, nil)
	for name := range reservedTopLevelNames {
		// Seed each reserved name on disk so the refusal is provably the
		// reserved-set guard (which runs before the Lstat existence check),
		// not an incidental "not found".
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".lock") {
			if err := os.WriteFile(filepath.Join(s.dataDir, name), []byte("x"), 0o644); err != nil {
				t.Fatalf("seed reserved file %q: %v", name, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Join(s.dataDir, name), 0o755); err != nil {
				t.Fatalf("seed reserved dir %q: %v", name, err)
			}
		}

		got, err := s.resolveDeletableDataDir(name)
		if !errors.Is(err, errProtectedDataDir) {
			t.Errorf("reserved name %q: error = %v, want errProtectedDataDir", name, err)
		}
		if got != "" {
			t.Errorf("reserved name %q: returned path %q, want empty", name, got)
		}
	}
}

// callDeleteDataDir builds a synthetic request for the given method and {name}
// segment and drives handleDeleteDataDir directly (unit-level, bypassing the
// auth/CSRF middleware). It returns the recorder so callers can assert the
// status code and JSON body.
//
// For names that contain path-traversal tokens (e.g. "../escape") the {name}
// segment must reach the handler intact. net/http path cleaning happens in the
// mux, not when the handler is invoked directly, but httptest.NewRequest's URL
// parsing can still rewrite a dotdot path — so we construct the request with a
// safe placeholder URL and then set req.URL.Path explicitly to the raw value
// the handler would observe after the mux's subtree match.
func callDeleteDataDir(s *Server, method, name string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/data-dirs/placeholder", nil)
	req.URL.Path = "/api/data-dirs/" + name
	rec := httptest.NewRecorder()
	s.handleDeleteDataDir(rec, req)
	return rec
}

// decodeDataDirBody parses the handler's JSON response body into a string map.
func decodeDataDirBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestHandleDeleteDataDir_SeededFolder verifies the happy path: a DELETE on a
// seeded Scan_Folder returns 200 with {"status":"deleted","name":...} and the
// directory is gone from disk afterward.
//
// Validates: Requirements 1.1
func TestHandleDeleteDataDir_SeededFolder(t *testing.T) {
	s := newTestServer(t, nil)
	l := seedDataDirLayout(t, s)

	rec := callDeleteDataDir(s, http.MethodDelete, l.scanFolderNm)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := decodeDataDirBody(t, rec)
	if body["status"] != "deleted" {
		t.Errorf("body status = %q, want %q", body["status"], "deleted")
	}
	if body["name"] != l.scanFolderNm {
		t.Errorf("body name = %q, want %q", body["name"], l.scanFolderNm)
	}
	if _, err := os.Lstat(l.scanFolder); !os.IsNotExist(err) {
		t.Fatalf("scan folder %q should be deleted, Lstat err = %v", l.scanFolder, err)
	}
}

// TestHandleDeleteDataDir_ReservedIsForbidden verifies a DELETE on a reserved
// entry ("logos") returns 403 and leaves the directory in place.
//
// Validates: Requirements 3.1
func TestHandleDeleteDataDir_ReservedIsForbidden(t *testing.T) {
	s := newTestServer(t, nil)
	l := seedDataDirLayout(t, s)

	rec := callDeleteDataDir(s, http.MethodDelete, "logos")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}
	if body := decodeDataDirBody(t, rec); body["error"] != "protected directory" {
		t.Errorf("body error = %q, want %q", body["error"], "protected directory")
	}
	if fi, err := os.Stat(l.logosFolder); err != nil || !fi.IsDir() {
		t.Fatalf("reserved folder %q must still exist as a dir (err=%v)", l.logosFolder, err)
	}
}

// TestHandleDeleteDataDir_MissingName verifies a DELETE on a name that does not
// exist under Data_Dir returns 404.
//
// Validates: Requirements 1.3
func TestHandleDeleteDataDir_MissingName(t *testing.T) {
	s := newTestServer(t, nil)
	seedDataDirLayout(t, s)

	rec := callDeleteDataDir(s, http.MethodDelete, "does-not-exist")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %q)", rec.Code, rec.Body.String())
	}
	if body := decodeDataDirBody(t, rec); body["error"] != "scan not found" {
		t.Errorf("body error = %q, want %q", body["error"], "scan not found")
	}
}

// TestHandleDeleteDataDir_TraversalRejected verifies a DELETE whose {name}
// contains a traversal token ("../escape") is rejected with 400 and that a
// sentinel file placed outside Data_Dir (at the location the escape would have
// resolved to) is left untouched.
//
// Validates: Requirements 2.1
func TestHandleDeleteDataDir_TraversalRejected(t *testing.T) {
	s := newTestServer(t, nil)
	seedDataDirLayout(t, s)

	// Sentinel file OUTSIDE dataDir, at the path "../escape" resolves to.
	root := filepath.Clean(s.dataDir)
	sentinel := filepath.Join(filepath.Dir(root), "escape")
	if err := os.WriteFile(sentinel, []byte("must survive"), 0o644); err != nil {
		t.Fatalf("seed sentinel %q: %v", sentinel, err)
	}
	t.Cleanup(func() { _ = os.Remove(sentinel) })

	rec := callDeleteDataDir(s, http.MethodDelete, "../escape")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	if body := decodeDataDirBody(t, rec); body["error"] != "invalid scan name" {
		t.Errorf("body error = %q, want %q", body["error"], "invalid scan name")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel %q outside dataDir must still exist: %v", sentinel, err)
	}
}

// TestHandleDeleteDataDir_RunningScanConflict verifies that when an active
// (running) instance is rooted under the requested folder, the handler returns
// 409 and does not delete the folder.
//
// Validates: Requirements 4.1
func TestHandleDeleteDataDir_RunningScanConflict(t *testing.T) {
	s := newTestServer(t, nil)
	l := seedDataDirLayout(t, s)

	s.instances = map[string]*ScanInstance{
		"inst-run": {
			ID:      "inst-run",
			Status:  "running",
			scanDir: filepath.Join(l.scanFolder, "2026-05-14", "slug-a"),
		},
	}

	rec := callDeleteDataDir(s, http.MethodDelete, l.scanFolderNm)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %q)", rec.Code, rec.Body.String())
	}
	if body := decodeDataDirBody(t, rec); body["error"] != "scan is running" {
		t.Errorf("body error = %q, want %q", body["error"], "scan is running")
	}
	if fi, err := os.Stat(l.scanFolder); err != nil || !fi.IsDir() {
		t.Fatalf("scan folder %q must still exist while a scan runs (err=%v)", l.scanFolder, err)
	}
}

// TestHandleDeleteDataDir_RejectsNonDeleteMethods verifies GET and POST are
// rejected with 405 Method Not Allowed (the route is DELETE-only).
//
// Validates: Requirements 1.4
func TestHandleDeleteDataDir_RejectsNonDeleteMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s := newTestServer(t, nil)
			l := seedDataDirLayout(t, s)

			rec := callDeleteDataDir(s, method, l.scanFolderNm)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s status = %d, want 405 (body %q)", method, rec.Code, rec.Body.String())
			}
			// The folder must remain untouched on a rejected method.
			if fi, err := os.Stat(l.scanFolder); err != nil || !fi.IsDir() {
				t.Fatalf("scan folder %q must survive a %s (err=%v)", l.scanFolder, method, err)
			}
		})
	}
}
