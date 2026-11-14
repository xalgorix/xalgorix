package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newScanDirTestServer returns a server whose data dir sits one level below a
// test-owned temp dir, so a scan dir that escapes the data dir lands in that
// temp dir (and is cleaned up) instead of somewhere shared.
func newScanDirTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := newTestServer(t, nil)
	outer := t.TempDir()
	s.dataDir = filepath.Join(outer, "data")
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return s, outer
}

// relToDataDir returns dir relative to the data dir, failing the test when
// dir is not strictly inside it.
func relToDataDir(t *testing.T, s *Server, target, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(filepath.Clean(s.dataDir), filepath.Clean(dir))
	if err != nil {
		t.Fatalf("target %q: scan dir %q not relative to data dir: %v", target, dir, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("target %q: scan dir %q escaped the data dir %q (rel %q)", target, dir, s.dataDir, rel)
	}
	return rel
}

func TestMakeScanDirKeepsTraversalTargetsInsideDataDir(t *testing.T) {
	targets := []string{
		"https://a.test/../../../escaped",
		"http://a.test/../../../../escaped",
		"https://a.test/./../.././../escaped",
		"../escaped",
		"/../escaped",
		"a.test/../../escaped",
		"https://a.test/..",
		"a.test/..",
		"..",
		".",
		"/",
		"https://a.test/.../....",
	}
	date := time.Now().Format("2006-01-02")
	for _, target := range targets {
		s, outer := newScanDirTestServer(t)
		dir := s.makeScanDir(target)
		rel := relToDataDir(t, s, target, dir)

		// Shape is <target segments...>/<date>/<slug>: the date folder must
		// never become a top-level entry of the data dir.
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) < 3 {
			t.Fatalf("target %q: scan dir %q (rel %q) is missing the target folder", target, dir, rel)
		}
		if parts[0] == date {
			t.Fatalf("target %q: scan dir %q put the date folder at the top of the data dir", target, dir)
		}

		// Nothing may be created next to the data dir.
		entries, err := os.ReadDir(outer)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "data" {
				t.Fatalf("target %q: created %q outside the data dir", target, filepath.Join(outer, e.Name()))
			}
		}
	}
}

func TestMakeScanDirKeepsOrdinaryTargetLayout(t *testing.T) {
	s, _ := newScanDirTestServer(t)
	date := time.Now().Format("2006-01-02")
	cases := []struct {
		target string
		prefix string
	}{
		{"example.com", filepath.Join("example.com", date) + string(os.PathSeparator)},
		{"example.com:8443", filepath.Join("example.com:8443", date) + string(os.PathSeparator)},
		{"https://example.com", filepath.Join("https:", "example.com", date) + string(os.PathSeparator)},
		{"https://example.com/app/", filepath.Join("https:", "example.com", "app", date) + string(os.PathSeparator)},
		{"http://example.com/a/b", filepath.Join("http:", "example.com", "a", "b", date) + string(os.PathSeparator)},
		{"_dmarc.example.com", filepath.Join("_dmarc.example.com", date) + string(os.PathSeparator)},
	}
	for _, tc := range cases {
		dir := s.makeScanDir(tc.target)
		rel := relToDataDir(t, s, tc.target, dir)
		if !strings.HasPrefix(rel, tc.prefix) {
			t.Fatalf("target %q: scan dir rel %q, want prefix %q (layout changed)", tc.target, rel, tc.prefix)
		}
		if leaf := filepath.Base(dir); !strings.HasPrefix(leaf, sanitizeTarget(tc.target)+"_") {
			t.Fatalf("target %q: leaf %q lost the sanitized target prefix", tc.target, leaf)
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("target %q: scan dir %q was not created: %v", tc.target, dir, err)
		}
	}
}

func TestMakeScanDirKeepsScansOutOfReservedStores(t *testing.T) {
	s, _ := newScanDirTestServer(t)
	for _, target := range []string{"context", "Sources", "_saved", "_schedules", "logos", ".dispatches", "context/../sources", "llm_keys.json"} {
		dir := s.makeScanDir(target)
		rel := relToDataDir(t, s, target, dir)
		top := strings.Split(rel, string(os.PathSeparator))[0]
		if reservedTopLevelEntry(top) {
			t.Fatalf("target %q: scan dir %q landed inside reserved store %q", target, dir, top)
		}
	}
}

// assertRealPathInsideDataDir resolves symlinks and fails when dir really
// lives outside the data dir.
func assertRealPathInsideDataDir(t *testing.T, s *Server, target, dir string) {
	t.Helper()
	realData, err := filepath.EvalSymlinks(s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("target %q: scan dir %q was not created: %v", target, dir, err)
	}
	rel, err := filepath.Rel(realData, realDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("target %q: scan dir %q really lives at %q, outside the data dir", target, dir, realDir)
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s gained entries %v; scan output escaped through a symlink", dir, entries)
	}
}

func TestMakeScanDirDoesNotFollowSymlinkOutOfDataDir(t *testing.T) {
	s, outer := newScanDirTestServer(t)
	outside := filepath.Join(outer, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlink can already sit inside the data dir, e.g. in a cloned
	// source repository stored under an earlier scan's folder.
	if err := os.MkdirAll(filepath.Join(s.dataDir, "a.test", "repo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.dataDir, "a.test", "repo", "esc")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// The same escape spelled as a relative link.
	if err := os.Symlink(filepath.Join("..", "..", "..", "outside"), filepath.Join(s.dataDir, "a.test", "repo", "relesc")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"a.test/repo/esc/pwn", "a.test/repo/esc", "a.test/repo/relesc/pwn"} {
		dir := s.makeScanDir(target)
		relToDataDir(t, s, target, dir)
		assertRealPathInsideDataDir(t, s, target, dir)
		assertEmptyDir(t, outside)
	}

	// A relative link that stays inside the data dir is still followed.
	if err := os.MkdirAll(filepath.Join(s.dataDir, "moved"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("moved", filepath.Join(s.dataDir, "b.test")); err != nil {
		t.Fatal(err)
	}
	inside := s.makeScanDir("b.test")
	if rel := relToDataDir(t, s, "b.test", inside); !strings.HasPrefix(rel, "b.test"+string(os.PathSeparator)) {
		t.Fatalf("in-root symlinked target folder was not used: %q", rel)
	}
	assertRealPathInsideDataDir(t, s, "b.test", inside)

	// A resume dir that runs through the same symlink must not be reused.
	resume := filepath.Join(s.dataDir, "a.test", "repo", "esc", "2026-01-01", "a.test_resume")
	dir, resumed := s.resumeScanDirOrNew(resume, "a.test")
	if resumed {
		t.Fatalf("resume through a symlink out of the data dir was accepted: %q", dir)
	}
	assertRealPathInsideDataDir(t, s, "a.test (resume)", dir)
	assertEmptyDir(t, outside)
}

func TestMakeScanDirDoesNotNestInsideAnotherScan(t *testing.T) {
	s, _ := newScanDirTestServer(t)
	first := s.makeScanDir("victim.test")
	s.saveScanRecordTo(&ScanRecord{ID: filepath.Base(first), Target: "victim.test", Status: "finished"}, first)
	if _, err := os.Stat(filepath.Join(first, "scan.json")); err != nil {
		t.Fatalf("fixture scan record missing: %v", err)
	}
	firstRel := relToDataDir(t, s, "victim.test", first)

	target := filepath.ToSlash(firstRel) + "/hidden"
	second := s.makeScanDir(target)
	relToDataDir(t, s, target, second)
	if rel, err := filepath.Rel(first, second); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("target %q put a new scan %q inside existing scan %q", target, second, first)
	}
	s.saveScanRecordTo(&ScanRecord{ID: filepath.Base(second), Target: target, Status: "finished"}, second)
	listed := map[string]bool{}
	for _, entry := range s.findAllScans() {
		listed[entry.dir] = true
	}
	if !listed[first] || !listed[second] {
		t.Fatalf("both scans must stay listed; got %v", listed)
	}

	// A scan.json that is a (dangling) symlink still marks a scan folder for
	// the walker, so it must block nesting too.
	marked := filepath.Join(s.dataDir, "h.test", "2026-01-01", "h.test_leaf")
	if err := os.MkdirAll(marked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(marked, "missing.json"), filepath.Join(marked, "scan.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	hidden := s.makeScanDir("h.test/2026-01-01/h.test_leaf/x")
	if rel, err := filepath.Rel(marked, hidden); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("new scan %q nested under a folder whose scan.json is a symlink", hidden)
	}
}

func TestMakeScanDirBoundsDeepTargets(t *testing.T) {
	s, _ := newScanDirTestServer(t)
	for _, target := range []string{
		"https://a.test/" + strings.Repeat("d/", 5000),
		// Every segment is a valid folder name; only the 1024-byte cap applies.
		"https://a.test/" + strings.Repeat(strings.Repeat("x", 200)+"/", 20),
	} {
		start := time.Now()
		dir := s.makeScanDir(target)
		elapsed := time.Since(start)
		rel := relToDataDir(t, s, "deep target", dir)
		if !strings.HasPrefix(rel, "unknown"+string(os.PathSeparator)) {
			t.Fatalf("deep target was not bounded; rel has %d bytes", len(rel))
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("bounded scan dir %q was not created: %v", dir, err)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("bounding a deep target took %v", elapsed)
		}
	}
	// A target at the segment cap keeps its own folder.
	parts := make([]string, maxScanTargetDirSegments)
	for i := range parts {
		parts[i] = "p"
	}
	dir := s.makeScanDir(strings.Join(parts, "/"))
	if rel := relToDataDir(t, s, "cap target", dir); strings.HasPrefix(rel, "unknown"+string(os.PathSeparator)) {
		t.Fatalf("a target with %d segments should keep its folder; got %q", maxScanTargetDirSegments, rel)
	}
}

func TestScanDirForResumeNewScanStaysInsideDataDir(t *testing.T) {
	s, _ := newScanDirTestServer(t)
	target := "https://a.test/../../../escaped"
	dir, resumed := s.scanDirForResume(ScanRequest{}, target)
	if resumed {
		t.Fatal("a non-resume request must not resume")
	}
	relToDataDir(t, s, target, dir)

	sub, _ := s.scanDirForWildcardSubdomainResume(ScanRequest{}, "../../escaped.a.test", 0)
	relToDataDir(t, s, "../../escaped.a.test", sub)
}
