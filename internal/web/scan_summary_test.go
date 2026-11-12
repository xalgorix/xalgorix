package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestScanRecordLiteSkipsEventsKeepsRest verifies the json.RawMessage shadow
// field intercepts the "events" key (so it is not decoded into []WSEvent)
// while every other ScanRecord field still parses normally.
func TestScanRecordLiteSkipsEventsKeepsRest(t *testing.T) {
	raw := []byte(`{
		"id": "scan-123",
		"instance_id": "inst-9",
		"target": "example.com",
		"started_at": "2026-06-01T10:00:00Z",
		"status": "finished",
		"scan_mode": "single",
		"total_tokens": 4242,
		"iterations": 7,
		"tool_calls": 13,
		"sub_scan_total": 3,
		"sub_scan_completed": 2,
		"vulns": [
			{"id": "v1", "title": "SQLi", "severity": "critical", "endpoint": "/login"},
			{"id": "v2", "title": "XSS", "severity": "medium", "endpoint": "/search"}
		],
		"events": [
			{"type": "tool_call", "tool_name": "nuclei", "output": "lots of data"},
			{"type": "agent_message", "content": "thinking..."}
		]
	}`)

	var lite scanRecordLite
	if err := json.Unmarshal(raw, &lite); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec := lite.ScanRecord

	if len(rec.Events) != 0 {
		t.Fatalf("expected events to be skipped, got %d events", len(rec.Events))
	}
	if rec.ID != "scan-123" {
		t.Errorf("id = %q, want scan-123", rec.ID)
	}
	if rec.InstanceID != "inst-9" {
		t.Errorf("instance_id = %q, want inst-9", rec.InstanceID)
	}
	if rec.Target != "example.com" {
		t.Errorf("target = %q, want example.com", rec.Target)
	}
	if rec.Status != "finished" {
		t.Errorf("status = %q, want finished", rec.Status)
	}
	if rec.TotalTokens != 4242 {
		t.Errorf("total_tokens = %d, want 4242", rec.TotalTokens)
	}
	if rec.Iterations != 7 || rec.ToolCalls != 13 {
		t.Errorf("iterations/tool_calls = %d/%d, want 7/13", rec.Iterations, rec.ToolCalls)
	}
	if rec.SubScanTotal != 3 || rec.SubScanCompleted != 2 {
		t.Errorf("sub_scan_total/completed = %d/%d, want 3/2", rec.SubScanTotal, rec.SubScanCompleted)
	}
	if len(rec.Vulns) != 2 {
		t.Fatalf("vulns = %d, want 2", len(rec.Vulns))
	}
	if rec.Vulns[0].Title != "SQLi" || rec.Vulns[1].Severity != "medium" {
		t.Errorf("vulns parsed incorrectly: %+v", rec.Vulns)
	}
}

// TestFindAllScanSummariesCachesByModtime verifies the per-file cache reuses a
// parsed record until the underlying file changes.
func TestFindAllScanSummariesCachesByModtime(t *testing.T) {
	s := newTestServer(t, nil)

	dir := filepath.Join(s.dataDir, "example.com", "2026-06-01", "scan-abc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scan.json")
	writeScan := func(target string) {
		body := `{"id":"scan-abc","target":"` + target + `","status":"finished","vulns":[]}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeScan("example.com")
	first := s.findAllScanSummaries()
	if len(first) != 1 || first[0].rec.Target != "example.com" {
		t.Fatalf("first walk = %+v", first)
	}

	// Cache entry exists keyed by path.
	s.scanSummaryCacheMu.Lock()
	_, cached := s.scanSummaryCache[path]
	s.scanSummaryCacheMu.Unlock()
	if !cached {
		t.Fatal("expected a cache entry after first walk")
	}

	// Delete the file: next walk must drop it from results and prune cache.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second := s.findAllScanSummaries()
	if len(second) != 0 {
		t.Fatalf("after delete walk = %d entries, want 0", len(second))
	}
	s.scanSummaryCacheMu.Lock()
	_, stillCached := s.scanSummaryCache[path]
	s.scanSummaryCacheMu.Unlock()
	if stillCached {
		t.Fatal("expected cache entry pruned after file removal")
	}
}

// writeSummaryScan writes a minimal finished scan.json for id.
func writeSummaryScan(t *testing.T, s *Server, id string) {
	t.Helper()
	dir := filepath.Join(s.dataDir, "example.com", "2026-06-01", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"id":"` + id + `","target":"example.com","status":"finished","vulns":[]}`
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// waitForSummaryJoiners blocks until n callers wait on the queued walk.
func waitForSummaryJoiners(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.scanSummaryWalkMu.Lock()
		got := 0
		if s.scanSummaryWalkNext != nil {
			got = s.scanSummaryWalkNext.joiners
		}
		s.scanSummaryWalkMu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d callers joined the queued walk, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// blockFirstSummaryWalk makes the first walk wait, after listing the data dir,
// until release is closed. entered is closed once it is waiting.
func blockFirstSummaryWalk(s *Server, walks *atomic.Int32) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	s.scanSummaryWalkHook = func() {
		if walks.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	return entered, release
}

// TestFindAllScanSummariesSharesWalks verifies that callers arriving while a
// walk runs share one queued walk instead of each walking the data dir, and
// that each still gets its own slice.
func TestFindAllScanSummariesSharesWalks(t *testing.T) {
	s := newTestServer(t, nil)
	writeSummaryScan(t, s, "scan-a")
	var walks atomic.Int32
	entered, release := blockFirstSummaryWalk(s, &walks)

	firstDone := make(chan []scanEntry)
	go func() { firstDone <- s.findAllScanSummaries() }()
	<-entered

	const joiners = 25
	results := make([][]scanEntry, joiners)
	var wg sync.WaitGroup
	for i := range joiners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = s.findAllScanSummaries()
		}()
	}
	waitForSummaryJoiners(t, s, joiners)
	close(release)

	if got := <-firstDone; len(got) != 1 {
		t.Fatalf("first caller got %d entries, want 1", len(got))
	}
	wg.Wait()
	for i, got := range results {
		if len(got) != 1 || got[0].rec.ID != "scan-a" {
			t.Fatalf("joiner %d got %+v, want scan-a", i, got)
		}
	}
	if n := walks.Load(); n != 2 {
		t.Fatalf("walks = %d, want 2 (the running walk plus one shared walk)", n)
	}

	results[0][0].dir = "mutated"
	if results[1][0].dir == "mutated" {
		t.Fatal("callers sharing a walk received the same slice")
	}
}

// TestFindAllScanSummariesJoinersSeeFreshResults verifies that a caller
// arriving while a walk runs never receives that walk's possibly stale
// results: a scan.json written before the call must be visible.
func TestFindAllScanSummariesJoinersSeeFreshResults(t *testing.T) {
	s := newTestServer(t, nil)
	writeSummaryScan(t, s, "scan-a")
	var walks atomic.Int32
	entered, release := blockFirstSummaryWalk(s, &walks)

	firstDone := make(chan []scanEntry)
	go func() { firstDone <- s.findAllScanSummaries() }()
	<-entered // the first walk has already listed the data dir

	writeSummaryScan(t, s, "scan-b")
	lateDone := make(chan []scanEntry)
	go func() { lateDone <- s.findAllScanSummaries() }()
	waitForSummaryJoiners(t, s, 1)
	close(release)

	if got := <-firstDone; len(got) != 1 {
		t.Fatalf("first caller got %d entries, want 1 (its walk listed before scan-b existed)", len(got))
	}
	if got := <-lateDone; len(got) != 2 {
		t.Fatalf("late caller got %d entries, want 2 (scan-b was written before it called)", len(got))
	}
}

// TestFindAllScanSummariesWalkPanicReleasesCallers verifies that a panicking
// walk panics in every caller waiting on it, rather than hanging them or
// handing them empty results, and leaves later walks working.
func TestFindAllScanSummariesWalkPanicReleasesCallers(t *testing.T) {
	s := newTestServer(t, nil)
	writeSummaryScan(t, s, "scan-a")
	var walks atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	s.scanSummaryWalkHook = func() {
		switch walks.Add(1) {
		case 1:
			close(entered)
			<-release
		case 2:
			panic("walk failed")
		}
	}
	recovered := func(call func()) (r any) {
		defer func() { r = recover() }()
		call()
		return nil
	}

	firstDone := make(chan any)
	go func() { firstDone <- recovered(func() { s.findAllScanSummaries() }) }()
	<-entered
	joinerDone := make(chan any)
	go func() { joinerDone <- recovered(func() { s.findAllScanSummaries() }) }()
	waitForSummaryJoiners(t, s, 1)
	close(release)

	if r := <-firstDone; r != nil {
		t.Fatalf("first caller panicked with %v; its walk succeeded", r)
	}
	if r := <-joinerDone; r != "walk failed" {
		t.Fatalf("joiner recovered %v, want the shared walk's panic", r)
	}
	if got := s.findAllScanSummaries(); len(got) != 1 {
		t.Fatalf("walk after the panic got %d entries, want 1", len(got))
	}
}

// TestHandleGetScanWalksDataDirOnce verifies that one scan-detail request
// walks the data dir once, although it both resolves the scan dir and
// attaches wildcard sub-scans.
func TestHandleGetScanWalksDataDirOnce(t *testing.T) {
	s := newTestServer(t, nil)
	writeSummaryScan(t, s, "scan-a")
	var walks atomic.Int32
	s.scanSummaryWalkHook = func() { walks.Add(1) }

	for _, path := range []string{"/api/scans/scan-a", "/api/scans/latest"} {
		walks.Store(0)
		w := httptest.NewRecorder()
		s.handleGetScan(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, w.Code, w.Body.String())
		}
		if n := walks.Load(); n != 1 {
			t.Fatalf("GET %s walked the data dir %d times, want 1", path, n)
		}
	}
}
