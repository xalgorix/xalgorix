package web

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// runExclusionResume resumes a wildcard scan whose discovery is done, with the
// given exclusion patterns in the live config (auto-resume reads the current
// server config). The server is already shutting down, so the subdomain loop
// stops at the resume index without dispatching a host: what is left on disk is
// exactly the inventory and index the next resume would use.
func runExclusionResume(t *testing.T, children []SubScanSummary, inventory []string, consumed int, patterns []string) (*ScanRecord, *QueueState) {
	t.Helper()
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "wildcard-exclude-resume", ScanMode: "wildcard", Status: "running"}
	s.instances[inst.ID] = inst
	dir := s.makeScanDir("example.invalid")
	s.saveScanRecordTo(&ScanRecord{
		ID: "wildcard-exclude-parent", InstanceID: inst.ID, Target: "example.invalid", ScanMode: "wildcard", Status: "running",
		SubScanTotal: len(inventory), SubScans: children,
	}, dir)
	close(s.shutdownChan)

	req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true,
		ResumeSubdomains: append([]string(nil), inventory...), ResumeSubIndex: consumed}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runWildcardTarget(context.Background(), &config.Config{WildcardExclude: patterns}, req, "example.invalid", 0, 1)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("subdomain loop dispatched a host assessment after the server began shutting down")
	}

	parent, ok := loadScanRecordFromDir(dir)
	if !ok {
		t.Fatal("parent record missing")
	}
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(inst.ID))
	if err != nil || entry.state == nil {
		t.Fatalf("queue state missing: %v", err)
	}
	return parent, entry.state
}

func subScanTargets(children []SubScanSummary) []string {
	out := make([]string, 0, len(children))
	for _, child := range children {
		out = append(out, child.Target)
	}
	return out
}

// An exclusion pattern added while a wildcard scan is in flight must not rewrite
// the part of the inventory the scan already worked through. The resume index
// points into the persisted list: dropping an already-assessed host from it
// shifts the index past a host that was never scanned, which is then recorded
// as finished and silently skipped.
func TestWildcardExcludeOnResumeKeepsConsumedInventory(t *testing.T) {
	inventory := []string{"example.invalid", "dev.example.invalid", "legacy.example.invalid", "a.example.invalid", "b.example.invalid"}
	children := []SubScanSummary{
		{ID: "child-root", Target: inventory[0], Status: "finished", Completion: "full"},
		{ID: "child-dev", Target: inventory[1], Status: "finished", Completion: "full", VulnCount: 1},
		// Moved past, but the saved entry carries no child id or start time
		// (older records): only the resume index protects it.
		{Target: inventory[2], Status: "finished"},
		{ID: "child-a", Target: inventory[3], Status: "finished", Completion: "full"},
		{Target: inventory[4], Status: "pending"},
	}
	parent, state := runExclusionResume(t, children, inventory, 4, []string{"dev", "legacy"})

	if got := subScanTargets(parent.SubScans); !reflect.DeepEqual(got, inventory) {
		t.Fatalf("resume rewrote the consumed inventory: got %v want %v", got, inventory)
	}
	if parent.SubScans[1].ID != "child-dev" {
		t.Fatalf("already-assessed host lost its child record: %+v", parent.SubScans[1])
	}
	if parent.SubScans[4].Status == "finished" {
		t.Fatalf("unscanned host recorded as finished: %+v", parent.SubScans[4])
	}
	if parent.SubScanSkipped != 0 {
		t.Fatalf("an assessed host was counted as skipped: SubScanSkipped=%d", parent.SubScanSkipped)
	}
	if !reflect.DeepEqual(state.WildcardSubdomains, inventory) || state.WildcardSubIndex != 4 {
		t.Fatalf("next resume would start at %d of %v, want 4 of %v", state.WildcardSubIndex, state.WildcardSubdomains, inventory)
	}
}

// When no saved inventory survives (older queue state and a parent record
// without children), resume re-reads raw discovery output, which comes back in
// random order. The saved resume index says nothing about that list, so it must
// not shield any of it from the patterns. The index here covers the whole raw
// list, so a filter that trusted it would keep every excluded host.
func TestWildcardExcludeOnResumeRawDiscoveryFiltersWholeList(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "wildcard-exclude-raw", ScanMode: "wildcard", Status: "running"}
	s.instances[inst.ID] = inst
	dir := s.makeScanDir("example.invalid")
	s.saveScanRecordTo(&ScanRecord{
		ID: "wildcard-exclude-raw-parent", InstanceID: inst.ID, Target: "example.invalid", ScanMode: "wildcard", Status: "running",
	}, dir)
	raw := "example.invalid\ndev.example.invalid\na.example.invalid\nb.example.invalid\n"
	if err := os.WriteFile(filepath.Join(dir, "subdomains.txt"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	close(s.shutdownChan)

	req := ScanRequest{InstanceID: inst.ID, ScanMode: "wildcard", IsResume: true, ResumeScanDir: dir, ResumeDiscoveryDone: true, ResumeSubIndex: 4}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runWildcardTarget(context.Background(), &config.Config{WildcardExclude: []string{"dev"}}, req, "example.invalid", 0, 1)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("subdomain loop dispatched a host assessment after the server began shutting down")
	}

	want := []string{"a.example.invalid", "b.example.invalid", "example.invalid"}
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(inst.ID))
	if err != nil || entry.state == nil {
		t.Fatalf("queue state missing: %v", err)
	}
	got := append([]string(nil), entry.state.WildcardSubdomains...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("raw re-read kept %v, want %v (dev excluded)", entry.state.WildcardSubdomains, want)
	}
}

// A scan's own exclude_subdomains must survive a restart or pause: wildcard
// resume rebuilds the request from the saved queue state, and a scan cut short
// during discovery runs discovery (and the filter) again.
func TestQueueStateKeepsPerScanWildcardExclusions(t *testing.T) {
	s := newTestServer(t, nil)
	req := ScanRequest{InstanceID: "wildcard-exclude-persist", Targets: []string{"example.invalid"}, ScanMode: "wildcard",
		ExcludeSubdomains: []string{"staging", "dev-*"}}
	s.saveQueueState(0, req)
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(req.InstanceID))
	if err != nil || entry.state == nil {
		t.Fatalf("queue state missing: %v", err)
	}
	if got := scanRequestFromQueueState(entry.state, entry.path).ExcludeSubdomains; !reflect.DeepEqual(got, req.ExcludeSubdomains) {
		t.Fatalf("resumed request has exclude_subdomains %v, want %v", got, req.ExcludeSubdomains)
	}
}

// Hosts the scan has not reached yet still follow the patterns on resume, while
// a host whose assessment already started (it has a child record) is kept so its
// work and findings stay attached to the parent.
func TestWildcardExcludeOnResumeFiltersOnlyUnstartedHosts(t *testing.T) {
	inventory := []string{"example.invalid", "a.example.invalid", "dev.example.invalid", "staging.example.invalid", "b.example.invalid"}
	children := []SubScanSummary{
		{ID: "child-root", Target: inventory[0], Status: "finished", Completion: "full"},
		{ID: "child-a", Target: inventory[1], Status: "finished", Completion: "full"},
		{ID: "child-dev", Target: inventory[2], Status: "stopped", StartedAt: "2026-01-01T00:00:00Z"},
		{Target: inventory[3], Status: "pending"},
		{Target: inventory[4], Status: "pending"},
	}
	parent, state := runExclusionResume(t, children, inventory, 2, []string{"dev", "staging"})

	want := []string{inventory[0], inventory[1], inventory[2], inventory[4]}
	if got := subScanTargets(parent.SubScans); !reflect.DeepEqual(got, want) {
		t.Fatalf("got inventory %v want %v", got, want)
	}
	if parent.SubScans[2].ID != "child-dev" {
		t.Fatalf("started host lost its child record: %+v", parent.SubScans[2])
	}
	if parent.SubScanSkipped != 1 {
		t.Fatalf("SubScanSkipped=%d want 1 (the unstarted staging host)", parent.SubScanSkipped)
	}
	if !reflect.DeepEqual(state.WildcardSubdomains, want) || state.WildcardSubIndex != 2 {
		t.Fatalf("next resume would start at %d of %v, want 2 of %v", state.WildcardSubIndex, state.WildcardSubdomains, want)
	}
}
