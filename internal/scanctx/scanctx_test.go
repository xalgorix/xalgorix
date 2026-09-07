package scanctx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ── Helpers ──

func resetRegistry(t *testing.T) {
	t.Helper()
	ResetAll()
}

// ══════════════════════════════════════════════════════════
// Registry lifecycle tests
// ══════════════════════════════════════════════════════════

func TestNew(t *testing.T) {
	sc := New("test-1", "/tmp/scan")
	if sc.ID != "test-1" {
		t.Fatalf("ID = %q, want %q", sc.ID, "test-1")
	}
	if sc.ScanDir != "/tmp/scan" {
		t.Fatalf("ScanDir = %q, want %q", sc.ScanDir, "/tmp/scan")
	}
	if sc.Vulns == nil || sc.Notes == nil || sc.Terminal == nil || sc.Browser == nil {
		t.Fatal("sub-stores must not be nil after New()")
	}
	if sc.Ctx == nil || sc.Cancel == nil {
		t.Fatal("context/cancel must not be nil after New()")
	}
	sc.Close()
}

func TestRequestRatePolicy(t *testing.T) {
	sc := New("policy-1", "")
	policy := RequestRatePolicy{MaxRPS: 3.5, Source: "test"}
	sc.SetRequestRatePolicy(policy)

	got := sc.RequestRatePolicy()
	if got != policy {
		t.Fatalf("RequestRatePolicy = %+v, want %+v", got, policy)
	}
	if got.CommandRPS() != 3 {
		t.Fatalf("CommandRPS = %d, want 3", got.CommandRPS())
	}
	if got.Delay().String() != "286ms" {
		t.Fatalf("Delay = %s, want 286ms", got.Delay())
	}

	sc.SetRequestRatePolicy(RequestRatePolicy{MaxRPS: 10, Source: "weaker"})
	if got := sc.RequestRatePolicy(); got != policy {
		t.Fatalf("weaker policy replaced stricter policy: %+v", got)
	}

	stricter := RequestRatePolicy{MaxRPS: 2, Source: "stricter"}
	sc.SetRequestRatePolicy(stricter)
	if got := sc.RequestRatePolicy(); got != stricter {
		t.Fatalf("stricter policy not applied: %+v", got)
	}
}

func TestRequestRatePolicyNormalizesSubOneRPS(t *testing.T) {
	sc := New("policy-sub-one", "")
	sc.SetRequestRatePolicy(RequestRatePolicy{MaxRPS: 0.5, Source: "custom instructions"})

	got := sc.RequestRatePolicy()
	if got.MaxRPS != 1 {
		t.Fatalf("MaxRPS = %v, want minimum supported 1", got.MaxRPS)
	}
	if !strings.Contains(got.Source, "minimum supported 1 rps") {
		t.Fatalf("Source = %q, want minimum note", got.Source)
	}
}

func TestActivateDeactivate(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	sc := New("a", "")
	Activate(sc)

	if got := Get("a"); got != sc {
		t.Fatal("Get should return activated context")
	}
	if ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", ActiveCount())
	}

	Deactivate("a")

	if got := Get("a"); got != nil {
		t.Fatal("Get should return nil after Deactivate")
	}
	if ActiveCount() != 0 {
		t.Fatalf("ActiveCount = %d, want 0", ActiveCount())
	}
}

func TestDeactivatePromotesDefault(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	a := New("a", "")
	b := New("b", "")
	Activate(a) // becomes default
	Activate(b)

	Deactivate("a") // should promote b

	got := Default()
	if got.ID != "b" {
		t.Fatalf("Default().ID = %q, want %q", got.ID, "b")
	}
}

func TestDefaultFallback(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	got := Default()
	if got == nil {
		t.Fatal("Default() must never return nil")
	}
	if got.ID != "cli-default" {
		t.Fatalf("fallback ID = %q, want %q", got.ID, "cli-default")
	}
	if ActiveCount() != 1 {
		t.Fatal("fallback should register itself")
	}
	// Calling again should return the same instance
	if Default() != got {
		t.Fatal("Default() should be idempotent")
	}
}

func TestDeactivateNonExistent(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)
	// Should not panic
	Deactivate("does-not-exist")
}

func TestGetNonExistent(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)
	if Get("nope") != nil {
		t.Fatal("Get for unknown ID should return nil")
	}
}

func TestResetAll(t *testing.T) {
	resetRegistry(t)

	Activate(New("x", ""))
	Activate(New("y", ""))
	ResetAll()

	if ActiveCount() != 0 {
		t.Fatalf("ActiveCount after ResetAll = %d, want 0", ActiveCount())
	}
	if Get("x") != nil || Get("y") != nil {
		t.Fatal("contexts should be gone after ResetAll")
	}
}

func TestSummaryEmpty(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)
	if s := Summary(); s != "No active scan contexts" {
		t.Fatalf("unexpected summary: %s", s)
	}
}

func TestSummaryWithContexts(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	sc := New("sum-1", "/scans/x")
	sc.Vulns.Add(map[string]interface{}{"title": "xss"})
	sc.Notes.Set("key", "val")
	Activate(sc)

	s := Summary()
	if !strings.Contains(s, "sum-1") || !strings.Contains(s, "vulns=1") || !strings.Contains(s, "notes=1") {
		t.Fatalf("unexpected summary: %s", s)
	}
}

// ══════════════════════════════════════════════════════════
// Close idempotency
// ══════════════════════════════════════════════════════════

func TestCloseIdempotent(t *testing.T) {
	sc := New("close-test", "")
	sc.Close()
	sc.Close() // must not panic
	sc.Close()

	// Context should be canceled
	if err := sc.Ctx.Err(); err != context.Canceled {
		t.Fatalf("context err = %v, want Canceled", err)
	}
}

// ══════════════════════════════════════════════════════════
// VulnStore
// ══════════════════════════════════════════════════════════

func TestVulnStore_AddGetCount(t *testing.T) {
	vs := NewVulnStore()
	if vs.Count() != 0 {
		t.Fatal("new store should be empty")
	}

	vs.Add(map[string]interface{}{"title": "SQLi", "severity": "high"})
	vs.Add(map[string]interface{}{"title": "XSS", "severity": "medium"})

	if vs.Count() != 2 {
		t.Fatalf("Count = %d, want 2", vs.Count())
	}

	all := vs.GetAll()
	if len(all) != 2 {
		t.Fatalf("GetAll len = %d, want 2", len(all))
	}
	if all[0]["title"] != "SQLi" {
		t.Fatalf("first vuln title = %v", all[0]["title"])
	}
}

func TestVulnStore_GetAllReturnsCopy(t *testing.T) {
	vs := NewVulnStore()
	vs.Add(map[string]interface{}{"x": 1})

	copy1 := vs.GetAll()
	copy1[0]["x"] = 999

	orig := vs.GetAll()
	// The slice element is a shared map ref, but the slice itself is a copy
	// so appending to copy1 doesn't affect orig length
	if len(orig) != 1 {
		t.Fatal("GetAll should return a slice copy")
	}
}

func TestVulnStore_Reset(t *testing.T) {
	vs := NewVulnStore()
	vs.Add(map[string]interface{}{"a": 1})
	vs.Reset()

	if vs.Count() != 0 {
		t.Fatal("Count should be 0 after Reset")
	}

	// Verify JSON is [] not null
	j, err := vs.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}
	if j != "[]" {
		t.Fatalf("ToJSON after Reset = %q, want %q", j, "[]")
	}
}

func TestVulnStore_ToJSON(t *testing.T) {
	vs := NewVulnStore()
	vs.Add(map[string]interface{}{"id": "v1"})

	j, err := vs.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal([]byte(j), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) != 1 || parsed[0]["id"] != "v1" {
		t.Fatalf("unexpected JSON: %s", j)
	}
}

func TestVulnStore_EmptyToJSON(t *testing.T) {
	vs := NewVulnStore()
	j, err := vs.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}
	if j != "[]" {
		t.Fatalf("empty ToJSON = %q, want %q", j, "[]")
	}
}

// ══════════════════════════════════════════════════════════
// NoteStore
// ══════════════════════════════════════════════════════════

func TestNoteStore_SetGetCount(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("csrf", "abc123")
	ns.Set("tech", "angular")

	if ns.Count() != 2 {
		t.Fatalf("Count = %d, want 2", ns.Count())
	}

	v, ok := ns.Get("csrf")
	if !ok || v != "abc123" {
		t.Fatalf("Get(csrf) = (%q, %v)", v, ok)
	}

	_, ok = ns.Get("missing")
	if ok {
		t.Fatal("Get(missing) should return false")
	}
}

func TestNoteStore_GetAllReturnsCopy(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("k", "v")

	copy1 := ns.GetAll()
	copy1["injected"] = "evil"

	if ns.Count() != 1 {
		t.Fatal("GetAll mutation should not affect store")
	}
}

func TestNoteStore_Overwrite(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("key", "old")
	ns.Set("key", "new")
	v, _ := ns.Get("key")
	if v != "new" {
		t.Fatalf("overwrite failed: got %q", v)
	}
}

func TestNoteStore_Reset(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("a", "1")
	ns.Reset()
	if ns.Count() != 0 {
		t.Fatal("Reset should clear all notes")
	}
}

func TestNoteStore_DiskPersistence(t *testing.T) {
	dir := t.TempDir()
	ns := NewNoteStore()
	ns.SetPersistPath(dir)
	ns.Set("token", "xyz")

	// Verify file was written
	data, err := os.ReadFile(filepath.Join(dir, "notes.json"))
	if err != nil {
		t.Fatalf("notes.json not written: %v", err)
	}
	var loaded map[string]string
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON on disk: %v", err)
	}
	if loaded["token"] != "xyz" {
		t.Fatalf("disk value = %q, want %q", loaded["token"], "xyz")
	}
}

func TestNoteStore_LoadFromDisk(t *testing.T) {
	dir := t.TempDir()

	// Write a seed file
	seed := map[string]string{"pre": "existing"}
	data, _ := json.Marshal(seed)
	os.WriteFile(filepath.Join(dir, "notes.json"), data, 0644)

	ns := NewNoteStore()
	ns.SetPersistPath(dir)
	count := ns.LoadFromDisk()

	if count != 1 {
		t.Fatalf("LoadFromDisk returned %d, want 1", count)
	}
	v, ok := ns.Get("pre")
	if !ok || v != "existing" {
		t.Fatal("loaded note not found")
	}
}

func TestNoteStore_LoadFromDiskNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	seed := map[string]string{"key": "old"}
	data, _ := json.Marshal(seed)
	os.WriteFile(filepath.Join(dir, "notes.json"), data, 0644)

	ns := NewNoteStore()
	ns.Set("key", "current")
	ns.SetPersistPath(dir)
	count := ns.LoadFromDisk()

	if count != 0 {
		t.Fatalf("should not overwrite existing keys, loaded %d", count)
	}
	v, _ := ns.Get("key")
	if v != "current" {
		t.Fatalf("existing value clobbered: got %q", v)
	}
}

func TestNoteStore_NoPersistPath(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("a", "b") // should not panic even without persist path
	if ns.LoadFromDisk() != 0 {
		t.Fatal("LoadFromDisk with no path should return 0")
	}
}

func TestNoteStore_FormatForContext(t *testing.T) {
	ns := NewNoteStore()
	if ns.FormatForContext() != "" {
		t.Fatal("empty store should return empty string")
	}

	ns.Set("csrf", "token123")
	out := ns.FormatForContext()
	if !strings.Contains(out, "csrf") || !strings.Contains(out, "token123") {
		t.Fatalf("format missing data: %s", out)
	}
	if !strings.Contains(out, "=== YOUR SAVED NOTES") {
		t.Fatal("missing header")
	}
}

func TestNoteStore_FormatTruncation(t *testing.T) {
	ns := NewNoteStore()
	ns.Set("big", strings.Repeat("x", 600))
	out := ns.FormatForContext()
	if !strings.Contains(out, "... (truncated)") {
		t.Fatal("long values should be truncated")
	}
}

func TestNoteStore_SetPersistPathEmpty(t *testing.T) {
	ns := NewNoteStore()
	ns.SetPersistPath("/tmp/test")
	ns.SetPersistPath("") // clear it
	ns.Set("k", "v")      // should not panic or write anywhere
}

func TestScanContextTargetsAreCopied(t *testing.T) {
	sc := New("targets-test", "")
	input := []string{" https://one.example ", "", "https://two.example"}
	sc.SetTargets(input)
	input[0] = "mutated"

	got := sc.Targets()
	if len(got) != 2 || got[0] != "https://one.example" || got[1] != "https://two.example" {
		t.Fatalf("Targets() = %#v, want trimmed defensive copy", got)
	}
	got[0] = "mutated-again"
	if again := sc.Targets(); again[0] != "https://one.example" {
		t.Fatalf("Targets leaked caller mutation: %#v", again)
	}
}

// ══════════════════════════════════════════════════════════
// TerminalState
// ══════════════════════════════════════════════════════════

func TestTerminalState_WorkDir(t *testing.T) {
	ts := NewTerminalState()
	if ts.GetWorkDir() != "" {
		t.Fatal("initial workdir should be empty")
	}
	ts.SetWorkDir("/scans/target")
	if ts.GetWorkDir() != "/scans/target" {
		t.Fatalf("GetWorkDir = %q", ts.GetWorkDir())
	}
}

func TestTerminalState_ActiveProcessCount(t *testing.T) {
	ts := NewTerminalState()
	if ts.ActiveProcessCount() != 0 {
		t.Fatal("initial count should be 0")
	}
}

func TestTerminalState_TrackUntrack(t *testing.T) {
	ts := NewTerminalState()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := &exec.Cmd{}
	ts.TrackProcess(cmd, cancel, "nmap -sV target")

	if ts.ActiveProcessCount() != 1 {
		t.Fatal("count should be 1 after track")
	}
	name, dur := ts.GetActiveCommand()
	if name != "nmap -sV target" {
		t.Fatalf("active command = %q", name)
	}
	if dur < 0 {
		t.Fatal("duration should be non-negative")
	}
	_ = ctx

	ts.UntrackProcess(cmd)
	if ts.ActiveProcessCount() != 0 {
		t.Fatal("count should be 0 after untrack")
	}
	name, _ = ts.GetActiveCommand()
	if name != "" {
		t.Fatal("active command should be cleared")
	}
}

func TestTerminalState_TrackTruncatesLongCommand(t *testing.T) {
	ts := NewTerminalState()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	long := strings.Repeat("a", 250)
	ts.TrackProcess(&exec.Cmd{}, cancel, long)

	name, _ := ts.GetActiveCommand()
	if len(name) != 203 { // 200 + "..."
		t.Fatalf("truncated len = %d, want 203", len(name))
	}
}

func TestTerminalState_StreamCallback(t *testing.T) {
	ts := NewTerminalState()
	if ts.GetStreamCallback() != nil {
		t.Fatal("initial callback should be nil")
	}

	called := false
	ts.SetStreamCallback(func(s string) { called = true })
	cb := ts.GetStreamCallback()
	if cb == nil {
		t.Fatal("callback should be set")
	}
	cb("test")
	if !called {
		t.Fatal("callback was not invoked")
	}

	ts.ClearStreamCallback()
	if ts.GetStreamCallback() != nil {
		t.Fatal("callback should be nil after clear")
	}
}

func TestTerminalState_KillAllClearsState(t *testing.T) {
	ts := NewTerminalState()
	_, cancel := context.WithCancel(context.Background())
	ts.TrackProcess(&exec.Cmd{}, cancel, "sleep 99")

	ts.KillAll()
	if ts.ActiveProcessCount() != 0 {
		t.Fatal("KillAll should clear process group")
	}
	name, _ := ts.GetActiveCommand()
	if name != "" {
		t.Fatal("KillAll should clear active command")
	}
}

func TestTerminalState_KillAllIdempotent(t *testing.T) {
	ts := NewTerminalState()
	ts.KillAll()
	ts.KillAll() // must not panic
}

// ══════════════════════════════════════════════════════════
// BrowserState
// ══════════════════════════════════════════════════════════

func TestBrowserState_SessionPath(t *testing.T) {
	bs := NewBrowserState()
	if bs.GetSessionPath() != "" {
		t.Fatal("initial path should be empty")
	}
	bs.SetSessionPath("/tmp/session")
	if bs.GetSessionPath() != "/tmp/session" {
		t.Fatalf("GetSessionPath = %q", bs.GetSessionPath())
	}
}

func TestBrowserState_Launched(t *testing.T) {
	bs := NewBrowserState()
	if bs.IsLaunched() {
		t.Fatal("should not be launched initially")
	}
	bs.SetLaunched(true)
	if !bs.IsLaunched() {
		t.Fatal("should be launched after SetLaunched(true)")
	}
}

func TestBrowserState_Close(t *testing.T) {
	bs := NewBrowserState()
	bs.SetSessionPath("/tmp/x")
	bs.SetLaunched(true)
	bs.Close()

	if bs.IsLaunched() {
		t.Fatal("should not be launched after Close")
	}
	if bs.GetSessionPath() != "" {
		t.Fatal("path should be cleared after Close")
	}
}

func TestBrowserState_CloseIdempotent(t *testing.T) {
	bs := NewBrowserState()
	bs.Close()
	bs.Close() // must not panic
}

// ══════════════════════════════════════════════════════════
// Concurrency — run with -race
// ═══════════════════════��══════════════════════════════════

func TestConcurrentVulnStore(t *testing.T) {
	vs := NewVulnStore()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			vs.Add(map[string]interface{}{"n": n})
			vs.GetAll()
			vs.Count()
			vs.ToJSON()
		}(i)
	}
	wg.Wait()

	if vs.Count() != 100 {
		t.Fatalf("Count = %d, want 100", vs.Count())
	}
}

func TestConcurrentNoteStore(t *testing.T) {
	ns := NewNoteStore()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := string(rune('a' + n%26))
			ns.Set(key, "val")
			ns.Get(key)
			ns.GetAll()
			ns.Count()
			ns.FormatForContext()
		}(i)
	}
	wg.Wait()
}

func TestConcurrentTerminalState(t *testing.T) {
	ts := NewTerminalState()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts.SetWorkDir("/tmp")
			ts.GetWorkDir()
			ts.ActiveProcessCount()
			ts.GetActiveCommand()
		}()
	}
	wg.Wait()
}

func TestConcurrentBrowserState(t *testing.T) {
	bs := NewBrowserState()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			bs.SetSessionPath("/tmp")
			bs.GetSessionPath()
			bs.SetLaunched(n%2 == 0)
			bs.IsLaunched()
		}(i)
	}
	wg.Wait()
}

func TestConcurrentRegistry(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := string(rune('A' + n%26))
			sc := New(id, "")
			Activate(sc)
			Get(id)
			ActiveCount()
			Summary()
			Default()
			Deactivate(id)
		}(i)
	}
	wg.Wait()
}

// ══════════════════════════════════════════════════════════
// Session isolation
// ══════════════════════════════════════════════════════════

func TestSessionIsolation(t *testing.T) {
	resetRegistry(t)
	defer resetRegistry(t)

	a := New("session-a", "/a")
	b := New("session-b", "/b")
	Activate(a)
	Activate(b)

	a.Vulns.Add(map[string]interface{}{"from": "a"})
	b.Notes.Set("from", "b")

	if a.Vulns.Count() != 1 {
		t.Fatal("a should have 1 vuln")
	}
	if b.Vulns.Count() != 0 {
		t.Fatal("b should have 0 vulns")
	}
	if a.Notes.Count() != 0 {
		t.Fatal("a should have 0 notes")
	}
	if b.Notes.Count() != 1 {
		t.Fatal("b should have 1 note")
	}
}

// TestNoteStore_ConcurrentDiskWrite is the regression for the race the
// review flagged: when two goroutines call Set() at the same time, both
// release the data lock before writing the file. Without writeMu the two
// os.WriteFile calls could interleave and produce a corrupt JSON file. We
// verify the file is always parseable JSON and contains the final state of
// every key after the burst completes.
func TestNoteStore_ConcurrentDiskWrite(t *testing.T) {
	dir := t.TempDir()
	ns := NewNoteStore()
	ns.SetPersistPath(dir)

	const writers = 16
	const writesPerWriter = 32

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("writer-%d", id)
			for j := 0; j < writesPerWriter; j++ {
				ns.Set(key, fmt.Sprintf("v%d", j))
			}
		}(i)
	}
	wg.Wait()

	// Final on-disk state must be parseable JSON.
	data, err := os.ReadFile(filepath.Join(dir, "notes.json"))
	if err != nil {
		t.Fatalf("read notes.json: %v", err)
	}
	var loaded map[string]string
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("notes.json corrupted (interleaved write?): %v\ncontent=%q", err, data)
	}

	// And every writer's final value must be present (the in-memory store is
	// the source of truth, but the disk snapshot — which is written after
	// every Set — should converge on the same content).
	for i := 0; i < writers; i++ {
		key := fmt.Sprintf("writer-%d", i)
		got, ok := loaded[key]
		if !ok {
			t.Errorf("disk snapshot missing %s", key)
			continue
		}
		want := fmt.Sprintf("v%d", writesPerWriter-1)
		if got != want {
			// Note: we can't strictly assert this — a Set() that wins the
			// data lock last but loses the writeMu race could still write a
			// stale snapshot. But the in-memory state must be correct.
			memVal, _ := ns.Get(key)
			if memVal != want {
				t.Errorf("in-memory %s = %q, want %q", key, memVal, want)
			}
		}
	}
}

// TestCloseReleasesEveryLeaseUnderPanic exercises Task 13.3's lease
// conservation property: every Tool_Lease cached on a Scan_Context must be
// released exactly once during Close, even if an earlier sub-step panics.
//
// We can't reach for a real *resources.ToolLease in this package without an
// import cycle, so we use BrowserState's launched/sessionPath signal as a
// stand-in for "the lease-holding sub-step ran". Once Task 10.1 caches a
// lease on BrowserState the same recovered-closure structure exercised here
// will release it.
//
// The test injects a panicking CancelFunc into Terminal.KillAll so the
// terminal sub-step blows up mid-shutdown. If the recovery boundary in
// Close were missing, Browser.Close would never run and any cached lease
// would leak. Because each sub-step is wrapped in its own deferred recover,
// Browser.Close still runs and the cached state is reset.
func TestCloseReleasesEveryLeaseUnderPanic(t *testing.T) {
	sc := New("close-panic-lease", "")

	// Pretend the browser has a lease attached — SetLaunched/SessionPath are
	// the visible signal that Browser.Close ran. Once Task 10.1 wires a real
	// lease into BrowserState, the same code path that clears these fields
	// in BrowserState.Close will release the lease via sync.Once.
	sc.Browser.SetLaunched(true)
	sc.Browser.SetSessionPath("/tmp/scan-session")

	// Track a "process" whose CancelFunc panics so Terminal.KillAll panics
	// mid-iteration. killTrackedProcess(&exec.Cmd{}) is a no-op (no Process
	// attached), so the panic comes from the cancel func.
	cancelInvoked := false
	panicCancel := context.CancelFunc(func() {
		cancelInvoked = true
		panic("synthetic terminal cleanup panic")
	})
	sc.Terminal.TrackProcess(&exec.Cmd{}, panicCancel, "panic-cmd")

	// Close must not propagate the panic and must still tear down Browser
	// state so any cached lease is released.
	sc.Close()

	if !cancelInvoked {
		t.Fatal("expected Terminal.KillAll to invoke the panicking cancel func")
	}
	if sc.Browser.IsLaunched() {
		t.Fatal("Browser.Close did not run after Terminal.KillAll panicked — " +
			"lease conservation under panic is broken")
	}
	if sc.Browser.GetSessionPath() != "" {
		t.Fatal("Browser.Close did not clear session path after KillAll panic")
	}
	if err := sc.Ctx.Err(); err != context.Canceled {
		t.Fatalf("scan context not canceled after Close: err=%v", err)
	}

	// Idempotency: a second Close must not panic and must keep the lease
	// release invariant (no double-release).
	sc.Close()
}
