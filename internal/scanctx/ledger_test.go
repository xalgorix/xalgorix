package scanctx

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLedgerUpsertAssignsIDAndStatus(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "SQLI", Endpoint: "/api/users", Parameter: "id"})
	if h.ID == "" {
		t.Fatal("expected an assigned ID")
	}
	if h.Status != HypothesisQueued {
		t.Fatalf("expected default status queued, got %q", h.Status)
	}
	if h.VulnClass != "sqli" {
		t.Fatalf("expected vuln class lowercased to sqli, got %q", h.VulnClass)
	}
	if h.DedupKey == "" {
		t.Fatal("expected a derived dedup key")
	}
	if ls.Len() != 1 {
		t.Fatalf("expected 1 hypothesis, got %d", ls.Len())
	}
}

func TestLedgerUpsertDedupMergesBlanks(t *testing.T) {
	ls := NewLedgerStore()
	first := ls.Upsert(Hypothesis{VulnClass: "idor", Endpoint: "/api/orders", Parameter: "oid"})
	// Same identity, adds a title + baseline that were blank before.
	second := ls.Upsert(Hypothesis{
		VulnClass: "idor", Endpoint: "/api/orders", Parameter: "oid",
		Title:    "Order IDOR",
		Baseline: "own order returns 200",
	})
	if first.ID != second.ID {
		t.Fatalf("expected dedup to reuse ID %q, got %q", first.ID, second.ID)
	}
	if ls.Len() != 1 {
		t.Fatalf("expected 1 hypothesis after dedup, got %d", ls.Len())
	}
	got, _ := ls.Get(first.ID)
	if got.Title != "Order IDOR" || got.Baseline != "own order returns 200" {
		t.Fatalf("expected blank fields filled by merge, got title=%q baseline=%q", got.Title, got.Baseline)
	}
}

func TestLedgerEndpointNormalizationDedup(t *testing.T) {
	ls := NewLedgerStore()
	a := ls.Upsert(Hypothesis{VulnClass: "xss", Endpoint: "/Search/?q=1"})
	b := ls.Upsert(Hypothesis{VulnClass: "xss", Endpoint: "/search"})
	if a.ID != b.ID {
		t.Fatalf("expected /Search/?q=1 and /search to dedup to one hypothesis, got %q and %q", a.ID, b.ID)
	}
	if ls.Len() != 1 {
		t.Fatalf("expected 1 hypothesis, got %d", ls.Len())
	}
}

func TestLedgerAddEvidenceRaisesConfidence(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "ssrf", Endpoint: "/fetch", Confidence: 0.2})
	if !ls.AddEvidence(h.ID, Evidence{Kind: "probe", Summary: "internal 169.254 reachable", Confidence: 0.8}) {
		t.Fatal("AddEvidence returned false for existing hypothesis")
	}
	got, _ := ls.Get(h.ID)
	if len(got.Evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(got.Evidence))
	}
	if got.Evidence[0].ID == "" {
		t.Fatal("expected evidence to get an ID")
	}
	if got.Confidence != 0.8 {
		t.Fatalf("expected confidence raised to 0.8, got %v", got.Confidence)
	}
	// A weaker observation must not lower confidence.
	ls.AddEvidence(h.ID, Evidence{Kind: "probe", Summary: "weak signal", Confidence: 0.1})
	got, _ = ls.Get(h.ID)
	if got.Confidence != 0.8 {
		t.Fatalf("expected confidence to stay 0.8, got %v", got.Confidence)
	}
	if ls.AddEvidence("H-nope", Evidence{Summary: "x"}) {
		t.Fatal("expected AddEvidence to unknown hypothesis to return false")
	}
}

func TestLedgerSetStatusConfidenceEffects(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "rce", Endpoint: "/exec", Confidence: 0.5})

	ls.SetStatus(h.ID, HypothesisProven, "attach XALG finding")
	got, _ := ls.Get(h.ID)
	if got.Status != HypothesisProven || got.Confidence != 1.0 {
		t.Fatalf("proven should force confidence 1.0, got status=%q conf=%v", got.Status, got.Confidence)
	}
	if got.NextAction != "attach XALG finding" {
		t.Fatalf("expected next action recorded, got %q", got.NextAction)
	}

	h2 := ls.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/login", Confidence: 0.6})
	ls.SetStatus(h2.ID, HypothesisRejected, "")
	got2, _ := ls.Get(h2.ID)
	if got2.Status != HypothesisRejected || got2.Confidence != 0 {
		t.Fatalf("rejected should zero confidence, got status=%q conf=%v", got2.Status, got2.Confidence)
	}
}

func TestLedgerSetStatusNormalizesUnknown(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "xss", Endpoint: "/x"})
	if !ls.SetStatus(h.ID, HypothesisStatus("banana"), "") {
		t.Fatal("SetStatus returned false")
	}
	got, _ := ls.Get(h.ID)
	if got.Status != HypothesisQueued {
		t.Fatalf("expected unknown status normalized to queued, got %q", got.Status)
	}
}

func TestLedgerAssignMovesToTesting(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "idor", Endpoint: "/a"})
	if !ls.Assign(h.ID, "agent-2") {
		t.Fatal("Assign returned false")
	}
	got, _ := ls.Get(h.ID)
	if got.AssignedTo != "agent-2" || got.Status != HypothesisTesting {
		t.Fatalf("expected assigned+testing, got assigned=%q status=%q", got.AssignedTo, got.Status)
	}
}

func TestLedgerClaimNextIsAtomicAcrossSpecialists(t *testing.T) {
	ls := NewLedgerStore()
	const hypothesisCount = 24
	for i := 0; i < hypothesisCount; i++ {
		ls.Upsert(Hypothesis{
			VulnClass:  "sqli",
			Endpoint:   fmt.Sprintf("/endpoint/%d", i),
			Confidence: float64(i) / hypothesisCount,
		})
	}

	const contenderCount = 48
	start := make(chan struct{})
	claimed := make(chan Hypothesis, contenderCount)
	var wg sync.WaitGroup
	for i := 0; i < contenderCount; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			if h, ok := ls.ClaimNext("sqli", fmt.Sprintf("specialist-%d", n)); ok {
				claimed <- h
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(claimed)

	seen := make(map[string]bool)
	for h := range claimed {
		if seen[h.ID] {
			t.Fatalf("hypothesis %s was claimed by more than one specialist", h.ID)
		}
		seen[h.ID] = true
		if h.Status != HypothesisTesting || h.AssignedTo == "" {
			t.Fatalf("claim %s was not persisted as owned testing work: %+v", h.ID, h)
		}
	}
	if len(seen) != hypothesisCount {
		t.Fatalf("expected exactly %d unique claims, got %d", hypothesisCount, len(seen))
	}
}

func TestLedgerSchedulableOrdering(t *testing.T) {
	ls := NewLedgerStore()
	ls.Upsert(Hypothesis{VulnClass: "a", Endpoint: "/1", Confidence: 0.3})
	high := ls.Upsert(Hypothesis{VulnClass: "b", Endpoint: "/2", Confidence: 0.9})
	blocked := ls.Upsert(Hypothesis{VulnClass: "c", Endpoint: "/3", Confidence: 0.9})
	ls.SetStatus(blocked.ID, HypothesisBlocked, "")
	proven := ls.Upsert(Hypothesis{VulnClass: "d", Endpoint: "/4", Confidence: 0.95})
	ls.SetStatus(proven.ID, HypothesisProven, "")

	sched := ls.Schedulable(0)
	// proven is excluded; three remain.
	if len(sched) != 3 {
		t.Fatalf("expected 3 schedulable, got %d", len(sched))
	}
	// Highest confidence first; queued before blocked on tie.
	if sched[0].ID != high.ID {
		t.Fatalf("expected highest-confidence queued first (%s), got %s", high.ID, sched[0].ID)
	}
	if sched[1].ID != blocked.ID {
		t.Fatalf("expected blocked (conf 0.9) second, got %s", sched[1].ID)
	}
	// Limit is respected.
	if len(ls.Schedulable(1)) != 1 {
		t.Fatal("expected Schedulable(1) to return 1")
	}
}

func TestLedgerEvidenceBounding(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/b"})
	// One finding ref that must survive eviction.
	ls.AddEvidence(h.ID, Evidence{Kind: EvidenceFindingRef, FindingID: "XALG-1", Summary: "confirmed"})
	for i := 0; i < maxEvidencePerHypothesis+20; i++ {
		ls.AddEvidence(h.ID, Evidence{Kind: "probe", Summary: fmt.Sprintf("probe %d", i)})
	}
	got, _ := ls.Get(h.ID)
	if len(got.Evidence) > maxEvidencePerHypothesis {
		t.Fatalf("expected evidence capped at %d, got %d", maxEvidencePerHypothesis, len(got.Evidence))
	}
	foundFinding := false
	for _, ev := range got.Evidence {
		if ev.Kind == EvidenceFindingRef && ev.FindingID == "XALG-1" {
			foundFinding = true
		}
	}
	if !foundFinding {
		t.Fatal("expected finding_ref evidence to be retained after eviction")
	}
}

func TestLedgerEvidenceStringTruncation(t *testing.T) {
	ls := NewLedgerStore()
	h := ls.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/c"})
	big := strings.Repeat("A", maxEvidenceStringLen+1000)
	ls.AddEvidence(h.ID, Evidence{Kind: "exploit", Summary: "x", Response: big})
	got, _ := ls.Get(h.ID)
	if len(got.Evidence[0].Response) > maxEvidenceStringLen+len("…(truncated)") {
		t.Fatalf("expected response truncated near %d, got %d", maxEvidenceStringLen, len(got.Evidence[0].Response))
	}
}

func TestLedgerPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ls := NewLedgerStore()
	ls.SetPersistPath(dir)
	h := ls.Upsert(Hypothesis{VulnClass: "ssrf", Endpoint: "/fetch", Parameter: "url", Confidence: 0.7})
	ls.AddEvidence(h.ID, Evidence{Kind: "exploit", Summary: "hit metadata", FindingID: "XALG-2"})
	ls.SetStatus(h.ID, HypothesisProven, "report it")

	// Confirm the file exists.
	if _, err := filepathGlobFirst(filepath.Join(dir, "ledger.json")); err != nil {
		t.Fatalf("expected ledger.json written: %v", err)
	}

	// Fresh store loads the same data.
	ls2 := NewLedgerStore()
	ls2.SetPersistPath(dir)
	n := ls2.LoadFromDisk()
	if n != 1 {
		t.Fatalf("expected to load 1 hypothesis, got %d", n)
	}
	got, ok := ls2.Get(h.ID)
	if !ok {
		t.Fatalf("expected hypothesis %s after load", h.ID)
	}
	if got.Status != HypothesisProven || got.Confidence != 1.0 {
		t.Fatalf("expected proven+1.0 after load, got status=%q conf=%v", got.Status, got.Confidence)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].FindingID != "XALG-2" {
		t.Fatalf("expected evidence with finding XALG-2 after load, got %+v", got.Evidence)
	}
	// New upserts on the loaded store must not collide IDs with loaded ones.
	h2 := ls2.Upsert(Hypothesis{VulnClass: "xss", Endpoint: "/new"})
	if h2.ID == h.ID {
		t.Fatalf("expected a fresh ID distinct from loaded %s, got %s", h.ID, h2.ID)
	}
}

func TestLedgerLoadDoesNotClobberLiveState(t *testing.T) {
	dir := t.TempDir()
	// Persist a proven hypothesis to disk.
	disk := NewLedgerStore()
	disk.SetPersistPath(dir)
	dh := disk.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/login", Parameter: "u"})
	disk.SetStatus(dh.ID, HypothesisProven, "")

	// A live store already has the SAME identity in "testing" — load must not
	// overwrite it back to proven-from-disk (live wins).
	live := NewLedgerStore()
	live.SetPersistPath(dir)
	lh := live.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/login", Parameter: "u"})
	live.Assign(lh.ID, "agent-1")
	live.LoadFromDisk()

	got, _ := live.Get(lh.ID)
	if got.Status != HypothesisTesting {
		t.Fatalf("expected live testing state preserved, got %q", got.Status)
	}
	if live.Len() != 1 {
		t.Fatalf("expected dedup to keep a single hypothesis, got %d", live.Len())
	}
}

func TestLedgerMergeChildIntoParent(t *testing.T) {
	parent := NewLedgerStore()
	child := NewLedgerStore()

	// Shared identity: child has stronger status + extra evidence.
	shared := parent.Upsert(Hypothesis{VulnClass: "idor", Endpoint: "/api/orders", Parameter: "id"})
	_ = shared
	cShared := child.Upsert(Hypothesis{VulnClass: "idor", Endpoint: "/api/orders", Parameter: "id", Confidence: 0.9})
	child.AddEvidence(cShared.ID, Evidence{Kind: "exploit", Summary: "cross-user read", FindingID: "XALG-5"})
	child.SetStatus(cShared.ID, HypothesisProven, "")

	// Child-only hypothesis.
	child.Upsert(Hypothesis{VulnClass: "ssrf", Endpoint: "/img"})

	merged := parent.Merge(child)
	if merged != 2 {
		t.Fatalf("expected 2 merged, got %d", merged)
	}
	if parent.Len() != 2 {
		t.Fatalf("expected parent to hold 2 hypotheses, got %d", parent.Len())
	}
	// The shared one should now be proven with the child's evidence.
	got, _ := parent.Get(shared.ID)
	if got.Status != HypothesisProven {
		t.Fatalf("expected merged status proven, got %q", got.Status)
	}
	foundEv := false
	for _, ev := range got.Evidence {
		if ev.FindingID == "XALG-5" {
			foundEv = true
		}
	}
	if !foundEv {
		t.Fatal("expected child evidence merged into parent")
	}
}

func TestLedgerFormatForContext(t *testing.T) {
	ls := NewLedgerStore()
	if ls.FormatForContext() != "" {
		t.Fatal("expected empty format for empty ledger")
	}
	h := ls.Upsert(Hypothesis{VulnClass: "sqli", Endpoint: "/login", Parameter: "u", NextAction: "try boolean blind"})
	out := ls.FormatForContext()
	if !strings.Contains(out, "HYPOTHESIS LEDGER") || !strings.Contains(out, h.ID) {
		t.Fatalf("expected rendered ledger to contain header and ID, got:\n%s", out)
	}
	if !strings.Contains(out, "try boolean blind") {
		t.Fatalf("expected next action in render, got:\n%s", out)
	}
}

func TestLedgerConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	ls := NewLedgerStore()
	ls.SetPersistPath(dir)

	const workers = 16
	const per = 25
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				h := ls.Upsert(Hypothesis{
					VulnClass: fmt.Sprintf("class-%d", w),
					Endpoint:  fmt.Sprintf("/e/%d/%d", w, i),
				})
				ls.AddEvidence(h.ID, Evidence{Kind: "probe", Summary: "x", Confidence: 0.5})
				ls.SetStatus(h.ID, HypothesisTesting, "next")
				_ = ls.All()
				_ = ls.FormatForContext()
				_ = ls.Schedulable(5)
				_ = ls.Counts()
			}
		}(w)
	}
	wg.Wait()

	if ls.Len() != workers*per {
		t.Fatalf("expected %d hypotheses, got %d", workers*per, ls.Len())
	}
	// Reload from disk into a fresh store to confirm persistence survived the
	// concurrent writes (count may lag by in-flight writes, but must be > 0
	// and never exceed the total).
	ls2 := NewLedgerStore()
	ls2.SetPersistPath(dir)
	loaded := ls2.LoadFromDisk()
	if loaded <= 0 || loaded > workers*per {
		t.Fatalf("expected 1..%d loaded from disk, got %d", workers*per, loaded)
	}
}

// filepathGlobFirst is a tiny helper: returns nil if the exact path exists.
func filepathGlobFirst(path string) (string, error) {
	matches, err := filepath.Glob(path)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no file at %s", path)
	}
	return matches[0], nil
}
