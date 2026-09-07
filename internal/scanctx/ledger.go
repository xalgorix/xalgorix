package scanctx

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// HypothesisStatus is the lifecycle state of an attack hypothesis in the
// ledger. It is a strict superset of the in-memory planner TaskStatus, adding
// the states an evidence-driven scheduler needs to reason about what is worth
// spending budget on next.
type HypothesisStatus string

const (
	// HypothesisQueued means the hypothesis has been identified from recon but
	// not yet investigated. Queued hypotheses are the primary schedulable pool.
	HypothesisQueued HypothesisStatus = "queued"
	// HypothesisTesting means a specialist is actively probing it right now.
	HypothesisTesting HypothesisStatus = "testing"
	// HypothesisProven means it was exploited with concrete, reproducible
	// evidence (typically linked to a reported finding by ID).
	HypothesisProven HypothesisStatus = "proven"
	// HypothesisRejected means it was investigated and disproven / not
	// exploitable (a control/baseline showed the behavior is intended).
	HypothesisRejected HypothesisStatus = "rejected"
	// HypothesisBlocked means it needs a precondition (e.g. credentials, a
	// reachable endpoint, a prior chain step) that is not yet satisfied.
	HypothesisBlocked HypothesisStatus = "blocked"
	// HypothesisExhausted means the attempt/budget was spent without proof;
	// kept so the scheduler does not re-open it indefinitely.
	HypothesisExhausted HypothesisStatus = "exhausted"
)

// validHypothesisStatuses gates external (tool/LLM-supplied) status values so a
// malformed update cannot corrupt scheduling.
var validHypothesisStatuses = map[HypothesisStatus]bool{
	HypothesisQueued:    true,
	HypothesisTesting:   true,
	HypothesisProven:    true,
	HypothesisRejected:  true,
	HypothesisBlocked:   true,
	HypothesisExhausted: true,
}

// NormalizeHypothesisStatus maps a free-form string to a known status, falling
// back to queued for anything unrecognized so scheduling never sees garbage.
func NormalizeHypothesisStatus(s string) HypothesisStatus {
	st := HypothesisStatus(strings.ToLower(strings.TrimSpace(s)))
	if validHypothesisStatuses[st] {
		return st
	}
	return HypothesisQueued
}

// Terminal reports whether a status is a settled outcome that the scheduler
// should not normally re-open (proven/rejected/exhausted).
func (s HypothesisStatus) Terminal() bool {
	return s == HypothesisProven || s == HypothesisRejected || s == HypothesisExhausted
}

const (
	maxEvidencePerHypothesis = 40   // keep memory/disk bounded (DoD)
	maxEvidenceStringLen     = 4096 // request/response fields
	maxSummaryLen            = 2048
	maxHypothesisFieldLen    = 512

	// EvidenceFindingRef marks evidence that references a confirmed, reported
	// finding by its reporting ID (e.g. XALG-3). This kind is never evicted by
	// the per-hypothesis evidence cap.
	EvidenceFindingRef = "finding_ref"
)

// Evidence is a single append-only observation attached to a hypothesis.
// Specialists accumulate observations (baselines, probes, exploit attempts,
// artifacts); confirmed findings are referenced by the authoritative reporting
// ID rather than duplicating the full proof payload here.
type Evidence struct {
	ID string `json:"id"`
	// Kind is a coarse category: "baseline"/"control", "probe", "exploit",
	// "artifact", or EvidenceFindingRef. Free-form but lower-cased on store.
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	// Request/Response are optional raw control/PoC evidence, bounded in size.
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	// FindingID links this evidence to a reported reporting.Vulnerability
	// (e.g. "XALG-3") when Kind == EvidenceFindingRef.
	FindingID string `json:"finding_id,omitempty"`
	// AgentID records which agent (coordinator or a specialist delegation ID)
	// contributed the evidence.
	AgentID string `json:"agent_id,omitempty"`
	// Confidence is the quality of THIS observation in [0,1].
	Confidence float64   `json:"confidence,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Hypothesis is one attack hypothesis: a (vulnerability class × target surface)
// claim with its lifecycle status, accumulated evidence, and scheduling
// metadata. It is the durable, scan-shared unit that drives specialist
// scheduling — a superset of the in-memory planner Task.
type Hypothesis struct {
	ID       string `json:"id"`
	DedupKey string `json:"dedup_key"`
	Title    string `json:"title"`

	// Identity — what and where.
	VulnClass string `json:"vuln_class"`
	Target    string `json:"target,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Parameter string `json:"parameter,omitempty"`
	// Role is the auth context this hypothesis applies to (anonymous, user,
	// admin, or a named role) — central to authorization/IDOR testing.
	Role string `json:"role,omitempty"`
	// DataFlow captures a source->sink path for whitebox/source-driven work.
	DataFlow string `json:"data_flow,omitempty"`

	// Preconditions / privileges required before this is testable.
	Preconditions     []string `json:"preconditions,omitempty"`
	RequiredPrivilege string   `json:"required_privilege,omitempty"`
	// Baseline is the control/negative result used to distinguish a real
	// vulnerability from intended behavior.
	Baseline string `json:"baseline,omitempty"`

	Status HypothesisStatus `json:"status"`
	// Confidence is the current belief (in [0,1]) that this is exploitable.
	Confidence float64 `json:"confidence"`
	// AssignedTo is the delegation/agent ID that currently owns the work.
	AssignedTo string `json:"assigned_to,omitempty"`
	// NextAction is the next-best concrete step for whoever picks this up.
	NextAction string `json:"next_action,omitempty"`
	// Attempts counts exploit attempts spent (for exhaustion/economics).
	Attempts int `json:"attempts"`

	Evidence []Evidence `json:"evidence,omitempty"`

	// Origin records who created it: "recon", "auto", "llm", or a specialist.
	Origin    string    `json:"origin,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// clone returns a deep copy so callers cannot mutate stored state without going
// through the store's locked methods.
func (h *Hypothesis) clone() Hypothesis {
	cp := *h
	if h.Preconditions != nil {
		cp.Preconditions = append([]string(nil), h.Preconditions...)
	}
	if h.Evidence != nil {
		cp.Evidence = append([]Evidence(nil), h.Evidence...)
	}
	return cp
}

// LedgerStore is the durable, concurrency-safe hypothesis/evidence graph for a
// single scan. It is shared by the coordinator and every specialist (they hold
// the same *ScanContext), persists to <scanDir>/ledger.json via atomic writes,
// and survives process restart/resume.
//
// It mirrors NoteStore's locking discipline: mutations serialize on mu, the
// on-disk snapshot is marshaled under mu, and the actual file write happens
// outside mu (serialized by writeMu) so disk I/O never blocks readers.
type LedgerStore struct {
	mu      sync.RWMutex
	hyps    map[string]*Hypothesis
	order   []string          // insertion order for stable rendering
	byDedup map[string]string // dedupKey -> hypothesis ID
	seq     int               // hypothesis ID sequence
	evSeq   int               // evidence ID sequence

	persistPath string

	// writeMu serializes disk writes only; see NoteStore for rationale.
	writeMu sync.Mutex
}

// NewLedgerStore creates an empty ledger with no persistence configured.
func NewLedgerStore() *LedgerStore {
	return &LedgerStore{
		hyps:    make(map[string]*Hypothesis),
		byDedup: make(map[string]string),
	}
}

// SetPersistPath configures disk persistence. An empty dir disables it.
//
// Path policy mirrors NoteStore: the path is dir + "/ledger.json" with no
// user-supplied component, and in production dir is the per-scan ScanDir (an
// Allow_List descendant by construction), so no sandbox.CheckResolve is needed
// here (and cannot be called — sandbox imports scanctx).
func (ls *LedgerStore) SetPersistPath(dir string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if dir != "" {
		ls.persistPath = filepath.Join(dir, "ledger.json")
	} else {
		ls.persistPath = ""
	}
}

// Upsert inserts a new hypothesis or merges into an existing one that shares
// the same dedup key. It returns a copy of the stored hypothesis.
//
// Dedup: if in.DedupKey is empty it is derived from (VulnClass, Endpoint,
// Parameter, Role). Non-empty scalar fields on `in` overwrite blanks on the
// existing record; identity fields are never blanked once set. Status and
// Confidence are only advanced by the dedicated methods, so Upsert does not
// silently regress a proven hypothesis back to queued.
func (ls *LedgerStore) Upsert(in Hypothesis) Hypothesis {
	now := time.Now().UTC()
	in.sanitize()
	key := in.DedupKey
	if key == "" {
		key = dedupKey(in.VulnClass, in.Endpoint, in.Parameter, in.Role)
	}

	ls.mu.Lock()
	var stored *Hypothesis
	if id, ok := ls.byDedup[key]; ok {
		if existing := ls.hyps[id]; existing != nil {
			existing.mergeFrom(in)
			existing.UpdatedAt = now
			stored = existing
		}
	}
	if stored == nil {
		ls.seq++
		id := fmt.Sprintf("H-%d", ls.seq)
		h := in
		h.ID = id
		h.DedupKey = key
		if h.Status == "" {
			h.Status = HypothesisQueued
		}
		if h.CreatedAt.IsZero() {
			h.CreatedAt = now
		}
		h.UpdatedAt = now
		ls.hyps[id] = &h
		ls.order = append(ls.order, id)
		ls.byDedup[key] = id
		stored = &h
	}
	out := stored.clone()
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return out
}

// AddEvidence appends an observation to a hypothesis and lightly nudges the
// hypothesis's confidence toward the evidence's own confidence. Returns false
// if the hypothesis does not exist.
func (ls *LedgerStore) AddEvidence(hypID string, ev Evidence) bool {
	now := time.Now().UTC()
	ev.sanitize()
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = now
	}

	ls.mu.Lock()
	h := ls.hyps[hypID]
	if h == nil {
		ls.mu.Unlock()
		return false
	}
	ls.evSeq++
	ev.ID = fmt.Sprintf("EV-%d", ls.evSeq)
	h.Evidence = append(h.Evidence, ev)
	capEvidence(h)
	// Evidence quality raises belief but never lowers it here; rejection is an
	// explicit status transition, not a side effect of adding an observation.
	if ev.Confidence > h.Confidence {
		h.Confidence = clampConfidence(ev.Confidence)
	}
	h.UpdatedAt = now
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return true
}

// SetStatus transitions a hypothesis's lifecycle state and optionally records
// the next-best action. Returns false if the hypothesis does not exist.
func (ls *LedgerStore) SetStatus(hypID string, status HypothesisStatus, nextAction string) bool {
	if !validHypothesisStatuses[status] {
		status = NormalizeHypothesisStatus(string(status))
	}
	now := time.Now().UTC()

	ls.mu.Lock()
	h := ls.hyps[hypID]
	if h == nil {
		ls.mu.Unlock()
		return false
	}
	h.Status = status
	if strings.TrimSpace(nextAction) != "" {
		h.NextAction = truncate(nextAction, maxSummaryLen)
	}
	if status == HypothesisProven && h.Confidence < 1.0 {
		h.Confidence = 1.0
	}
	if status == HypothesisRejected {
		h.Confidence = 0
	}
	h.UpdatedAt = now
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return true
}

// Assign records the owning agent/delegation ID and moves a queued hypothesis
// into "testing". Returns false if the hypothesis does not exist.
func (ls *LedgerStore) Assign(hypID, agentID string) bool {
	now := time.Now().UTC()
	ls.mu.Lock()
	h := ls.hyps[hypID]
	if h == nil {
		ls.mu.Unlock()
		return false
	}
	h.AssignedTo = truncate(strings.TrimSpace(agentID), maxHypothesisFieldLen)
	if h.Status == HypothesisQueued {
		h.Status = HypothesisTesting
	}
	h.UpdatedAt = now
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return true
}

// ClaimNext atomically selects the highest-confidence queued hypothesis that
// matches vulnClass, assigns it to agentID, and moves it to testing. Selection
// and assignment happen under one lock so concurrent specialists cannot both
// observe the same queued item and overwrite one another's ownership.
// An empty vulnClass matches every class.
func (ls *LedgerStore) ClaimNext(vulnClass, agentID string) (Hypothesis, bool) {
	classFilter := strings.ToLower(strings.TrimSpace(vulnClass))
	owner := truncate(strings.TrimSpace(agentID), maxHypothesisFieldLen)
	now := time.Now().UTC()

	ls.mu.Lock()
	var picked *Hypothesis
	for _, id := range ls.order {
		h := ls.hyps[id]
		if h == nil || h.Status != HypothesisQueued {
			continue
		}
		if classFilter != "" && h.VulnClass != classFilter {
			continue
		}
		// Strictly greater replaces the candidate; equal confidence keeps the
		// earlier insertion, matching Schedulable's stable ordering.
		if picked == nil || h.Confidence > picked.Confidence {
			picked = h
		}
	}
	if picked == nil {
		ls.mu.Unlock()
		return Hypothesis{}, false
	}
	picked.AssignedTo = owner
	picked.Status = HypothesisTesting
	picked.UpdatedAt = now
	out := picked.clone()
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return out, true
}

// RecordAttempt increments the exploit-attempt counter (economics/exhaustion).
func (ls *LedgerStore) RecordAttempt(hypID string) bool {
	ls.mu.Lock()
	h := ls.hyps[hypID]
	if h == nil {
		ls.mu.Unlock()
		return false
	}
	h.Attempts++
	h.UpdatedAt = time.Now().UTC()
	data, path := ls.marshalLocked()
	ls.mu.Unlock()

	ls.writeFile(data, path)
	return true
}

// Get returns a copy of a hypothesis by ID.
func (ls *LedgerStore) Get(id string) (Hypothesis, bool) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	h, ok := ls.hyps[id]
	if !ok {
		return Hypothesis{}, false
	}
	return h.clone(), true
}

// All returns copies of every hypothesis in insertion order.
func (ls *LedgerStore) All() []Hypothesis {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	out := make([]Hypothesis, 0, len(ls.order))
	for _, id := range ls.order {
		if h := ls.hyps[id]; h != nil {
			out = append(out, h.clone())
		}
	}
	return out
}

// Schedulable returns the non-terminal hypotheses that are candidates for a
// specialist to pick up (queued or blocked), highest-confidence first, then by
// insertion order. "testing" is excluded because it is already owned.
func (ls *LedgerStore) Schedulable(limit int) []Hypothesis {
	ls.mu.RLock()
	cands := make([]Hypothesis, 0, len(ls.order))
	for _, id := range ls.order {
		h := ls.hyps[id]
		if h == nil {
			continue
		}
		if h.Status == HypothesisQueued || h.Status == HypothesisBlocked {
			cands = append(cands, h.clone())
		}
	}
	ls.mu.RUnlock()

	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].Confidence != cands[j].Confidence {
			return cands[i].Confidence > cands[j].Confidence
		}
		// Queued before blocked when confidence ties (blocked needs a
		// precondition that may not be met yet).
		if cands[i].Status != cands[j].Status {
			return cands[i].Status == HypothesisQueued
		}
		return false
	})
	if limit > 0 && len(cands) > limit {
		cands = cands[:limit]
	}
	return cands
}

// Counts returns the number of hypotheses in each status.
func (ls *LedgerStore) Counts() map[HypothesisStatus]int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	out := make(map[HypothesisStatus]int)
	for _, id := range ls.order {
		if h := ls.hyps[id]; h != nil {
			out[h.Status]++
		}
	}
	return out
}

// Len returns the number of hypotheses.
func (ls *LedgerStore) Len() int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return len(ls.hyps)
}

// Reset clears all hypotheses (used when a scan is explicitly reset).
func (ls *LedgerStore) Reset() {
	ls.mu.Lock()
	ls.hyps = make(map[string]*Hypothesis)
	ls.byDedup = make(map[string]string)
	ls.order = nil
	ls.seq = 0
	ls.evSeq = 0
	data, path := ls.marshalLocked()
	ls.mu.Unlock()
	ls.writeFile(data, path)
}

// Merge folds another ledger's hypotheses into this one (child -> parent
// rollup), deduplicating by dedup key. Evidence from the source is appended to
// the matching parent hypothesis; new hypotheses are inserted. Returns the
// number of source hypotheses that resulted in an insert or an evidence merge.
// Mirrors reporting.MergeVulnsToContext for the ledger.
func (ls *LedgerStore) Merge(other *LedgerStore) int {
	if other == nil || other == ls {
		return 0
	}
	src := other.All()
	merged := 0
	for _, s := range src {
		key := s.DedupKey
		if key == "" {
			key = dedupKey(s.VulnClass, s.Endpoint, s.Parameter, s.Role)
		}
		ls.mu.Lock()
		if id, ok := ls.byDedup[key]; ok && ls.hyps[id] != nil {
			dst := ls.hyps[id]
			dst.mergeFrom(s)
			// Advance status toward the more-settled/proven of the two.
			if statusRank(s.Status) > statusRank(dst.Status) {
				dst.Status = s.Status
			}
			if s.Confidence > dst.Confidence {
				dst.Confidence = s.Confidence
			}
			for _, ev := range s.Evidence {
				ls.evSeq++
				ev.ID = fmt.Sprintf("EV-%d", ls.evSeq)
				dst.Evidence = append(dst.Evidence, ev)
			}
			capEvidence(dst)
			dst.UpdatedAt = time.Now().UTC()
		} else {
			ls.seq++
			id := fmt.Sprintf("H-%d", ls.seq)
			h := s
			h.ID = id
			h.DedupKey = key
			// Re-ID evidence into this store's sequence.
			for i := range h.Evidence {
				ls.evSeq++
				h.Evidence[i].ID = fmt.Sprintf("EV-%d", ls.evSeq)
			}
			ls.hyps[id] = &h
			ls.order = append(ls.order, id)
			ls.byDedup[key] = id
		}
		merged++
		ls.mu.Unlock()
	}
	ls.mu.Lock()
	data, path := ls.marshalLocked()
	ls.mu.Unlock()
	ls.writeFile(data, path)
	return merged
}

// FormatForContext renders a compact, LLM-friendly view of the open work and
// proven findings for injection into agent context. Empty when the ledger is
// empty.
func (ls *LedgerStore) FormatForContext() string {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	if len(ls.order) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("=== HYPOTHESIS LEDGER (shared, durable) ===\n")
	counts := map[HypothesisStatus]int{}
	for _, id := range ls.order {
		if h := ls.hyps[id]; h != nil {
			counts[h.Status]++
		}
	}
	b.WriteString(fmt.Sprintf("queued=%d testing=%d proven=%d rejected=%d blocked=%d exhausted=%d\n",
		counts[HypothesisQueued], counts[HypothesisTesting], counts[HypothesisProven],
		counts[HypothesisRejected], counts[HypothesisBlocked], counts[HypothesisExhausted]))
	shown := 0
	for _, id := range ls.order {
		h := ls.hyps[id]
		if h == nil || h.Status == HypothesisRejected || h.Status == HypothesisExhausted {
			continue
		}
		if shown >= 25 {
			b.WriteString("… (more hypotheses; use read_ledger for the full list)\n")
			break
		}
		loc := h.Endpoint
		if h.Parameter != "" {
			loc += " [" + h.Parameter + "]"
		}
		if h.Role != "" {
			loc += " as " + h.Role
		}
		b.WriteString(fmt.Sprintf("• %s [%s] %s conf=%.2f %s", h.ID, h.Status, h.VulnClass, h.Confidence, strings.TrimSpace(loc)))
		if h.NextAction != "" {
			b.WriteString(" → " + h.NextAction)
		}
		b.WriteString("\n")
		shown++
	}
	b.WriteString("=== END LEDGER ===")
	return b.String()
}

// LoadFromDisk merges a persisted ledger into this (empty or partial) store.
// Existing in-memory hypotheses (by dedup key) are preserved; only unseen
// hypotheses from disk are inserted, so a resume never clobbers live state.
// Returns the number of hypotheses loaded.
func (ls *LedgerStore) LoadFromDisk() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if ls.persistPath == "" {
		return 0
	}
	data, err := os.ReadFile(ls.persistPath)
	if err != nil {
		return 0
	}
	var snap ledgerSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		log.Printf("[ledger] Warning: failed to parse %s: %v", ls.persistPath, err)
		return 0
	}
	count := 0
	for _, h := range snap.Hypotheses {
		if h == nil {
			continue
		}
		key := h.DedupKey
		if key == "" {
			key = dedupKey(h.VulnClass, h.Endpoint, h.Parameter, h.Role)
			h.DedupKey = key
		}
		if _, exists := ls.byDedup[key]; exists {
			continue // do not clobber live state
		}
		if h.ID == "" {
			ls.seq++
			h.ID = fmt.Sprintf("H-%d", ls.seq)
		}
		ls.hyps[h.ID] = h
		ls.order = append(ls.order, h.ID)
		ls.byDedup[key] = h.ID
		count++
	}
	// Advance sequences past anything loaded so new IDs never collide.
	if snap.Seq > ls.seq {
		ls.seq = snap.Seq
	}
	if snap.EvSeq > ls.evSeq {
		ls.evSeq = snap.EvSeq
	}
	if count > 0 {
		log.Printf("[ledger] Loaded %d hypotheses from: %s", count, ls.persistPath)
	}
	return count
}

// ledgerSnapshot is the on-disk JSON shape.
type ledgerSnapshot struct {
	Seq        int           `json:"seq"`
	EvSeq      int           `json:"ev_seq"`
	Order      []string      `json:"order"`
	Hypotheses []*Hypothesis `json:"hypotheses"`
}

// marshalLocked serializes the store. Must be called with ls.mu held. Returns
// (nil, "") when persistence is disabled.
func (ls *LedgerStore) marshalLocked() ([]byte, string) {
	if ls.persistPath == "" {
		return nil, ""
	}
	snap := ledgerSnapshot{
		Seq:   ls.seq,
		EvSeq: ls.evSeq,
		Order: append([]string(nil), ls.order...),
	}
	for _, id := range ls.order {
		if h := ls.hyps[id]; h != nil {
			snap.Hypotheses = append(snap.Hypotheses, h)
		}
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		log.Printf("[ledger] Warning: failed to marshal ledger: %v", err)
		return nil, ""
	}
	return data, ls.persistPath
}

// writeFile persists serialized data atomically. Safe to call without holding
// mu; writeMu serializes concurrent writers. Uses storage.WriteAtomic so a
// crash mid-write can never leave a torn ledger.json.
func (ls *LedgerStore) writeFile(data []byte, path string) {
	if data == nil || path == "" {
		return
	}
	ls.writeMu.Lock()
	defer ls.writeMu.Unlock()
	if err := storage.WriteAtomic(path, data); err != nil {
		log.Printf("[ledger] Warning: failed to save ledger to %s: %v", path, err)
	}
}

// --- helpers ---

// statusRank orders statuses by "settledness" for merge conflict resolution:
// proven wins over everything; otherwise more-progressed states win.
func statusRank(s HypothesisStatus) int {
	switch s {
	case HypothesisProven:
		return 5
	case HypothesisTesting:
		return 3
	case HypothesisBlocked:
		return 2
	case HypothesisExhausted:
		return 2
	case HypothesisRejected:
		return 1
	case HypothesisQueued:
		return 0
	default:
		return 0
	}
}

// mergeFrom copies non-empty scalar identity/metadata fields from src into h
// without blanking existing values. It does not touch ID, DedupKey, status,
// confidence, attempts, or timestamps (those are managed by the store).
func (h *Hypothesis) mergeFrom(src Hypothesis) {
	if h.Title == "" && src.Title != "" {
		h.Title = src.Title
	}
	if h.VulnClass == "" && src.VulnClass != "" {
		h.VulnClass = src.VulnClass
	}
	if h.Target == "" && src.Target != "" {
		h.Target = src.Target
	}
	if h.Endpoint == "" && src.Endpoint != "" {
		h.Endpoint = src.Endpoint
	}
	if h.Parameter == "" && src.Parameter != "" {
		h.Parameter = src.Parameter
	}
	if h.Role == "" && src.Role != "" {
		h.Role = src.Role
	}
	if h.DataFlow == "" && src.DataFlow != "" {
		h.DataFlow = src.DataFlow
	}
	if h.RequiredPrivilege == "" && src.RequiredPrivilege != "" {
		h.RequiredPrivilege = src.RequiredPrivilege
	}
	if h.Baseline == "" && src.Baseline != "" {
		h.Baseline = src.Baseline
	}
	if src.NextAction != "" {
		h.NextAction = src.NextAction
	}
	if len(src.Preconditions) > 0 {
		h.Preconditions = mergeStringSet(h.Preconditions, src.Preconditions)
	}
	if h.Origin == "" && src.Origin != "" {
		h.Origin = src.Origin
	}
}

// sanitize bounds and normalizes external hypothesis input.
func (h *Hypothesis) sanitize() {
	h.Title = truncate(strings.TrimSpace(h.Title), maxSummaryLen)
	h.VulnClass = strings.ToLower(truncate(strings.TrimSpace(h.VulnClass), maxHypothesisFieldLen))
	h.Target = truncate(strings.TrimSpace(h.Target), maxHypothesisFieldLen)
	h.Endpoint = truncate(strings.TrimSpace(h.Endpoint), maxHypothesisFieldLen)
	h.Parameter = truncate(strings.TrimSpace(h.Parameter), maxHypothesisFieldLen)
	h.Role = truncate(strings.TrimSpace(h.Role), maxHypothesisFieldLen)
	h.DataFlow = truncate(strings.TrimSpace(h.DataFlow), maxSummaryLen)
	h.RequiredPrivilege = truncate(strings.TrimSpace(h.RequiredPrivilege), maxHypothesisFieldLen)
	h.Baseline = truncate(strings.TrimSpace(h.Baseline), maxSummaryLen)
	h.NextAction = truncate(strings.TrimSpace(h.NextAction), maxSummaryLen)
	h.Origin = truncate(strings.TrimSpace(h.Origin), maxHypothesisFieldLen)
	h.Confidence = clampConfidence(h.Confidence)
	if h.Status != "" {
		h.Status = NormalizeHypothesisStatus(string(h.Status))
	}
	if len(h.Preconditions) > 0 {
		cleaned := make([]string, 0, len(h.Preconditions))
		for _, p := range h.Preconditions {
			if p = truncate(strings.TrimSpace(p), maxHypothesisFieldLen); p != "" {
				cleaned = append(cleaned, p)
			}
		}
		h.Preconditions = cleaned
	}
}

func (ev *Evidence) sanitize() {
	ev.Kind = strings.ToLower(truncate(strings.TrimSpace(ev.Kind), maxHypothesisFieldLen))
	if ev.Kind == "" {
		ev.Kind = "probe"
	}
	ev.Summary = truncate(strings.TrimSpace(ev.Summary), maxSummaryLen)
	ev.Request = truncate(ev.Request, maxEvidenceStringLen)
	ev.Response = truncate(ev.Response, maxEvidenceStringLen)
	ev.FindingID = truncate(strings.TrimSpace(ev.FindingID), maxHypothesisFieldLen)
	ev.AgentID = truncate(strings.TrimSpace(ev.AgentID), maxHypothesisFieldLen)
	ev.Confidence = clampConfidence(ev.Confidence)
}

// capEvidence bounds evidence per hypothesis, evicting the oldest non-finding
// observations first so confirmed-finding references are always retained.
func capEvidence(h *Hypothesis) {
	if len(h.Evidence) <= maxEvidencePerHypothesis {
		return
	}
	over := len(h.Evidence) - maxEvidencePerHypothesis
	kept := make([]Evidence, 0, maxEvidencePerHypothesis)
	// First pass: drop oldest non-finding evidence.
	for _, ev := range h.Evidence {
		if over > 0 && ev.Kind != EvidenceFindingRef {
			over--
			continue
		}
		kept = append(kept, ev)
	}
	// If still over (all remaining were finding refs), trim oldest.
	if len(kept) > maxEvidencePerHypothesis {
		kept = kept[len(kept)-maxEvidencePerHypothesis:]
	}
	h.Evidence = kept
}

// dedupKey builds a normalized identity for a hypothesis.
func dedupKey(vulnClass, endpoint, parameter, role string) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(vulnClass)),
		normalizeEndpoint(endpoint),
		strings.ToLower(strings.TrimSpace(parameter)),
		strings.ToLower(strings.TrimSpace(role)),
	}, "|")
}

// normalizeEndpoint lowercases, drops the query/fragment, and trims a trailing
// slash so "/a/?x=1" and "/A/" collapse to the same key.
func normalizeEndpoint(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	if i := strings.IndexAny(e, "?#"); i >= 0 {
		e = e[:i]
	}
	e = strings.ToLower(e)
	if len(e) > 1 {
		e = strings.TrimRight(e, "/")
	}
	return e
}

func clampConfidence(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}

func mergeStringSet(existing, additions []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[e] = true
	}
	for _, a := range additions {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			existing = append(existing, a)
			seen[a] = true
		}
	}
	return existing
}
