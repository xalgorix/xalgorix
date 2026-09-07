// Package scanctx provides per-scan-session state isolation.
// Each ScanContext encapsulates the mutable state (vulnerabilities, notes,
// terminal processes, browser instance) that was previously stored in
// package-level globals. This allows multiple concurrent scan sessions
// without data corruption.
package scanctx

import (
	"context"
	"fmt"
	"log"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/safe"
)

// RequestRatePolicy is the per-scan outbound request budget. MaxRPS is kept as
// a float so operator settings like 2.5 rps can be represented, while command
// adapters can derive conservative integer flags from it.
type RequestRatePolicy struct {
	MaxRPS float64
	Source string
}

// NormalizeRequestRatePolicy applies the minimum enforceable request policy.
// Scanner CLIs generally accept whole-number rates, so sub-1 RPS instructions
// are raised to the lowest supported cap instead of being silently represented
// as a fractional policy that most tools cannot honor.
func NormalizeRequestRatePolicy(policy RequestRatePolicy) RequestRatePolicy {
	if policy.MaxRPS > 0 && policy.MaxRPS < 1 {
		policy.MaxRPS = 1
		if policy.Source != "" {
			policy.Source += "; minimum supported 1 rps"
		} else {
			policy.Source = "minimum supported 1 rps"
		}
	}
	return policy
}

// Enabled reports whether a request-rate policy should be enforced.
func (p RequestRatePolicy) Enabled() bool {
	return p.MaxRPS > 0
}

// CommandRPS returns the highest whole-number rate that does not exceed MaxRPS.
func (p RequestRatePolicy) CommandRPS() int {
	if p.MaxRPS <= 0 {
		return 0
	}
	n := int(math.Floor(p.MaxRPS))
	if n < 1 {
		return 1
	}
	return n
}

// Delay returns the minimum gap between requests needed to stay under MaxRPS.
func (p RequestRatePolicy) Delay() time.Duration {
	if p.MaxRPS <= 0 {
		return 0
	}
	ms := int(math.Ceil(1000 / p.MaxRPS))
	if ms < 1 {
		ms = 1
	}
	return time.Duration(ms) * time.Millisecond
}

// ScanContext holds all mutable state for a single scan session.
// Create one per scan instance via New(), and thread it through
// the tool registry so tools read/write their own session's state.
type ScanContext struct {
	ID      string
	ScanDir string

	Vulns    *VulnStore
	Notes    *NoteStore
	Terminal *TerminalState
	Browser  *BrowserState
	// Ledger is the durable, scan-shared hypothesis/evidence graph. It is the
	// one place the coordinator and every delegated specialist record and read
	// attack hypotheses, evidence, and status, and it persists to
	// <ScanDir>/ledger.json so it survives restart/resume.
	Ledger *LedgerStore
	// Coverage is the live scan-shared endpoint × class matrix. It lets the
	// coordinator reconcile work executed by parallel delegated specialists.
	Coverage *CoverageStore

	// ctx/cancel for the scan's lifecycle
	Ctx    context.Context
	Cancel context.CancelFunc

	policyMu          sync.RWMutex
	requestRatePolicy RequestRatePolicy
	targetsMu         sync.RWMutex
	targets           []string
}

// New creates a fresh ScanContext for an isolated scan session.
func New(id, scanDir string) *ScanContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanContext{
		ID:       id,
		ScanDir:  scanDir,
		Vulns:    NewVulnStore(),
		Notes:    NewNoteStore(),
		Terminal: NewTerminalState(),
		Browser:  NewBrowserState(),
		Ledger:   NewLedgerStore(),
		Coverage: NewCoverageStore(),
		Ctx:      ctx,
		Cancel:   cancel,
	}
}

// Close tears down all resources owned by this scan context.
// Safe to call multiple times.
//
// Each sub-step (cancel, Terminal.KillAll, Browser.Close) runs inside its
// own recovered closure so a panic in one step never prevents the others
// from running. The outer defer is a final safety net for anything not
// covered by the inner closures.
//
// Lease-conservation under panic (Task 13.3, Requirements 4.1 and 4.5):
// every Tool_Lease cached on this Scan_Context is released exactly once
// during Close, regardless of whether any earlier sub-step panics. The
// recovered-closure structure above is what carries this guarantee:
//
//   - The Cancel sub-step releases the scan's root context.WithCancel
//     funds — it never holds a Tool_Lease, but canceling here lets the
//     downstream subprocesses tracked by Terminal observe their context's
//     Done channel and exit cleanly before KillAll runs.
//
//   - The Terminal.KillAll sub-step is responsible for releasing every
//     per-process Tool_Lease acquired by terminal_execute and python_action
//     invocations. Each tool acquires its lease via
//     resources.AcquireToolLeaseContext and releases it in its own defer
//     when the subprocess exits or is killed, so KillAll's role here is to
//     trigger that exit path for any still-running child.
//
//   - The Browser.Close sub-step releases the browser Tool_Lease cached on
//     BrowserState. The release is idempotent (sync.Once on the browser
//     side), so a duplicate Close call from another shutdown path will
//     not double-release the lease.
//
// Because each sub-step lives in its own deferred-recover closure, a panic
// inside one step (for example, a corrupted cmd handle inside KillAll)
// produces a single recovery log line and lets the remaining steps run.
// That preserves the lease-conservation invariant: no cached lease is
// leaked, and none is released more than once, even when a panic occurs
// mid-shutdown.
func (sc *ScanContext) Close() {
	defer safe.Recover("scanctx.close", sc.ID)

	func() {
		defer safe.Recover("scanctx.close.cancel", sc.ID)
		if sc.Cancel != nil {
			sc.Cancel()
		}
	}()

	func() {
		defer safe.Recover("scanctx.close.terminal", sc.ID)
		if sc.Terminal != nil {
			sc.Terminal.KillAll()
		}
	}()

	func() {
		defer safe.Recover("scanctx.close.browser", sc.ID)
		if sc.Browser != nil {
			sc.Browser.Close()
		}
	}()
}

// SetRequestRatePolicy stores the scan-specific outbound request budget.
func (sc *ScanContext) SetRequestRatePolicy(policy RequestRatePolicy) {
	policy = NormalizeRequestRatePolicy(policy)
	sc.policyMu.Lock()
	defer sc.policyMu.Unlock()
	if current := sc.requestRatePolicy; current.Enabled() {
		if !policy.Enabled() || current.MaxRPS <= policy.MaxRPS {
			return
		}
	}
	sc.requestRatePolicy = policy
}

// RequestRatePolicy returns the current scan-specific outbound request budget.
func (sc *ScanContext) RequestRatePolicy() RequestRatePolicy {
	sc.policyMu.RLock()
	defer sc.policyMu.RUnlock()
	return sc.requestRatePolicy
}

// SetTargets stores the root coordinator's declared targets for tools that
// need to salvage an omitted target field. Delegated agents share this context
// and must not replace the root target set with their narrower assignment.
func (sc *ScanContext) SetTargets(targets []string) {
	if sc == nil {
		return
	}
	clean := make([]string, 0, len(targets))
	for _, target := range targets {
		if target = strings.TrimSpace(target); target != "" {
			clean = append(clean, target)
		}
	}
	sc.targetsMu.Lock()
	sc.targets = clean
	sc.targetsMu.Unlock()
}

// Targets returns a defensive copy of the root coordinator's target set.
func (sc *ScanContext) Targets() []string {
	if sc == nil {
		return nil
	}
	sc.targetsMu.RLock()
	defer sc.targetsMu.RUnlock()
	return append([]string(nil), sc.targets...)
}

// ──────────────────────────────────────────────────────────
// Active context registry — allows tool packages to access
// their session's ScanContext without changing Execute signatures.
// ──────────────────────────────────────────────────────────

var (
	activeMu   sync.RWMutex
	activeCtxs = make(map[string]*ScanContext) // instanceID → ScanContext
	defaultCtx *ScanContext                    // fallback for CLI mode (single scan)
)

// Activate registers a ScanContext as the active context for its ID.
// Also sets it as the default if no default exists (CLI mode compat).
func Activate(sc *ScanContext) {
	activeMu.Lock()
	defer activeMu.Unlock()
	activeCtxs[sc.ID] = sc
	if defaultCtx == nil {
		defaultCtx = sc
	}
}

// Deactivate removes a ScanContext from the active registry.
func Deactivate(id string) {
	activeMu.Lock()
	defer activeMu.Unlock()
	delete(activeCtxs, id)
	if defaultCtx != nil && defaultCtx.ID == id {
		defaultCtx = nil
		// Promote any remaining context as default
		for _, sc := range activeCtxs {
			defaultCtx = sc
			break
		}
	}
}

// Get returns the ScanContext for a given instance ID.
func Get(id string) *ScanContext {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeCtxs[id]
}

// Default returns the default (CLI-mode) ScanContext.
// If no context is active, creates and returns a temporary one.
//
// IMPORTANT: From the web server, callers MUST resolve the context via
// the agent/session that owns the request (registry.GetScanContextID,
// session.sctx, etc). Reaching Default() from a web-mode goroutine
// indicates a wiring bug — a tool would land in the shared CLI bucket
// where state from one scan would leak into another. The fallback creation
// log line is *the* signal that this regression has happened; grep for
// "[scanctx] Created fallback CLI context" in logs after a deploy.
func Default() *ScanContext {
	activeMu.RLock()
	if defaultCtx != nil {
		defer activeMu.RUnlock()
		return defaultCtx
	}
	activeMu.RUnlock()

	// Create a fallback for CLI mode. Capture a short caller stack so a bug
	// where web code accidentally drops the contextID is easy to root-cause.
	var callerInfo string
	pcs := make([]uintptr, 8)
	if n := runtime.Callers(2, pcs); n > 0 {
		frames := runtime.CallersFrames(pcs[:n])
		var b strings.Builder
		for {
			f, more := frames.Next()
			fmt.Fprintf(&b, "\n  %s\n    %s:%d", f.Function, f.File, f.Line)
			if !more {
				break
			}
		}
		callerInfo = b.String()
	}

	activeMu.Lock()
	defer activeMu.Unlock()
	if defaultCtx == nil {
		defaultCtx = New("cli-default", "")
		activeCtxs[defaultCtx.ID] = defaultCtx
		log.Printf("[scanctx] Created fallback CLI context (legitimate in CLI mode; in web mode this is a wiring bug):%s", callerInfo)
	}
	return defaultCtx
}

// ActiveCount returns the number of active scan contexts.
func ActiveCount() int {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return len(activeCtxs)
}

// ──────────────────────────────────────────────────────────
// Summary / debug
// ──────────────────────────────────────────────────────────

// Summary returns a human-readable summary of all active scan contexts.
func Summary() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if len(activeCtxs) == 0 {
		return "No active scan contexts"
	}
	s := fmt.Sprintf("%d active scan context(s):\n", len(activeCtxs))
	for id, sc := range activeCtxs {
		vulnCount := sc.Vulns.Count()
		noteCount := sc.Notes.Count()
		procCount := sc.Terminal.ActiveProcessCount()
		s += fmt.Sprintf("  [%s] dir=%s vulns=%d notes=%d procs=%d\n",
			id, sc.ScanDir, vulnCount, noteCount, procCount)
	}
	return s
}

// ResetAll tears down all active contexts. Used for testing.
func ResetAll() {
	activeMu.Lock()
	defer activeMu.Unlock()
	for _, sc := range activeCtxs {
		sc.Close()
	}
	activeCtxs = make(map[string]*ScanContext)
	defaultCtx = nil
}
