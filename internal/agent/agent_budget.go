package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// scanBudget is shared by the root coordinator and every delegated agent.
// Without a graph-wide ledger, a three-specialist scan would receive four
// independent copies of each configured cap and could spend roughly 4x the
// operator's requested tool/token budget.
type scanBudget struct {
	persistMu sync.Mutex
	startOnce sync.Once
	startedMu sync.RWMutex
	startedAt time.Time

	toolCalls     atomic.Int64
	iterations    atomic.Int64
	tokens        atomic.Int64
	progress      atomic.Int64
	progressFacts map[string]bool // protected by persistMu
	progressAt    time.Time       // protected by persistMu
}

func newScanBudget() *scanBudget { return &scanBudget{} }

func (b *scanBudget) start() {
	if b == nil {
		return
	}
	b.startOnce.Do(func() {
		b.startedMu.Lock()
		b.startedAt = time.Now()
		b.startedMu.Unlock()
	})
}

func (b *scanBudget) elapsed() (time.Duration, bool) {
	if b == nil {
		return 0, false
	}
	b.startedMu.RLock()
	started := b.startedAt
	b.startedMu.RUnlock()
	if started.IsZero() {
		return 0, false
	}
	return time.Since(started), true
}

// scanDeadline is shared by model requests, delegated work and tool waits.
func (a *Agent) scanDeadline() (time.Time, bool) {
	if a.cfg == nil || a.cfg.MaxDurationSec <= 0 {
		return time.Time{}, false
	}
	started := a.scanStart
	if a.scanBudget != nil {
		a.scanBudget.startedMu.RLock()
		started = a.scanBudget.startedAt
		a.scanBudget.startedMu.RUnlock()
	}
	if started.IsZero() {
		return time.Time{}, false
	}
	return started.Add(time.Duration(a.cfg.MaxDurationSec) * time.Second), true
}

func (a *Agent) toolWaitContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	if scanDeadline, ok := a.scanDeadline(); ok && scanDeadline.Before(deadline) {
		deadline = scanDeadline
	}
	return context.WithDeadline(a.ctx, deadline)
}

// reserveToolCalls atomically reserves up to requested calls beneath cap and
// returns the number the caller may execute. cap <= 0 means unlimited, but the
// calls are still counted for telemetry.
func (b *scanBudget) reserveToolCalls(requested, cap int) int {
	if b == nil || requested <= 0 {
		return 0
	}
	if cap <= 0 {
		b.toolCalls.Add(int64(requested))
		return requested
	}
	for {
		used := b.toolCalls.Load()
		remaining := int64(cap) - used
		if remaining <= 0 {
			return 0
		}
		allowed := int64(requested)
		if allowed > remaining {
			allowed = remaining
		}
		if b.toolCalls.CompareAndSwap(used, used+allowed) {
			return int(allowed)
		}
	}
}

func (b *scanBudget) toolCallCount() int {
	if b == nil {
		return 0
	}
	return int(b.toolCalls.Load())
}

func (b *scanBudget) reserveIteration(cap int) bool {
	if b == nil {
		return true
	}
	if cap <= 0 {
		b.iterations.Add(1)
		return true
	}
	for {
		used := b.iterations.Load()
		if used >= int64(cap) {
			return false
		}
		if b.iterations.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

func (b *scanBudget) iterationCount() int {
	if b == nil {
		return 0
	}
	return int(b.iterations.Load())
}

func (b *scanBudget) addTokens(delta int) int {
	if b == nil {
		return 0
	}
	if delta > 0 {
		return int(b.tokens.Add(int64(delta)))
	}
	return int(b.tokens.Load())
}

func (b *scanBudget) tokenCount() int {
	if b == nil {
		return 0
	}
	return int(b.tokens.Load())
}

// syncBudgetTokens folds this agent client's cumulative token count into the
// graph-wide total exactly once per delta. Each agent owns one client and only
// advances lastBudgetTokens from its own loop, while scanBudget.tokens is
// atomic across agents.
func (a *Agent) syncBudgetTokens() int {
	if a == nil || a.client == nil {
		if a != nil && a.scanBudget != nil {
			return a.scanBudget.tokenCount()
		}
		return 0
	}
	_, _, current := a.client.GetTokens()
	if a.scanBudget == nil {
		return current
	}
	delta := current - a.lastBudgetTokens
	if delta > 0 {
		a.lastBudgetTokens = current
		return a.scanBudget.addTokens(delta)
	}
	return a.scanBudget.tokenCount()
}
