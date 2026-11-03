package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// Once the finish tail is armed it, not the stuck-loop limit, ends a quiet
// scan: a model verifying one lead past the 160-iteration limit reaches the
// principled finish (completion assessment, residual, untested label) instead
// of being cut as stuck_loop_limit.
func TestFinishTailOwnsQuietSaturatedScan(t *testing.T) {
	const idle = semanticNonProgressLimit + 140
	a, _ := newSaturatedAgent(t, idle, -1)
	finalAt := 0
	for i := 1; i <= idle+50; i++ {
		a.state.Iteration++
		if res := a.semanticLivenessCheck(); res.StopReason != "" {
			t.Fatalf("stuck-loop limit cut the saturated scan at step %d: %+v", i, res)
		}
		if a.autoFinalizeIfPlanComplete() {
			finalAt = i
			break
		}
	}
	if finalAt != idle {
		t.Fatalf("finalized at step %d, want %d (the finish tail)", finalAt, idle)
	}
	if a.CompletionStopReason() != StopReasonUntestedAtFinish {
		t.Errorf("stop reason = %q, want %q", a.CompletionStopReason(), StopReasonUntestedAtFinish)
	}
}

// While the tail is armed the wall-clock idle budget restarts every turn, so it
// only catches a single hung request, not a long verification.
func TestFinishTailRestartsWallClockIdle(t *testing.T) {
	a, _ := newSaturatedAgent(t, 500, -1)
	a.cfg.MaxNonProgressSec = 3600
	a.scanBudget.progressAt = time.Now().Add(-2 * time.Hour)
	if res := a.semanticLivenessCheck(); res.StopReason != "" {
		t.Fatalf("armed tail was stopped by the wall-clock idle budget: %+v", res)
	}
	if rem := a.semanticIdleRemaining(); rem < 59*time.Minute {
		t.Fatalf("idle clock not restarted under the armed tail: %s left", rem)
	}
}

// With the tail disabled nothing else bounds the scan, so the stuck-loop limit
// still applies at saturation.
func TestStuckLimitAppliesWhenFinishTailDisabled(t *testing.T) {
	a, _ := newSaturatedAgent(t, -1, -1)
	a.state.ProgressIdleIterations = semanticNonProgressLimit - 1
	if res := a.semanticLivenessCheck(); res.StopReason != "stuck_loop_limit" {
		t.Fatalf("disabled tail must leave the stuck-loop limit in force, got %+v", res)
	}
}

// A model lead that lands on an engine seed with the same class and endpoint
// becomes a model lead: it restarts the tail and holds the verification window.
func TestModelLeadMergedIntoSeedIsALead(t *testing.T) {
	a, ctx := newSaturatedAgent(t, 10, 5)
	seed := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "auth", Endpoint: "/Api/account", Origin: "auto-plan-surface", Confidence: 0.5})
	for i := 0; i < 3; i++ {
		if step(a) {
			t.Fatal("finalized early")
		}
	}
	time.Sleep(2 * time.Millisecond)
	lead := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "auth", Endpoint: "/Api/account", Origin: "coordinator", Confidence: 0.8, Status: scanctx.HypothesisTesting})
	if lead.ID != seed.ID {
		t.Fatalf("lead did not merge into the seed: %s vs %s", lead.ID, seed.ID)
	}
	step(a)
	if a.state.LeadIdleResets != 1 {
		t.Fatalf("model lead on a seed did not restart the tail: resets=%d", a.state.LeadIdleResets)
	}
	if leads := activeVerificationLeads(a.state, time.Time{}); len(leads) != 1 || leads[0].ID != seed.ID {
		t.Fatalf("model lead on a seed is not an active lead: %+v", leads)
	}
}

// The verification window counts the turns it held, so provider retries that
// advance the iteration number cannot use it up.
func TestLeadWindowCountsTurnsNotIterations(t *testing.T) {
	a, ctx := newSaturatedAgent(t, 10, 5)
	lead := ctx.Ledger.Upsert(modelLead("/Api/account", 0.8))
	for i := 0; i < 3; i++ {
		step(a)
	}
	time.Sleep(2 * time.Millisecond)
	ctx.Ledger.SetStatus(lead.ID, scanctx.HypothesisTesting, "probe")
	for a.state.LeadWindowStartIteration == 0 {
		if step(a) {
			t.Fatal("finalized before the window opened")
		}
	}
	for turn := 1; turn <= 5; turn++ {
		a.state.Iteration += 40 // retries in between: no model turn
		if final := a.autoFinalizeIfPlanComplete(); final != (turn == 5) {
			t.Fatalf("window turn %d: finalized=%v, want finalize only on turn 5", turn, final)
		}
	}
}

func TestPauseIdleClockExcludesProviderWait(t *testing.T) {
	a := &Agent{state: NewScanState(), scanBudget: newScanBudget(), cfg: &config.Config{MaxNonProgressSec: 60}}
	a.scanBudget.progressAt = time.Now().Add(-50 * time.Second)
	a.pauseIdleClock(30 * time.Second)
	if rem := a.semanticIdleRemaining(); rem < 38*time.Second || rem > 41*time.Second {
		t.Fatalf("idle remaining after a 30s provider wait = %s, want ~40s", rem)
	}
}

// A provider rate-limit storm longer than the stuck-loop limit must not end
// the scan as stuck_loop_limit: retries are not model turns.
func TestProviderRetriesDoNotSpendStuckLimit(t *testing.T) {
	const storm = semanticNonProgressLimit + 40
	var requests int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) <= storm {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "Rate limit exceeded. Please retry later.", "type": "tokens"}})
			return
		}
		select { // park the first request after the storm until the test ends
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	cfg := &config.Config{LLM: "openai/gpt-test", APIBase: srv.URL, APIKey: "sk-test", MaxRateLimitWaitSec: 3600}
	events := make(chan Event, 4096)
	a := NewAgent(cfg, "provider-retry-idle", events, scopeguard.Config{BindAddr: "127.0.0.1"},
		WithLLMClient(llm.NewClient(cfg)),
		withRateLimitBackoff(func(int) time.Duration { return time.Millisecond }))
	done := make(chan struct{})
	go func() { a.Run([]string{"example.com"}, "assess"); close(done) }()

	deadline := time.After(60 * time.Second)
	for atomic.LoadInt32(&requests) <= storm {
		select {
		case <-done:
			for ev := range drain(events) {
				if ev.Type == "finished" {
					t.Fatalf("scan ended during the provider storm: %s / %s", ev.AbortReason, ev.Content)
				}
			}
			t.Fatal("scan ended during the provider storm")
		case <-deadline:
			t.Fatalf("storm did not complete: %d requests", atomic.LoadInt32(&requests))
		case <-time.After(5 * time.Millisecond):
		}
	}
	a.Stop()
	<-done
	if a.state.ProgressIdleIterations > 2 {
		t.Fatalf("provider retries counted as idle turns: ProgressIdleIterations=%d", a.state.ProgressIdleIterations)
	}
}

func drain(ch chan Event) chan Event {
	out := make(chan Event, len(ch))
	for {
		select {
		case ev := <-ch:
			out <- ev
		default:
			close(out)
			return out
		}
	}
}
