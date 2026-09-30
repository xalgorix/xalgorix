package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// TestLedgerFinishGateBlocksStaleTestingClaimEarly (P7 baseline): within the
// bounded retry window the gate still blocks on a claimed-but-not-closed
// hypothesis and names it.
func TestLedgerFinishGateBlocksStaleTestingClaimEarly(t *testing.T) {
	ctx, state := newTestCtxState(t)
	h := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "stuck lead", VulnClass: "business-logic", Status: scanctx.HypothesisTesting,
	})
	state.FinishAttempts = 2
	res := hookLedgerFinishGate(state, nil)
	if !res.Block {
		t.Fatal("gate must block within the retry window while a claim is open")
	}
	if !strings.Contains(res.BlockReason, h.ID) || !strings.Contains(res.BlockReason, "claimed but not closed") {
		t.Errorf("block reason should name the open claim: %q", res.BlockReason)
	}
	// The claim is NOT settled during the retry window.
	stored, _ := ctx.Ledger.Get(h.ID)
	if stored.Status != scanctx.HypothesisTesting {
		t.Errorf("claim must stay testing during the retry window, got %q", stored.Status)
	}
}

// TestLedgerFinishGateSettlesStaleTestingClaimExhausted (P7): after the
// bounded retries the gate converts the stale in-flight claim to the typed
// terminal `exhausted` disposition instead of silently stepping aside —
// one stuck testing hypothesis must not ride the whole scan into the
// finish-gate ceiling (the v4.6.123 pentest-ground run burned 500+
// iterations and terminated finish_gate_exhausted exactly this way).
func TestLedgerFinishGateSettlesStaleTestingClaimExhausted(t *testing.T) {
	ctx, state := newTestCtxState(t)
	stuck := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "stuck lead", VulnClass: "business-logic", Status: scanctx.HypothesisTesting,
	})
	other := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "second stuck lead", VulnClass: "race-conditions", Status: scanctx.HypothesisTesting,
	})
	// A QUEUED hypothesis is untouched: queued work was never claimed and
	// stays schedulable for a resume.
	queued := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "never claimed", VulnClass: "sqli", Status: scanctx.HypothesisQueued,
	})

	state.FinishAttempts = 4
	if res := hookLedgerFinishGate(state, nil); res.Block {
		t.Fatalf("gate must stop blocking after the bounded retries: %q", res.BlockReason)
	}
	for _, id := range []string{stuck.ID, other.ID} {
		stored, ok := ctx.Ledger.Get(id)
		if !ok || stored.Status != scanctx.HypothesisExhausted {
			t.Errorf("stale claim %s: status = %q, want exhausted", id, stored.Status)
		}
		if stored, _ := ctx.Ledger.Get(id); !strings.Contains(stored.NextAction, "auto-dispositioned") {
			t.Errorf("exhausted disposition should carry the auditable reason, got %q", stored.NextAction)
		}
	}
	stored, _ := ctx.Ledger.Get(queued.ID)
	if stored.Status != scanctx.HypothesisQueued {
		t.Errorf("never-claimed queued hypothesis must stay queued, got %q", stored.Status)
	}

	// The conversion is idempotent: re-running the gate changes nothing.
	if res := hookLedgerFinishGate(state, nil); res.Block {
		t.Errorf("gate must stay clear after conversion: %q", res.BlockReason)
	}
}

// TestLedgerFinishGateStaleSettlementIsOwnerScoped (P7): a delegated
// specialist's gate only settles its OWN stale claims, never the root's or
// another lane's.
func TestLedgerFinishGateStaleSettlementIsOwnerScoped(t *testing.T) {
	ctx, state := newTestCtxState(t)
	mine := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "my claim", VulnClass: "sqli", Status: scanctx.HypothesisTesting, AssignedTo: "sub_1",
	})
	foreign := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "root claim", VulnClass: "xss", Status: scanctx.HypothesisTesting,
	})

	state.DelegatedAgent = true
	state.DelegatedAgentID = "sub_1"
	state.FinishAttempts = 4
	if res := hookLedgerFinishGate(state, nil); res.Block {
		t.Fatalf("gate must clear after settling the specialist's own claim: %q", res.BlockReason)
	}
	if stored, _ := ctx.Ledger.Get(mine.ID); stored.Status != scanctx.HypothesisExhausted {
		t.Errorf("own claim must settle exhausted, got %q", stored.Status)
	}
	if stored, _ := ctx.Ledger.Get(foreign.ID); stored.Status != scanctx.HypothesisTesting {
		t.Errorf("foreign claim must stay testing, got %q", stored.Status)
	}
}
