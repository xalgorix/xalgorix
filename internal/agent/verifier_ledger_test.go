package agent

import (
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func engineExploit(source string) scanctx.Evidence {
	return scanctx.Evidence{Kind: "exploit", Summary: "CONFIRMED by " + source, Source: source, Confidence: 0.95}
}

// A verifier confirmation that merges into an existing record (an engine seed
// or a lead the model rejected) still ends up proven; a weak one reopens
// unclaimed or settled-without-proof work as testing but never overrides a
// model rejection.
func TestSettleVerifierHypothesis(t *testing.T) {
	ctx, _ := newTestCtxState(t)
	a := &Agent{}
	l := ctx.Ledger

	seed := l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/q", Parameter: "id", Origin: "auto-surface-param"})
	merged := l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/q", Parameter: "id", Origin: "verify_sqli", Status: scanctx.HypothesisTesting})
	if merged.ID != seed.ID || merged.Status != scanctx.HypothesisQueued {
		t.Fatalf("precondition: verifier upsert should merge into the queued seed, got %s %s", merged.ID, merged.Status)
	}
	a.settleVerifierHypothesis(l, seed.ID, true, "")
	if h, _ := l.Get(seed.ID); h.Status != scanctx.HypothesisProven {
		t.Fatalf("strong confirmation on a seed: status %s, want proven", h.Status)
	}

	rejected := l.Upsert(scanctx.Hypothesis{VulnClass: "ssti", Endpoint: "/t", Origin: "coordinator"})
	l.SetStatus(rejected.ID, scanctx.HypothesisRejected, "")
	a.settleVerifierHypothesis(l, rejected.ID, false, "")
	if h, _ := l.Get(rejected.ID); h.Status != scanctx.HypothesisRejected {
		t.Fatalf("weak signal overrode a model rejection: %s", h.Status)
	}
	a.settleVerifierHypothesis(l, rejected.ID, true, "")
	if h, _ := l.Get(rejected.ID); h.Status != scanctx.HypothesisProven {
		t.Fatalf("strong confirmation must reopen a rejected hypothesis as proven, got %s", h.Status)
	}

	for _, st := range []scanctx.HypothesisStatus{scanctx.HypothesisQueued, scanctx.HypothesisBlocked, scanctx.HypothesisExhausted} {
		h := l.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/w/" + string(st), Origin: "authz_matrix"})
		l.SetStatus(h.ID, st, "")
		a.settleVerifierHypothesis(l, h.ID, false, "")
		if got, _ := l.Get(h.ID); got.Status != scanctx.HypothesisTesting {
			t.Errorf("weak signal on %s work: status %s, want testing", st, got.Status)
		}
	}

	// A proven record is never touched, and a specialist owns what it verified.
	sub := &Agent{delegatedAgentID: "agent_sqli"}
	sub.settleVerifierHypothesis(l, seed.ID, false, "")
	if h, _ := l.Get(seed.ID); h.Status != scanctx.HypothesisProven || h.AssignedTo != "agent_sqli" {
		t.Fatalf("specialist result: status=%s assigned=%q, want proven / agent_sqli", h.Status, h.AssignedTo)
	}
}

// The finish gate's stale-claim settlement and the principled finish never
// auto-exhaust a claim an engine verifier recorded exploit evidence on.
func TestEngineEvidencedClaimsAreNotAutoExhausted(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ConvergeFinish = true
	plain := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "business-logic", Status: scanctx.HypothesisTesting})
	seen := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/orders/1", Status: scanctx.HypothesisTesting, Origin: "authz_matrix"})
	ctx.Ledger.AddEvidence(seen.ID, engineExploit("authz_matrix"))
	modelOnly := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/m", Status: scanctx.HypothesisTesting, Origin: "coordinator"})
	ctx.Ledger.AddEvidence(modelOnly.ID, scanctx.Evidence{Kind: "exploit", Summary: "confirmed (model text)"})

	state.FinishAttempts = 4
	hookLedgerFinishGate(state, nil)
	status := func(id string) scanctx.HypothesisStatus { h, _ := ctx.Ledger.Get(id); return h.Status }
	if status(plain.ID) != scanctx.HypothesisExhausted || status(modelOnly.ID) != scanctx.HypothesisExhausted {
		t.Fatalf("claims without engine evidence should settle: plain=%s model=%s", status(plain.ID), status(modelOnly.ID))
	}
	if status(seen.ID) != scanctx.HypothesisTesting {
		t.Fatalf("finish gate auto-exhausted an engine-evidenced claim: %s", status(seen.ID))
	}
	if n := reconcileLedgerForFinish(state); n != 0 || status(seen.ID) != scanctx.HypothesisTesting {
		t.Fatalf("principled finish settled an engine-evidenced claim: n=%d status=%s", n, status(seen.ID))
	}
}

// The verification window waits on engine-confirmed work of any age: proven
// but unreported, or still testing with engine exploit evidence.
func TestVerificationLeadsIncludeEngineConfirmedWork(t *testing.T) {
	ctx, state := newTestCtxState(t)
	proven := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/p", Origin: "verify_sqli"})
	ctx.Ledger.AddEvidence(proven.ID, engineExploit("verify_sqli"))
	ctx.Ledger.SetStatus(proven.ID, scanctx.HypothesisProven, "")
	testing := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/o", Origin: "authz_matrix", Status: scanctx.HypothesisTesting})
	ctx.Ledger.AddEvidence(testing.ID, engineExploit("authz_matrix"))
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "xss", Endpoint: "/seed", Origin: "auto-plan", Status: scanctx.HypothesisTesting, Confidence: 0.9})

	got := map[string]bool{}
	for _, h := range activeVerificationLeads(state, time.Now().Add(time.Hour)) {
		got[h.ID] = true
	}
	if len(got) != 2 || !got[proven.ID] || !got[testing.ID] {
		t.Fatalf("leads = %v, want exactly the proven-unreported %s and engine-evidenced %s", got, proven.ID, testing.ID)
	}
}
