package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// ── Coverage attribution (Part 21 cases 38-40) ───────────────────────────────

// Case 39: one shallow specialist test (a raw request probe) must not close
// the class globally.
func TestSpecialistEvidence_RawProbeDoesNotCloseClass(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DiscoveredEndpoints = []string{"example.com/search", "example.com/api/users"}
	// A specialist's raw probe on /search lands only in the shared RAW tier
	// (this is what markEndpointClassCoverage mirrors to the shared store).
	ctx.Coverage.Mark("example.com/search", "sqli")
	if endpointTestedForClass(state, "example.com/search", "sqli") {
		t.Fatal("raw request-level probes must never close coverage for the coordinator")
	}
	if endpointTestedForClass(state, "example.com/api/users", "sqli") {
		t.Fatal("case 38: an unrelated endpoint must not inherit sqli coverage")
	}
	task := newCoverageTask("sqli", state.DiscoveredEndpoints)
	if taskCoverageComplete(state, task) {
		t.Fatal("one shallow child probe must not complete the sqli lane")
	}
}

// Case 40: strong specialist evidence (a deterministic verifier that actually
// executed) contributes to global coverage without the root re-probing.
func TestSpecialistEvidence_VerifierRunContributes(t *testing.T) {
	_, state := newTestCtxState(t)
	state.DiscoveredEndpoints = []string{"example.com/search", "example.com/api/users"}

	// The child ran verify_sqli against /search successfully (the result hook
	// bridges it into the shared verifier-attributed tier).
	hookVerifierEvidenceBridge(state, map[string]string{
		"tool_name": "verify_sqli",
		"url":       "https://example.com/search?q=1",
		"output":    "baseline identical; not exploitable",
	})
	if !endpointTestedForClass(state, "example.com/search", "sqli") {
		t.Fatal("verifier-executed pairs must count as scan-level coverage")
	}
	// Only for that endpoint — the unrelated endpoint stays open (case 38).
	if endpointTestedForClass(state, "example.com/api/users", "sqli") {
		t.Fatal("verifier coverage is per endpoint, never global")
	}

	// A verifier that errored or produced no output is NOT evidence.
	_, state2 := newTestCtxState(t)
	hookVerifierEvidenceBridge(state2, map[string]string{
		"tool_name": "verify_sqli",
		"url":       "https://example.com/search?q=1",
		"error":     "missing required parameter: url",
	})
	if endpointTestedForClass(state2, "example.com/search", "sqli") {
		t.Fatal("a failed verifier call must not count as evidence")
	}
}

// Case 41: mere keywords in commands do not falsely mark classes complete.
func TestCoverageKeywords_MeaninglessSignalsIgnored(t *testing.T) {
	// Bare admin URL with an XFF header: no access-control coverage.
	if containsAccessControlIndicator(`curl -H "x-forwarded-for: 1.2.3.4" https://target.com/admin`) {
		t.Fatal("a plain /admin request must not count as access-control coverage")
	}
	// A harmless XML doctype: not XXE coverage.
	if hasStr(detectedVulnClasses(`curl -d "<?xml version=\"1.0\"?><!DOCTYPE note><note>x</note>" https://t.example/order`), "xxe") {
		t.Fatal("a plain DOCTYPE without an entity is not XXE coverage")
	}
	// The localhost target URL itself: not SSRF coverage.
	if hasStr(detectedVulnClasses(`curl https://127.0.0.1:9000/search`), "ssrf") {
		t.Fatal("a request TO a local target is not SSRF coverage")
	}
	// Genuine entity-injection probe: counts.
	if !hasStr(detectedVulnClasses(`curl -d "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><t>&xxe;</t>" https://t.example/order`), "xxe") {
		t.Fatal("a real entity injection probe must count as xxe coverage")
	}
	// Genuine boundary probe: counts.
	if !containsAccessControlIndicator(`curl https://target.com/api/user/2 -H "Cookie: session=user1"`) {
		t.Fatal("a cross-object probe must count as access-control coverage")
	}
}

// ── Lane completion (Part 15) ──────────────────────────────────────────────

// Pre-assigned but never-claimed hypotheses keep a specialist's finish gate
// closed, and soft assignment never removes them from the schedulable pool.
func TestLaneCompletion_AssignedUnclaimedBlocksFinish(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DelegatedAgent = true
	state.DelegatedAgentID = "agent-biz"
	state.FinishAttempts = 1

	h := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "Test business-logic on /api/checkout", VulnClass: "business-logic",
		Endpoint: "/api/checkout", Status: scanctx.HypothesisQueued,
	})
	if !ctx.Ledger.MarkAssigned(h.ID, "agent-biz") {
		t.Fatal("MarkAssigned must succeed")
	}

	// Soft assignment keeps the hypothesis queued...
	if got := ctx.Ledger.Schedulable(5); len(got) != 1 || got[0].ID != h.ID {
		t.Fatalf("soft-assigned hypotheses must remain schedulable, got %v", got)
	}
	// ...but the specialist cannot finish over its unclaimed lane.
	gate := hookLedgerFinishGate(state, nil)
	if !gate.Block || !strings.Contains(gate.BlockReason, "lane-assigned but never claimed") {
		t.Fatalf("expected a lane-completion block, got: %+v", gate)
	}

	// The root is not blocked by a specialist's lane (owner scoping).
	_, rootState := newTestCtxState(t)
	rootState.FinishAttempts = 1
	rootGate := hookLedgerFinishGate(rootState, nil)
	if rootGate.Block {
		t.Fatal("the root must not inherit a specialist's lane-assignment block")
	}
}
