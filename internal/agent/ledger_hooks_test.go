package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// newTestCtxState creates an active ScanContext (with an in-memory ledger, no
// persist path) and a ScanState wired to it. The context is deactivated on
// cleanup so tests do not leak active contexts into one another.
func newTestCtxState(t *testing.T) (*scanctx.ScanContext, *ScanState) {
	t.Helper()
	id := "ledger-hooks-test-" + t.Name()
	ctx := scanctx.New(id, "")
	scanctx.Activate(ctx)
	t.Cleanup(func() { scanctx.Deactivate(id) })
	state := NewScanState()
	state.ScanContextID = id
	return ctx, state
}

func TestSeedLedgerFromPlan(t *testing.T) {
	ctx, state := newTestCtxState(t)
	plan := NewPlan()
	plan.add(&Task{ID: "recon", Title: "Recon", Phase: 1, Status: TaskPending})
	plan.add(&Task{ID: "test-sqli", Title: "Test SQLi", Phase: 6, VulnClass: "sqli", Status: TaskPending})
	plan.add(&Task{ID: "test-xss", Title: "Test XSS", Phase: 7, VulnClass: "xss", Status: TaskPending})
	plan.add(&Task{ID: "report", Title: "Report", Phase: 22, Status: TaskPending})
	state.Plan = plan

	n := seedLedgerFromPlan(state, ctx.Ledger)
	if n != 2 {
		t.Fatalf("expected 2 class hypotheses seeded (structural tasks skipped), got %d", n)
	}
	if ctx.Ledger.Len() != 2 {
		t.Fatalf("expected ledger length 2, got %d", ctx.Ledger.Len())
	}
	// Idempotent: re-seeding the same plan dedups to zero new.
	if again := seedLedgerFromPlan(state, ctx.Ledger); again != 0 {
		t.Fatalf("expected 0 new hypotheses on reseed, got %d", again)
	}
}

func TestHookLedgerSeedLifecycle(t *testing.T) {
	ctx, state := newTestCtxState(t)

	// No plan yet -> no-op, not marked seeded.
	if r := hookLedgerSeed(state, nil); r.Nudge != "" || state.LedgerSeeded {
		t.Fatal("expected no-op before a plan exists")
	}

	plan := NewPlan()
	plan.add(&Task{ID: "test-idor", VulnClass: "idor", Status: TaskPending})
	state.Plan = plan

	hookLedgerSeed(state, nil)
	if !state.LedgerSeeded {
		t.Fatal("expected LedgerSeeded to be set")
	}
	if ctx.Ledger.Len() != 1 {
		t.Fatalf("expected 1 hypothesis after seed, got %d", ctx.Ledger.Len())
	}

	// Second call is a no-op (already seeded).
	before := ctx.Ledger.Len()
	hookLedgerSeed(state, nil)
	if ctx.Ledger.Len() != before {
		t.Fatal("expected a second hookLedgerSeed call to be a no-op")
	}
}

func TestHookAdvisoryLeadCommitsExactRouteBeforeBreadth(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "exploit_search",
		"query":     "Example 4.2 exploit",
		"output":    "CVE-2026-12345 permits unauthenticated remote code execution through POST /api/setup/validate even after the setup UI is complete.",
	})
	for _, want := range []string{"ADVISORY LEAD COMMITTED", "CVE-2026-12345", "/api/setup/validate", "verify_timing", "adjacent setup", "byte-for-byte", "escaped Unicode/newlines", "RUNSCRIPT/URL/XML/webhook/database fetch"} {
		if !strings.Contains(result.Nudge, want) {
			t.Fatalf("advisory commitment nudge missing %q: %s", want, result.Nudge)
		}
	}
	all := ctx.Ledger.All()
	if len(all) != 1 || all[0].VulnClass != "rce" || all[0].Endpoint != "/api/setup/validate" || all[0].Origin != "advisory-lookup" || all[0].Status != scanctx.HypothesisQueued {
		t.Fatalf("exact advisory lead was not durably seeded: %+v", all)
	}
	for _, want := range []string{"byte-for-byte", "escaped Unicode/newlines", "RUNSCRIPT/URL fetch is not code execution proof"} {
		if !strings.Contains(all[0].NextAction, want) {
			t.Fatalf("advisory next action missing %q: %s", want, all[0].NextAction)
		}
	}
	if repeat := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "cve_search", "cve_id": "CVE-2026-12345",
		"output": "Remote code execution at /api/setup/validate (CWE-94).",
	}); repeat.Nudge != "" || ctx.Ledger.Len() != 1 {
		t.Fatalf("same advisory route should nudge/seed once: result=%+v ledger=%+v", repeat, ctx.Ledger.All())
	}
}

func TestHookAdvisoryLeadRequiresClassificationForSparseExactCVE(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "exploit_search",
		"cve_id":    "CVE-2026-99999",
		"output":    "Exploit-DB search results for CVE-2026-99999.",
	})
	for _, want := range []string{"NEEDS CLASSIFICATION", "CVE-2026-99999", "cve_search", "before broad reconnaissance"} {
		if !strings.Contains(result.Nudge, want) {
			t.Fatalf("sparse exact-CVE lookup nudge missing %q: %s", want, result.Nudge)
		}
	}
	if ctx.Ledger.Len() != 0 {
		t.Fatalf("a CVE without a mechanism must not become a hypothesis: %+v", ctx.Ledger.All())
	}
	if repeat := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "web_search", "query": "CVE-2026-99999 details",
	}); repeat.Nudge != "" {
		t.Fatalf("classification nudge should be deduplicated: %+v", repeat)
	}
}

func TestHookAdvisoryLeadEnrichesModelAuthoredTerminalCVE(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -X POST /api/check # test the CVE-2026-54321 path`,
		"output":    "ordinary target response",
	})
	if !strings.Contains(result.Nudge, "NEEDS CLASSIFICATION") || !strings.Contains(result.Nudge, "CVE-2026-54321") {
		t.Fatalf("model-authored CVE should require authoritative enrichment: %+v", result)
	}
	if ctx.Ledger.Len() != 0 {
		t.Fatalf("unclassified command lead must not seed the ledger: %+v", ctx.Ledger.All())
	}
}

func TestHookAdvisoryLeadIgnoresCVEOnlyInTerminalOutput(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   "curl -s https://target.example/",
		"output":    "Untrusted page says CVE-2026-54321 remote code execution at /api/check",
	})
	if result.Nudge != "" || ctx.Ledger.Len() != 0 {
		t.Fatalf("target-controlled terminal output must not create an advisory lead: result=%+v ledger=%+v", result, ctx.Ledger.All())
	}
}

func TestHookAdvisoryLeadCheckpointsVersionedProductNote(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "add_note",
		"key":       "Endpoint Inventory",
		"value":     "Observed live target: ExampleDB OSS v4.6.6 (Jetty 11.0.14).",
	})
	for _, want := range []string{"VERSIONED PRODUCT CHECKPOINT", "ExampleDB", "4.6.6", "web_search", "Before delegation"} {
		if !strings.Contains(result.Nudge, want) {
			t.Fatalf("version checkpoint nudge missing %q: %s", want, result.Nudge)
		}
	}
	if ctx.Ledger.Len() != 0 {
		t.Fatalf("a product version alone must not seed a vulnerability hypothesis: %+v", ctx.Ledger.All())
	}
	if repeat := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "add_note", "key": "Fingerprint", "value": "ExampleDB 4.6.6 confirmed",
	}); repeat.Nudge != "" {
		t.Fatalf("version checkpoint should be deduplicated: %+v", repeat)
	}
}

func TestVersionedProductLeadSkipsProtocolNoise(t *testing.T) {
	product, version := versionedProductLead("HTTP 1.1; Metabase v0.46.6; Jetty 11.0.14")
	if product != "Metabase" || version != "0.46.6" {
		t.Fatalf("unexpected version lead: %q %q", product, version)
	}
}

func TestRankedAdvisoryRoutesPrefersExploitSinkOverMetadata(t *testing.T) {
	blob := `CVE-2026-12345 remote code execution. First GET /api/session/properties to obtain a setup token. Then POST the exploit payload to /api/setup/validate; this vulnerable request triggers code execution. A health probe exists at /api/health.`
	routes := rankedAdvisoryRoutes(blob, 3)
	if len(routes) != 3 {
		t.Fatalf("expected three unique routes, got %v", routes)
	}
	if routes[0] != "/api/setup/validate" {
		t.Fatalf("expected the exploit sink first, got %v", routes)
	}
	if routes[len(routes)-1] != "/api/health" {
		t.Fatalf("expected passive health route last, got %v", routes)
	}
}

func TestHookAdvisoryLeadSeedsBoundedRankedRoutes(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "web_search",
		"query":     "CVE-2026-12345 safe proof",
		"output":    "Remote code execution: GET /api/session/properties for metadata, then POST payload to /api/setup/validate. /api/health is informational. /api/fourth is unrelated.",
	})
	if !strings.Contains(result.Nudge, "/api/setup/validate") {
		t.Fatalf("ranked sink missing from nudge: %s", result.Nudge)
	}
	all := ctx.Ledger.All()
	if len(all) != 3 {
		t.Fatalf("expected bounded top-three route hypotheses, got %d: %+v", len(all), all)
	}
	if all[0].Endpoint != "/api/setup/validate" && all[1].Endpoint != "/api/setup/validate" && all[2].Endpoint != "/api/setup/validate" {
		t.Fatalf("exploit sink was not seeded: %+v", all)
	}
}

func TestHookLedgerSeedNoActiveContext(t *testing.T) {
	state := NewScanState()
	state.ScanContextID = "no-such-active-context"
	plan := NewPlan()
	plan.add(&Task{ID: "test-sqli", VulnClass: "sqli", Status: TaskPending})
	state.Plan = plan

	if r := hookLedgerSeed(state, nil); r.Nudge != "" {
		t.Fatal("expected no nudge without an active context")
	}
	if state.LedgerSeeded {
		t.Fatal("expected LedgerSeeded to stay false when no ledger is reachable")
	}
}

func TestProvenUnreportedHypotheses(t *testing.T) {
	ctx, _ := newTestCtxState(t)
	l := ctx.Ledger

	l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/a"}) // queued — ignored

	proven := l.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/b"})
	l.SetStatus(proven.ID, scanctx.HypothesisProven, "") // proven, no finding — listed

	reported := l.Upsert(scanctx.Hypothesis{VulnClass: "ssrf", Endpoint: "/c"})
	l.SetStatus(reported.ID, scanctx.HypothesisProven, "")
	l.AddEvidence(reported.ID, scanctx.Evidence{Kind: scanctx.EvidenceFindingRef, FindingID: "XALG-1", Summary: "confirmed"})

	un := provenUnreportedHypotheses(l)
	if len(un) != 1 || un[0] != proven.ID {
		t.Fatalf("expected only %s unreported, got %v", proven.ID, un)
	}
}

func TestHookLedgerFinishGate(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.FinishAttempts = 1
	l := ctx.Ledger

	p := l.Upsert(scanctx.Hypothesis{VulnClass: "rce", Endpoint: "/x"})
	l.SetStatus(p.ID, scanctx.HypothesisProven, "")

	r := hookLedgerFinishGate(state, nil)
	if !r.Block {
		t.Fatal("expected finish blocked while a proven hypothesis is unreported")
	}
	if !strings.Contains(r.BlockReason, p.ID) {
		t.Fatalf("expected block reason to name %s, got: %s", p.ID, r.BlockReason)
	}

	// Linking a finding clears the gate.
	l.AddEvidence(p.ID, scanctx.Evidence{Kind: scanctx.EvidenceFindingRef, FindingID: "XALG-2", Summary: "poc"})
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected gate to clear after linking a finding")
	}

	// Even with a fresh proven-unreported hypothesis, the gate must release once
	// the attempt bound is exceeded so it can never deadlock the scan.
	p2 := l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/y"})
	l.SetStatus(p2.ID, scanctx.HypothesisProven, "")
	state.FinishAttempts = 4
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected gate to release after FinishAttempts exceeds the bound")
	}
}

func TestHookLedgerFinishGateDiscoveryModeBypass(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DiscoveryMode = true
	state.FinishAttempts = 1
	p := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/x"})
	ctx.Ledger.SetStatus(p.ID, scanctx.HypothesisProven, "")

	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected discovery mode to bypass the ledger finish gate")
	}
}

func TestBuildDelegationNudgeIsLedgerDriven(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DetectedTechs = map[string]bool{"php": true}
	state.DiscoveredEndpoints = []string{"/api/users", "/login"}
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/api/users", Parameter: "id", Confidence: 0.6})

	nudge := buildDelegationNudge(state)
	for _, want := range []string{
		"authz-logic", "injection-serverside", "client-source", // specialist roles
		"read_ledger", "assigned_to", // ledger-driven assignment
		"One claim or one finding is never lane completion",
		"report every distinct proven vulnerability",
		"detected stack: php", "/api/users", // recon context + schedulable hypothesis
	} {
		if !strings.Contains(nudge, want) {
			t.Fatalf("expected delegation nudge to contain %q\n---\n%s", want, nudge)
		}
	}
}

func TestSpecialistProfilesCoverWeakClasses(t *testing.T) {
	covered := map[string]bool{}
	for _, p := range defaultSpecialistProfiles {
		if p.Role == "" || p.EvidenceContract == "" || p.StoppingRule == "" {
			t.Fatalf("specialist profile %q is missing required fields", p.Role)
		}
		for _, c := range p.VulnClasses {
			covered[c] = true
		}
		// The recon-discovery lane is a bounded ENUMERATION lane, not a
		// hypothesis-exhaustion lane: its stop rule is budget/manifest-shaped.
		if p.Role == "recon-discovery" {
			if !strings.Contains(p.StoppingRule, "bounded") {
				t.Fatalf("discovery lane must have a bounded stop rule: %s", p.StoppingRule)
			}
		} else if !strings.Contains(p.StoppingRule, "do not stop after the first finding") ||
			!strings.Contains(p.StoppingRule, "no assigned queued/testing hypothesis remains") {
			t.Fatalf("specialist profile %q permits premature lane completion: %s", p.Role, p.StoppingRule)
		}
		if p.Role == "client-source" &&
			(!strings.Contains(p.Focus, "dynamic URL routes") ||
				!strings.Contains(p.EvidenceContract, "verify_path_template_xss")) {
			t.Fatalf("client specialist does not cover path-template XSS: %s", p.EvidenceContract)
		}
	}
	// The classes autonomous scanners are weakest at must be owned by a profile.
	for _, want := range []string{"rce", "remote-code-execution", "code-injection", "blind-sqli", "xss", "idor", "ssrf", "path_traversal"} {
		if !covered[want] {
			t.Fatalf("expected specialist profiles to cover %q", want)
		}
	}
	var injection *specialistProfile
	for i := range defaultSpecialistProfiles {
		if defaultSpecialistProfiles[i].Role == "injection-serverside" {
			injection = &defaultSpecialistProfiles[i]
		}
	}
	if injection == nil {
		t.Fatal("missing injection-serverside profile")
	}
	for _, want := range []string{"version-matched public-advisory leads", "web_search/exploit_search", "cve_search", "target-attributable", "verify_timing", "Thread.sleep"} {
		if !strings.Contains(injection.EvidenceContract, want) {
			t.Fatalf("server-side specialist is missing advisory-guided proof rule %q: %s", want, injection.EvidenceContract)
		}
	}
}

func TestHookLedgerFinishGateBlocksClaimedWork(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.FinishAttempts = 1
	h := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/search"})
	ctx.Ledger.Assign(h.ID, "sub-injection")

	r := hookLedgerFinishGate(state, nil)
	if !r.Block || !strings.Contains(r.BlockReason, h.ID) || !strings.Contains(r.BlockReason, "claimed but not closed") {
		t.Fatalf("expected claimed hypothesis to block finish, got: %+v", r)
	}
	ctx.Ledger.SetStatus(h.ID, scanctx.HypothesisRejected, "baseline and probe matched")
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected gate to clear after claimed hypothesis is closed")
	}
}

func TestHookLedgerFinishGateScopesDelegatedOwnership(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.FinishAttempts = 1
	state.DelegatedAgent = true
	state.DelegatedAgentID = "sub-a"

	own := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/owned"})
	ctx.Ledger.Assign(own.ID, "sub-a")
	other := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/other"})
	ctx.Ledger.Assign(other.ID, "sub-b")

	r := hookLedgerFinishGate(state, nil)
	if !r.Block || !strings.Contains(r.BlockReason, own.ID) {
		t.Fatalf("expected delegated gate to block on its own testing work, got: %+v", r)
	}
	if strings.Contains(r.BlockReason, other.ID) {
		t.Fatalf("delegated gate must not block on another specialist's work: %s", r.BlockReason)
	}

	ctx.Ledger.SetStatus(own.ID, scanctx.HypothesisRejected, "control matched")
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected sub-a to finish while only sub-b still has testing work")
	}

	// A hypothesis created by the specialist belongs to it even before an
	// explicit assignment, so proven evidence cannot escape its reporting gate.
	created := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "xss", Endpoint: "/created", Origin: "sub-a"})
	ctx.Ledger.SetStatus(created.ID, scanctx.HypothesisProven, "")
	if r = hookLedgerFinishGate(state, nil); !r.Block || !strings.Contains(r.BlockReason, created.ID) {
		t.Fatalf("expected origin-owned proven work to block sub-a, got: %+v", r)
	}
	ctx.Ledger.AddEvidence(created.ID, scanctx.Evidence{Kind: scanctx.EvidenceFindingRef, FindingID: "XALG-A"})
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected delegated gate to clear after its origin-owned finding was linked")
	}

	// The root coordinator remains responsible for all shared-ledger work.
	state.DelegatedAgent = false
	state.DelegatedAgentID = ""
	if r = hookLedgerFinishGate(state, nil); !r.Block || !strings.Contains(r.BlockReason, other.ID) {
		t.Fatalf("expected root gate to retain global visibility, got: %+v", r)
	}
}

func TestHookDelegationCoordinatorFiresOnceWithLedger(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.Iteration = 6
	state.Plan = AutoPlan([]string{"/api/orders"}, nil)
	state.PlanBuilt = true
	state.LedgerSeeded = true
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/api/orders", Confidence: 0.7})

	r := fireDirectives(t, state, hookDelegationCoordinator)
	if r.Nudge == "" {
		t.Fatal("expected a delegation nudge once recon is mature")
	}
	if !strings.Contains(r.Nudge, "read_ledger") || !strings.Contains(r.Nudge, "injection-serverside") {
		t.Fatalf("expected a ledger-driven, profile-based nudge, got:\n%s", r.Nudge)
	}
	if !state.DelegationNudgeFired {
		t.Fatal("expected DelegationNudgeFired to be set")
	}
	// One-time: subsequent calls are silent.
	if fireDirectives(t, state, hookDelegationCoordinator).Nudge != "" {
		t.Fatal("expected the delegation nudge to fire only once")
	}
}

func TestHookDelegationCoordinatorWaitsForPlanAndLedger(t *testing.T) {
	_, state := newTestCtxState(t)
	state.ReconDone = true
	state.Iteration = 6

	if got := fireDirectives(t, state, hookDelegationCoordinator); got.Nudge != "" || state.DelegationNudgeFired {
		t.Fatal("delegation must wait until a plan and its ledger hypotheses exist")
	}
	state.Plan = AutoPlan([]string{"/api/orders"}, nil)
	state.PlanBuilt = true
	if got := fireDirectives(t, state, hookDelegationCoordinator); got.Nudge != "" || state.DelegationNudgeFired {
		t.Fatal("delegation must wait until the plan has been seeded into the ledger")
	}
	state.LedgerSeeded = true
	if got := fireDirectives(t, state, hookDelegationCoordinator); got.Nudge != "" || state.DelegationNudgeFired {
		t.Fatal("delegation must wait for a real endpoint inventory")
	}
	state.EndpointInventorySaved = true
	if got := fireDirectives(t, state, hookDelegationCoordinator); got.Nudge == "" || !state.DelegationNudgeFired {
		t.Fatal("expected delegation after plan, ledger, and inventory initialization")
	}

	child := NewScanState()
	child.DelegatedAgent = true
	child.ReconDone = true
	child.Iteration = 20
	child.Plan = AutoPlan([]string{"/api/orders"}, nil)
	child.PlanBuilt = true
	child.LedgerSeeded = true
	if got := hookDelegationCoordinator(child, nil); got.Nudge != "" || child.DelegationNudgeFired {
		t.Fatal("delegated specialists must never receive another delegation nudge")
	}
}

func TestDefaultHooksWaitForInventoryBeforeDelegation(t *testing.T) {
	_, state := newTestCtxState(t)
	state.ReconDone = true
	state.Iteration = 5
	state.EndpointsTested["example.test/api/health"] = true

	reg := NewHookRegistry()
	RegisterDefaultHooks(reg)
	first := reg.Fire(OnIterationStart, state, nil)
	if state.Plan != nil || state.PlanBuilt || state.LedgerSeeded {
		t.Fatalf("a health check must not become a provisional whole-target plan: plan=%v built=%v seeded=%v",
			state.Plan != nil, state.PlanBuilt, state.LedgerSeeded)
	}
	if !strings.Contains(first.Nudge, "Endpoint Inventory") {
		t.Fatalf("first iteration should request grounded inventory: %q", first.Nudge)
	}
	if strings.Contains(first.Nudge, "MULTI-AGENT DECOMPOSITION") {
		t.Fatal("delegation must not run before an inventory")
	}

	state.Iteration = 6
	second := reg.Fire(OnIterationStart, state, nil)
	if strings.Contains(second.Nudge, "MULTI-AGENT DECOMPOSITION") {
		t.Fatalf("single observed endpoint must not trigger generic delegation: %q", second.Nudge)
	}
}
