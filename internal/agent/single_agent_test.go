package agent

// single_agent_test.go — deterministic coverage for single-agent mode: the
// root/coordinator must perform the ENTIRE assessment with ZERO specialist
// agents. Every scenario below maps to the single-agent-mode contract:
// disabling every specialist must not reduce scope, evidence standards,
// plan completeness, or methodology. Specialists are optional acceleration
// only.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

// satisfyComprehensiveRecon seeds a fully-settled comprehensive recon state
// (validated dimensions) so tests can exercise post-recon behavior.
func satisfyComprehensiveRecon(state *ScanState) {
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DirBustingDone = true
	state.DirBustingUsedWordlist = true
	state.DetectedTechs["flask"] = true
	state.ReconCoverage.HTTPProbed = true
	state.ReconCoverage.TechFingerprinted = true
	state.ReconCoverage.Crawled = true
	state.ReconCoverage.ContentDiscoveredHosts["example.com"] = true
}

// fireExec runs one terminal command through BOTH attribution layers: the
// execute-time attempt recorder and the result-time completion validator.
func fireExec(state *ScanState, command, output string) {
	hookWorkTracker(state, map[string]string{"tool_name": "terminal_execute", "command": command})
	hookReconResultTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   command,
		"output":    output,
	})
}

// newDelegationTestAgent builds a minimal agent with a real spawn-capable
// registry, for tests that exercise delegation gating.
func newDelegationTestAgent(t *testing.T, cfg *config.Config, state *ScanState) *Agent {
	t.Helper()
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "lane exhausted", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)
	return &Agent{
		cfg:        cfg,
		registry:   registry,
		agentGraph: graph,
		state:      state,
		events:     make(chan Event, 16),
	}
}

// ── Delegation-disabled behavior (scenarios 1-5) ───────────────────────────

// Scenario 1: XALGORIX_DISABLE_AUTO_DELEGATE=true (DelegationEnabled=false)
// produces no spawn-agent nudge or reminder.
func TestSingleAgent_NoSpawnNudgeWhenDelegationDisabled(t *testing.T) {
	state := NewScanState()
	state.DelegationEnabled = false
	state.Iteration = 8
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.Plan = AutoPlan([]string{"/api/users"}, nil)
	state.PlanBuilt = true
	state.LedgerSeeded = true

	result := fireDirectives(t, state, hookDelegationCoordinator)
	if result.Nudge != "" || len(result.Directives) != 0 {
		t.Fatalf("single-agent mode must not receive a decomposition nudge: %q %+v", result.Nudge, result.Directives)
	}
	if state.DelegationNudgeFired {
		t.Fatal("single-agent mode must never mark a delegation nudge as fired")
	}

	// Even the reminder path (a fired-then-ignored nudge) is unreachable:
	// set the fired state manually and confirm no reminder is composed.
	state.DelegationNudgeFired = true
	again := fireDirectives(t, state, hookDelegationCoordinator)
	if again.Nudge != "" || len(again.Directives) != 0 {
		t.Fatalf("single-agent mode must not receive delegation reminders: %q", again.Nudge)
	}
}

// Scenario 2: with every specialist lane disabled, the coordinator produces
// no decomposition nudge, and the engine derives DelegationEnabled=false.
func TestSingleAgent_AllLanesDisabledDerivesSingleAgentMode(t *testing.T) {
	allDisabled := &config.Config{DisabledSpecialists: []string{
		"recon-discovery", "authz-logic", "business-logic", "injection-serverside", "client-source",
	}}
	state := NewScanState()
	a := newDelegationTestAgent(t, allDisabled, state)
	if a.delegationEnabled() {
		t.Fatal("all lanes operator-disabled must derive DelegationEnabled=false")
	}
	a2 := newDelegationTestAgent(t, &config.Config{}, state)
	if !a2.delegationEnabled() {
		t.Fatal("with lanes available and auto-delegation on, DelegationEnabled must be true")
	}
	a3 := newDelegationTestAgent(t, &config.Config{DisableAutoDelegate: true}, state)
	if a3.delegationEnabled() {
		t.Fatal("XALGORIX_DISABLE_AUTO_DELEGATE=true must derive DelegationEnabled=false")
	}
}

// Scenario 3: maybeAutoDelegate does not affect plan completeness when
// delegation is disabled — plan state is identical.
func TestSingleAgent_MaybeAutoDelegateLeavesPlanUntouchedWhenDisabled(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.Iteration = 8
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	state.LedgerSeeded = true
	before := len(state.Plan.Tasks)
	beforeIDs := planTaskIDs(state.Plan)

	a := newDelegationTestAgent(t, &config.Config{DisableAutoDelegate: true}, state)
	if msg := a.maybeAutoDelegate([]string{"https://example.com"}); msg != "" {
		t.Fatalf("delegation-disabled mode must not produce delegation output: %q", msg)
	}
	if len(state.Plan.Tasks) != before || strings.Join(beforeIDs, ",") != strings.Join(planTaskIDs(state.Plan), ",") {
		t.Fatal("maybeAutoDelegate must not alter plan completeness in single-agent mode")
	}
}

func planTaskIDs(p *Plan) []string {
	ids := make([]string, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		ids = append(ids, t.ID)
	}
	return ids
}

// Scenario 5: disabling specialists must not set state that falsely implies a
// wave executed or was attempted.
func TestSingleAgent_DisabledDoesNotFakeWaveState(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.Iteration = 8
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	state.LedgerSeeded = true

	a := newDelegationTestAgent(t, &config.Config{DisableAutoDelegate: true}, state)
	for i := 0; i < 2; i++ {
		if msg := a.maybeAutoDelegate([]string{"https://example.com"}); msg != "" {
			t.Fatalf("delegation-disabled mode must stay silent: %q", msg)
		}
	}
	if state.DelegationAttempted || state.WaveLaunched || state.ReconLaneLaunched {
		t.Fatalf("disabled config must never fake wave state: attempted=%v wave=%v reconLane=%v",
			state.DelegationAttempted, state.WaveLaunched, state.ReconLaneLaunched)
	}
	if state.DelegationDeferReason != "" {
		t.Fatalf("single-agent mode is not a defer state, got reason %q", state.DelegationDeferReason)
	}
	if !state.SingleAgentNoted {
		t.Fatal("the one-time single-agent notice should have been recorded")
	}
}

// ── Recon task completion (scenarios 6-9) ──────────────────────────────────

// Scenarios 6-7: one validated curl (or one whatweb) does not complete the
// recon plan task while substantial applicable recon remains.
func TestSingleAgent_SingleCommandDoesNotCompleteReconTask(t *testing.T) {
	for _, cmd := range []string{
		"curl -sk https://example.test/ -o tmp/index.html",
		"whatweb https://example.test",
	} {
		state := NewScanState()
		state.DiscoveredEndpoints = []string{"/api/users", "/admin/dashboard"}
		state.Plan = AutoPlan(state.DiscoveredEndpoints, nil)
		fireExec(state, cmd, "HTTP/1.1 200 OK")
		reconcilePlan(state)
		if state.Plan.Get("recon").Status == TaskCompleted {
			t.Fatalf("a single %q must not close the recon task while comprehensive recon is outstanding", cmd)
		}
		if ComprehensiveReconComplete(state) {
			t.Fatal("a single command must not satisfy the comprehensive predicate")
		}
	}
}

// Scenario 8: the recon task closes only when the comprehensive predicate is
// satisfied.
func TestSingleAgent_ReconTaskCompletesOnlyUnderComprehensivePredicate(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/", "/about"}
	state.Plan = AutoPlan(state.DiscoveredEndpoints, nil)
	state.ReconDone = true
	reconcilePlan(state)
	if state.Plan.Get("recon").Status == TaskCompleted {
		t.Fatal("ReconDone alone must not close the recon task")
	}
	satisfyComprehensiveRecon(state)
	reconcilePlan(state)
	if state.Plan.Get("recon").Status != TaskCompleted {
		t.Fatal("the recon task must complete under the comprehensive predicate")
	}
}

// Scenario 9: professional finish blocks while comprehensive recon is
// incomplete, and names the missing dimensions from the same generator.
func TestSingleAgent_ProfessionalFinishBlocksOnIncompleteRecon(t *testing.T) {
	state := NewScanState()
	state.ProfessionalAssessment = true
	state.ReconDone = true
	state.Iteration = 60
	state.TerminalCalls = 30
	state.MeaningfulTestCalls = 10
	state.PlanBuilt = true
	state.MaxFinishRejections = 15
	plan := NewPlan()
	plan.add(&Task{ID: "recon", Title: "Map live surface", Phase: 1, Status: TaskCompleted})
	plan.add(&Task{ID: "test-xss", Title: "Test routes", Phase: 6, VulnClass: "xss", Status: TaskCompleted})
	plan.add(&Task{ID: "report", Title: "Report", Phase: 22, Status: TaskCompleted})
	state.Plan = plan

	result := hookFinishGatekeeper(state, nil)
	if !result.Block || !strings.Contains(result.BlockReason, "Comprehensive reconnaissance is incomplete") {
		t.Fatalf("professional finish must enforce the comprehensive-recon predicate, got: %+v", result)
	}
	if !strings.Contains(result.BlockReason, "content discovery") || !strings.Contains(result.BlockReason, "technology stack detection") {
		t.Fatalf("the block must list the authoritative missing dimensions, got: %s", result.BlockReason)
	}
} // ── Failed tool execution (scenarios 10-14) ────────────────────────────────

// Scenario 10: a failed ffuf (binary missing) records the attempt but never
// completes content discovery.
func TestSingleAgent_FailedFfufDoesNotCompleteContentDiscovery(t *testing.T) {
	state := NewScanState()
	fireExec(state, "ffuf -w /usr/share/wordlists/common.txt -u https://example.test/FUZZ -mc 200",
		"bash: ffuf: command not found")
	if state.ReconCoverage.ContentDiscoveredHosts["example.test"] {
		t.Fatal("a failed ffuf must not complete per-host content discovery")
	}
	if state.DirBustingDone || state.DirBustingUsedWordlist {
		t.Fatal("a failed ffuf must not complete content discovery at all")
	}
	if !state.ReconCoverage.Attempted["content_discovery"] || state.ReconCoverage.FailedAttempts["content_discovery"] == 0 {
		t.Fatal("the attempt and the failure must both be recorded")
	}
}

// Scenario 11: an nmap run without a scan report (host down, no -Pn) and a
// missing binary both fail to complete service discovery.
func TestSingleAgent_FailedNmapDoesNotCompleteServiceDiscovery(t *testing.T) {
	for _, out := range []string{
		"bash: nmap: command not found",
		"Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn",
	} {
		state := NewScanState()
		fireExec(state, "nmap -sV example.test", out)
		if state.ReconCoverage.ServicesProbed {
			t.Fatalf("nmap output %q must not complete service discovery", out)
		}
		if !state.ReconCoverage.Attempted["service_discovery"] {
			t.Fatal("the attempt must still be recorded")
		}
	}
}

// Scenario 12: a failed arjun does not complete parameter discovery.
func TestSingleAgent_FailedArjunDoesNotCompleteParameterDiscovery(t *testing.T) {
	state := NewScanState()
	fireExec(state, "arjun -u https://example.test/api/users", "bash: arjun: command not found")
	if state.ReconCoverage.ParamDiscovered {
		t.Fatal("a failed arjun must not complete parameter discovery")
	}
	if state.ReconCoverage.FailedAttempts["parameter_discovery"] == 0 {
		t.Fatal("the failed parameter-discovery attempt must be counted")
	}
}

// Scenario 13: a crawler that could not connect does not complete crawling.
func TestSingleAgent_FailedCrawlDoesNotCompleteCrawling(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/robots.txt",
		"curl: (7) Failed to connect to example.test port 443: Connection refused")
	if state.ReconCoverage.Crawled {
		t.Fatal("a refused robots.txt fetch must not complete crawling")
	}
}

// Scenario 14: a valid-negative ffuf run (genuinely completed, zero findings)
// DOES complete content discovery — valid negatives count.
func TestSingleAgent_ValidNegativeScanCounts(t *testing.T) {
	state := NewScanState()
	fireExec(state, "ffuf -w /usr/share/wordlists/common.txt -u https://example.test/FUZZ -mc 200",
		"Progress: 100/100 :: Status: 404")
	if !state.ReconCoverage.ContentDiscoveredHosts["example.test"] || !state.DirBustingDone {
		t.Fatal("a genuinely completed empty scan must count as coverage")
	}
	if !state.DirBustingUsedWordlist {
		t.Fatal("the -w flag plus a valid result must satisfy the wordlist signal")
	}
}

// ── API mapping (scenarios 15-17) ───────────────────────────────────────────

// Scenario 15: a 404 on /swagger.json is an attempt, not API mapping.
func TestSingleAgent_Swagger404DoesNotCompleteAPIMapping(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/swagger.json",
		"HTTP/1.1 404 Not Found\n"+`{"error":"not found"}`)
	if state.ReconCoverage.APISurfaceDiscovered {
		t.Fatal("a 404 probe must not complete API mapping")
	}
	if !state.ReconCoverage.Attempted["api_surface"] {
		t.Fatal("the API attempt must be recorded")
	}
}

// Scenario 16: a parsed OpenAPI document completes API mapping.
func TestSingleAgent_ParsedOpenAPIDocumentsCompleteAPIMapping(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/openapi.json",
		`{"openapi":"3.0.0","info":{"title":"API"},"paths":{"/users":{"get":{"operationId":"listUsers"}}}}`)
	if !state.ReconCoverage.APISurfaceDiscovered {
		t.Fatal("a parsed OpenAPI document must complete API mapping")
	}
}

// Scenario 17: a confirmed GraphQL introspection response completes API
// mapping and settles the API-surface obligation.
func TestSingleAgent_GraphQLIntrospectionSettlesAPIMapping(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/graphql"}
	if !apiSignalsExist(state) {
		t.Fatal("setup: a /graphql inventory path must set API signals")
	}
	fireExec(state, "curl -sk https://example.test/graphql -d x", `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	if !state.ReconCoverage.APISurfaceDiscovered {
		t.Fatal("a confirmed GraphQL schema response must complete API mapping")
	}
}

// ── JavaScript analysis (scenarios 18-20) ───────────────────────────────────

// Scenario 18: first-party bundles make JS analysis applicable, and it is
// owed before recon completes.
func TestSingleAgent_FirstPartyJSMakesJSAnalysisApplicable(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredEndpoints = []string{"/", "/static/js/app.js"}
	if !jsAnalysisApplicable(state) {
		t.Fatal("a first-party bundle path must make JS analysis applicable")
	}
	missing := ComprehensiveReconMissing(state)
	if !strings.Contains(strings.Join(missing, ";"), "JavaScript analysis") {
		t.Fatalf("JS analysis must be owed when first-party JS exists, got %v", missing)
	}
}

// Scenario 19: crawling alone does not bypass applicable JS analysis.
func TestSingleAgent_CrawlingDoesNotBypassJSAnalysis(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state) // includes rc.Crawled = true
	state.DiscoveredEndpoints = []string{"/", "/static/js/app.js"}
	if ComprehensiveReconComplete(state) {
		t.Fatal("crawl-complete must not satisfy recon while JS analysis is applicable and outstanding")
	}
	fireExec(state, "curl -sk https://example.test/static/js/app.js -o tmp/app.js",
		"webpackChunk: fetch('/api/orders')")
	if !state.ReconCoverage.JSAnalyzed {
		t.Fatal("a validated JS analysis must settle the JS dimension")
	}
	// The validated JS result ENRICHES the structured surface: the bundle's
	// fetch('/api/orders') promotes /api/orders with provenance "js", which
	// legitimately creates a NEW API-mapping obligation. Completeness is
	// evaluated against the CURRENT surface, never the stale one.
	found := false
	for _, ep := range state.DiscoveredEndpoints {
		if ep == "/api/orders" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a JS-extracted API route must enter the structured surface, got %v", state.DiscoveredEndpoints)
	}
	missing := ComprehensiveReconMissing(state)
	assertAny(t, missing, "API-surface")
}

// Scenario 20: with no first-party JS observed, a typed N/A disposition is
// legitimate and accepted.
func TestSingleAgent_NoJSAllowsLegitimateNADisposition(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	if jsAnalysisApplicable(state) {
		t.Fatal("with no first-party JS evidence the dimension is not applicable")
	}
	if !MarkReconDimensionNA(state, "js_analysis") {
		t.Fatal("the js_analysis N/A disposition must be accepted")
	}
	missing := ComprehensiveReconMissing(state)
	if strings.Contains(strings.Join(missing, ";"), "JavaScript analysis") {
		t.Fatalf("N/A disposition must clear the JS demand, got %v", missing)
	}
}

// ── Auth mapping (scenarios 21-23) ─────────────────────────────────────────

// Scenario 21: a 404 on /login is only an attempt — auth mapping is not
// complete without evidence the auth surface exists.
func TestSingleAgent_Login404IsNotAuthMapping(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/login",
		"HTTP/1.1 404 Not Found\n"+`{"error":"not found"}`)
	if state.ReconCoverage.AuthMapped == "complete" {
		t.Fatal("a 404 on /login must not complete auth mapping")
	}
}

// Scenario 22: no credentials does NOT excuse auth surface mapping — mapping
// can complete without credentials; authenticated testing blocks separately.
func TestSingleAgent_AuthMappingSeparateFromCredentials(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredEndpoints = []string{"/", "/login"}
	state.AuthContextAvailable = false
	missing := ComprehensiveReconMissing(state)
	if !strings.Contains(strings.Join(missing, ";"), "auth surface mapping") {
		t.Fatal("a discovered auth surface must still require mapping without credentials")
	}
	// Mapping completes from evidence (a live login response + cookie),
	// with no credentials involved.
	fireExec(state, "curl -sk https://example.test/login",
		"HTTP/1.1 200 OK\nSet-Cookie: session=abc; HttpOnly")
	if state.ReconCoverage.AuthMapped != "complete" {
		t.Fatal("live auth-surface evidence must complete auth mapping without credentials")
	}
	missing = ComprehensiveReconMissing(state)
	if strings.Contains(strings.Join(missing, ";"), "auth surface mapping") {
		t.Fatalf("auth mapping demand must settle after evidence, got %v", missing)
	}
}

// Scenario 23: reset/OAuth/MFA surfaces are part of auth mapping.
func TestSingleAgent_DiscoveredAuthSurfacesActivateMapping(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/", "/password-reset", "/oauth/authorize", "/account/mfa"}
	if !authSurfaceExists(state) {
		t.Fatal("reset/OAuth/MFA surfaces must activate auth mapping")
	}
} // ── Parameter discovery (scenarios 24-27) ──────────────────────────────────

func TestSingleAgent_ParameterDiscoverySignals(t *testing.T) {
	// Scenario 24: an HTML form in a tool result activates it.
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/search",
		`<html><body><form action="/search" method="get"><input name="q"></form>`)
	if !state.FormsObserved || !parameterizedSurfaceExists(state) {
		t.Fatal("observed HTML forms must activate parameter discovery")
	}

	// Scenario 25: a query string in the inventory activates it.
	state = NewScanState()
	state.DiscoveredEndpoints = []string{"/", "/search?q=old"}
	if !parameterizedSurfaceExists(state) {
		t.Fatal("an observed query string must activate parameter discovery")
	}

	// Scenario 26: OpenAPI-seeded parameters activate it.
	state = NewScanState()
	state.SeededSurface = []SeededSurfaceEndpoint{{Path: "/api/users", Method: "GET", Params: []string{"id"}}}
	if !parameterizedSurfaceExists(state) {
		t.Fatal("seeded parameters must activate parameter discovery")
	}

	// Scenario 27: a state-changing route activates it.
	state = NewScanState()
	recordEndpointMethod(state, "/api/orders", "PUT")
	if !parameterizedSurfaceExists(state) {
		t.Fatal("a state-changing route must activate parameter discovery")
	}
}

// ── Scope-aware subdomain discovery (scenarios 28-30) ───────────────────────

// Scenario 28: an explicit single-host scope does not owe subdomain
// enumeration; a typed N/A is also accepted for the record.
func TestSingleAgent_SingleHostScopeSkipsSubdomainEnumeration(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.com"}
	if subdomainScopeApplicable(state) {
		t.Fatal("a single explicit host must not owe subdomain enumeration")
	}
	if !MarkReconDimensionNA(state, "subdomain_discovery") {
		t.Fatal("the subdomain_discovery N/A disposition must be accepted")
	}
	missing := ComprehensiveReconMissing(state)
	if strings.Contains(strings.Join(missing, ";"), "subdomain") {
		t.Fatalf("single-host scope must not demand subdomain work, got %v", missing)
	}
}

// Scenario 29: a domain or wildcard scope requires DNS + subdomain
// enumeration + live-host probing.
func TestSingleAgent_DomainScopeRequiresSubdomainEnumeration(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.ScanTargets = []string{"example.com"}
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if !strings.Contains(missing, "subdomain enumeration") {
		t.Fatalf("a domain scope must demand subdomain enumeration, got %s", missing)
	}
	if !strings.Contains(missing, "DNS resolution") {
		t.Fatalf("a domain scope must demand DNS resolution, got %s", missing)
	}
}

// Scenario 30: discovered live subdomains enter the structured host inventory
// and inherit content-discovery obligations.
func TestSingleAgent_DiscoveredSubdomainsEnterHostInventory(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.ScanTargets = []string{"example.com"}
	fireExec(state, "subfinder -d example.com", "app.example.com\napi.example.com\nstaging.example.com")
	if !state.ReconCoverage.SubdomainEnumerated {
		t.Fatal("a validated subfinder run must complete subdomain enumeration")
	}
	for _, host := range []string{"app.example.com", "api.example.com", "staging.example.com"} {
		if !state.DiscoveredHosts[host] {
			t.Fatalf("discovered subdomain %s must enter the host inventory", host)
		}
	}
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if !strings.Contains(missing, "content discovery on api.example.com") {
		t.Fatalf("discovered live subdomains must inherit content-discovery obligations, got %s", missing)
	}
}

// ── Multi-host (scenarios 31-33) ───────────────────────────────────────────

// Scenario 31: content discovery on the app host does not complete the api host.
func TestSingleAgent_ContentDiscoveryIsPerApplicationHost(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredEndpoints = []string{"https://app.example.com/", "https://api.example.com/v1/users"}
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if !strings.Contains(missing, "content discovery on api.example.com") {
		t.Fatalf("per-application coverage must demand the api host, got %s", missing)
	}
}

// Scenario 32: a typed covered-by-equivalent-app disposition settles a host.
func TestSingleAgent_EquivalentAppDispositionSettlesHost(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredEndpoints = []string{"https://app.example.com/", "https://api.example.com/v1/users"}
	applied := applyReconDispositions(state, "host api.example.com: covered_by_equivalent_app (api.example.com serves the same backend vhost as app.example.com)")
	if len(applied) == 0 {
		t.Fatal("the host disposition must be applied")
	}
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if strings.Contains(missing, "content discovery on api.example.com") {
		t.Fatalf("covered_by_equivalent_app must settle the host, got %s", missing)
	}
}

// Scenario 33: bare discovered hostnames are not lost for lacking https://.
func TestSingleAgent_BareHostnamesAreNotLost(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredHosts["files.example.com"] = true
	hosts := distinctApplicationHosts(state)
	found := false
	for _, h := range hosts {
		if h == "files.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bare hostnames must appear in the application inventory, got %v", hosts)
	}
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if !strings.Contains(missing, "content discovery on files.example.com") {
		t.Fatalf("bare hostnames must inherit content-discovery obligations, got %s", missing)
	}
}

// ── Deep mode (scenarios 34-36) ────────────────────────────────────────────

// Scenario 34: a deep scan owes service discovery (when unsettled).
func TestSingleAgent_DeepScanRequiresServiceDiscovery(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DeepReconRequired = true
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if !strings.Contains(missing, "service/port enumeration") {
		t.Fatalf("deep mode must require service discovery, got %s", missing)
	}
}

// Scenario 35: a standard scan does not inherit deep obligations.
func TestSingleAgent_StandardScanSkipsDeepObligations(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DeepReconRequired = false
	missing := strings.Join(ComprehensiveReconMissing(state), ";")
	if strings.Contains(missing, "service/port enumeration") || strings.Contains(missing, "deep mode") {
		t.Fatalf("standard mode must not inherit deep obligations, got %s", missing)
	}
	if !ComprehensiveReconComplete(state) {
		t.Fatalf("a settled standard scan must be complete, got %v", ComprehensiveReconMissing(state))
	}
} // ── Plan refresh (scenarios 4, 37-41) ──────────────────────────────────────

// Scenarios 37-41: the root plan is built from an early inventory, then
// refreshed by the PLANNER on every surface revision — upload, checkout, and
// GraphQL endpoints discovered later add their tasks, with ZERO specialists.
func TestSingleAgent_PlanRefreshIndependentOfDelegation(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DetectedTechs["flask"] = true
	state.DelegationEnabled = false // single-agent mode for the whole test
	// The notes accessor is keyed by the scan-context id (production always
	// has one); any non-empty id works with the stub below.
	state.ScanContextID = "single-agent-refresh-test"

	// The endpoint inventory note is the authoritative surface source the
	// planner re-extracts every iteration (exactly as production does).
	inventory := "## Discovered Endpoints\n- /api/users\n"
	prevAccessor := notesBlobForContext
	notesBlobForContext = func(string) string { return inventory }
	t.Cleanup(func() { notesBlobForContext = prevAccessor })

	// 37: the early inventory builds the plan.
	fireDirectives(t, state, hookPlanner)
	if !state.PlanBuilt || state.Plan == nil {
		t.Fatal("an early inventory must build the root plan")
	}
	if state.PlanSurfaceRevision == "" {
		t.Fatal("the plan must remember the surface revision it was built from")
	}
	if state.Plan.Get("test-file-upload") != nil {
		t.Fatal("no upload task before an upload surface exists")
	}

	// 38: a later upload endpoint adds the file-upload task.
	inventory += "- /upload\n"
	fireDirectives(t, state, hookPlanner)
	if state.Plan.Get("test-file-upload") == nil {
		t.Fatal("a discovered upload endpoint must add the file-upload task via planner refresh")
	}

	// 39: a later checkout endpoint adds business-logic and race tasks.
	inventory += "- /checkout\n"
	fireDirectives(t, state, hookPlanner)
	if state.Plan.Get("test-business-logic") == nil || state.Plan.Get("test-race-conditions") == nil {
		t.Fatal("a discovered workflow endpoint must add business-logic and race tasks via planner refresh")
	}

	// 40: a later GraphQL endpoint adds the GraphQL task.
	inventory += "- /graphql\n"
	fireDirectives(t, state, hookPlanner)
	if state.Plan.Get("test-graphql") == nil {
		t.Fatal("a discovered GraphQL endpoint must add the GraphQL task via planner refresh")
	}

	// 41: the whole refresh ran with zero specialists.
	if state.DelegationAttempted || state.WaveLaunched || state.ReconLaneLaunched {
		t.Fatal("plan refresh must not require or fake any specialist activity")
	}
	// The auto-N/A auth disposition survives refreshes (no auth surface).
	if state.Plan.Get("auth-session") == nil || state.Plan.Get("auth-session").Status != TaskSkipped {
		t.Fatal("refresh must re-derive the auth-session N/A for an authless surface")
	}
}

// ── Part 18 consumer: adaptive finish does not punish a disabled wave ──────

// A scan that disabled delegation must not inherit the +40 iteration
// requirement that only applies when a specialist wave actually ran.
func TestSingleAgent_DelegationAttemptedMislabelDoesNotInflateAdaptiveFinish(t *testing.T) {
	base := func() *ScanState {
		s := NewScanState()
		s.Iteration = 40
		s.TerminalCalls = 50
		s.ReconDone = true
		s.EndpointInventorySaved = true
		s.ReconCoverage.HTTPProbed = true
		s.ReconCoverage.TechFingerprinted = true
		s.ReconCoverage.Crawled = true
		for i := 0; i < 6; i++ {
			s.EndpointsTested[fmt.Sprintf("/e%d", i)] = true
		}
		for i := 0; i < 5; i++ {
			s.InjectionEndpoints[fmt.Sprintf("/e%d", i)] = true
			s.AccessControlEndpoints[fmt.Sprintf("/e%d", i)] = true
		}
		s.DirBustingHosts["example.test"] = true
		s.ReconCoverage.ContentDiscoveredHosts["example.test"] = true
		return s
	}

	// A wave that never ran (single-agent mode): adaptive fast path open.
	solo := base()
	solo.DelegationAttempted = false
	solo.WaveLaunched = false
	if result := hookFinishGatekeeper(solo, nil); result.Block {
		t.Fatalf("single-agent scan must not inherit the wave iteration boost: %s", result.BlockReason)
	}

	// Regression guard: even a stale DelegationAttempted=true (which older
	// code set for DISABLED configs) must not trigger the boost — only a
	// real wave (WaveLaunched) does.
	mislabeled := base()
	mislabeled.DelegationAttempted = true
	mislabeled.WaveLaunched = false
	if result := hookFinishGatekeeper(mislabeled, nil); result.Block {
		t.Fatalf("DelegationAttempted without a real wave must not inflate iteration requirements: %s", result.BlockReason)
	}

	// A scan whose wave really did run keeps the stricter floor.
	wave := base()
	wave.WaveLaunched = true
	if result := hookFinishGatekeeper(wave, nil); !result.Block {
		t.Fatal("a scan with a real specialist wave must keep the stricter adaptive floor")
	}
}

// ── Part 27: task-driven root skill loading ─────────────────────────────────

// With zero specialists, the next plan lane — not just technology detection —
// must surface its methodology for the root.
func TestSingleAgent_NextLaneSkillRecommendations(t *testing.T) {
	state := NewScanState()
	satisfyComprehensiveRecon(state)
	state.DiscoveredEndpoints = []string{"/users", "/about"}
	state.Plan = AutoPlanFromState(state)
	reconcilePlan(state) // recon + dirbust complete -> class tasks become ready
	recs := recommendedSkillsForState(state)
	if len(recs) == 0 {
		t.Fatal("the ready plan lanes must surface methodology skills for the root")
	}
	found := false
	for _, rec := range recs {
		if strings.Contains(rec.Reason, "next plan lane") {
			found = true
		}
	}
	if !found {
		t.Fatalf("at least one recommendation must come from the ready plan lanes, got %v", recs)
	}
}

// ── Part 19: root-owned deep recon duties ───────────────────────────────────

// The deep-recon playbook previously carried only by the recon-discovery
// specialist must reach the root as applicability-scoped directives.
func TestSingleAgent_DeepReconDirectorGivesRootTheSpecialistPlaybook(t *testing.T) {
	state := NewScanState()
	state.Iteration = 6
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"/", "/static/js/app.js", "/api/users", "/login", "/search?q=old"}
	result := fireDirectives(t, state, hookDeepReconDirector)
	if result.Nudge == "" {
		t.Fatal("outstanding dimensions must produce a root recon directive")
	}
	for _, duty := range []string{".git", "sourceMappingURL", "introspection", "arjun/x8"} {
		if !strings.Contains(result.Nudge, duty) {
			t.Fatalf("root recon directive must carry the deep-recon duty %q, got: %s", duty, result.Nudge)
		}
	}
	// The directive stops once recon is settled: the surface above carries
	// JS/API/auth/parameter signals, so those dimensions must settle too.
	satisfyComprehensiveRecon(state)
	state.ReconCoverage.JSAnalyzed = true
	state.ReconCoverage.APISurfaceDiscovered = true
	state.ReconCoverage.AuthMapped = "complete"
	markAuthFlowMapped(state, "login")
	state.ReconCoverage.ParamDiscovered = true
	if !ComprehensiveReconComplete(state) {
		t.Fatalf("setup: expected settled recon, missing %v", ComprehensiveReconMissing(state))
	}
	if done := fireDirectives(t, state, hookDeepReconDirector); done.Nudge != "" {
		t.Fatal("the director must stop once comprehensive recon is complete")
	}
}

// ── Part 31: run comparison — equivalent required methodology ──────────────

// The required methodology must derive from the surface, never from the
// specialist configuration: with identical surface, specialist-enabled and
// specialist-disabled scans owe the same work.
func TestSingleAgent_RequiredMethodologyEquivalentWithAndWithoutSpecialists(t *testing.T) {
	build := func(t *testing.T, delegationEnabled bool) *ScanState {
		_, s := newTestCtxState(t)
		s.DelegationEnabled = delegationEnabled
		s.DeepReconRequired = true
		s.ScanTargets = []string{"example.com"}
		s.DiscoveredEndpoints = []string{
			"app.example.com/", "app.example.com/login", "app.example.com/static/js/app.js",
			"app.example.com/api/users", "app.example.com/graphql", "app.example.com/checkout",
		}
		s.FormsObserved = true
		s.DetectedTechs["flask"] = true
		return s
	}
	enabled := build(t, true)
	disabled := build(t, false)

	// Same plan scope (task IDs).
	planA, planB := AutoPlanFromState(enabled), AutoPlanFromState(disabled)
	idsA, idsB := planTaskIDs(planA), planTaskIDs(planB)
	if strings.Join(idsA, ",") != strings.Join(idsB, ",") {
		t.Fatalf("plan scope must be identical with and without specialists:\nA: %v\nB: %v", idsA, idsB)
	}

	// Same recon obligations (one authoritative generator) — also scenario
	// 36: deep behavior is independent of specialist state.
	missingA, missingB := ComprehensiveReconMissing(enabled), ComprehensiveReconMissing(disabled)
	if strings.Join(missingA, ";") != strings.Join(missingB, ";") {
		t.Fatalf("recon obligations must be identical:\nA: %v\nB: %v", missingA, missingB)
	}

	// Same applicability per endpoint.
	for _, ep := range enabled.DiscoveredEndpoints {
		ca := ApplicableClassesForEndpoint(enabled, ep)
		cb := ApplicableClassesForEndpoint(disabled, ep)
		if strings.Join(ca, ",") != strings.Join(cb, ",") {
			t.Fatalf("applicable classes for %s must be identical: %v vs %v", ep, ca, cb)
		}
	}

	// Same hypothesis ledger scope.
	la, lb := ledgerForState(enabled), ledgerForState(disabled)
	seedLedgerFromPlan(enabled, la)
	seedLedgerFromPlan(disabled, lb)
	if la.Len() != lb.Len() {
		t.Fatalf("hypothesis scope must be identical, got %d vs %d", la.Len(), lb.Len())
	}
	setOf := func(l *scanctx.LedgerStore) map[string]bool {
		out := map[string]bool{}
		for _, h := range l.All() {
			out[h.VulnClass+"|"+h.Endpoint] = true
		}
		return out
	}
	sa, sb := setOf(la), setOf(lb)
	for h := range sa {
		if !sb[h] {
			t.Fatalf("specialist-enabled scan must not own unique methodology: %q missing from single-agent scope", h)
		}
	}
}

// Single-agent mode: the system prompt must not instruct the root to spawn
// a disabled wave — it names the single-agent contract instead.
func TestSingleAgent_SystemPromptHasNoCoordinatorSection(t *testing.T) {
	registry := tools.NewRegistry()
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	graph.Register(registry)

	solo := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2, Checklist: "professional", DisableAutoDelegate: true},
		registry: registry,
	}
	prompt := solo.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	if strings.Contains(prompt, "Multi-Agent Coordinator") {
		t.Fatal("single-agent mode must not instruct the root to spawn a coordinator wave")
	}
	if !strings.Contains(prompt, "Single-Agent Mode (specialists disabled)") {
		t.Fatal("single-agent mode must name the single-agent contract")
	}

	// Enabled mode keeps the coordinator contract.
	multi := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2, Checklist: "professional"},
		registry: registry,
	}
	multiPrompt := multi.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	if !strings.Contains(multiPrompt, "## Multi-Agent Coordinator") {
		t.Fatal("delegation-enabled scans keep the multi-agent coordinator contract")
	}
}
