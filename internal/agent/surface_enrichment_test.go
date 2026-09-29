// Package agent - surface_enrichment_test.go: deterministic regression
// coverage for the black-box surface-enrichment contract. Every scenario maps
// to the spec matrix: methods, content types, parameters, mixed plans, typed
// dispositions, single-agent enforcement, crawl/JS validation, auth flows,
// domain scope, host ranking, lane skills, and plan freshness. The root agent
// must never miss work because the structured surface was enriched after the
// initial plan was created.
package agent

import (
	"strings"
	"testing"
)

func containsClass(got []string, want string) bool {
	for _, c := range got {
		if c == want {
			return true
		}
	}
	return false
}

func endpointInInventory(state *ScanState, endpoint string) bool {
	for _, ep := range state.DiscoveredEndpoints {
		if ep == endpoint {
			return true
		}
		for _, a := range endpointCoverageAliases(ep) {
			for _, b := range endpointCoverageAliases(endpoint) {
				if a == b {
					return true
				}
			}
		}
	}
	return false
}

func fireTerminal(state *ScanState, command string) {
	hookWorkTracker(state, map[string]string{"tool_name": "terminal_execute", "command": command})
}

// ── Methods (spec 1-4) ───────────────────────────────────────────────────────

// GET first + POST later: both remain visible.
func TestSurfaceMethods_GETThenPOSTKeepsBoth(t *testing.T) {
	state := NewScanState()
	recordEndpointMethod(state, "example.test/orders", "GET")
	recordEndpointMethod(state, "example.test/orders", "POST")
	methods := sortedObservedMethods(state, "example.test/orders")
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		t.Fatalf("GET then POST must retain both methods, got %v", methods)
	}
	se := buildSurfaceEndpoint(state, "example.test/orders")
	if !se.hasMethod("GET") || !se.hasMethod("POST") {
		t.Fatalf("the surface endpoint must expose both methods, got %v", se.Methods)
	}
}

// POST first + GET later: both remain visible (order independence).
func TestSurfaceMethods_POSTThenGETKeepsBoth(t *testing.T) {
	state := NewScanState()
	recordEndpointMethod(state, "example.test/orders", "POST")
	recordEndpointMethod(state, "example.test/orders", "GET")
	methods := sortedObservedMethods(state, "example.test/orders")
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		t.Fatalf("POST then GET must retain both methods, got %v", methods)
	}
}

// PATCH observed after GET activates the state-changing obligations.
func TestSurfaceMethods_PATCHActivatesStateChangingClasses(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.test/users/123"}
	recordEndpointMethod(state, "example.test/users/123", "GET")
	got := ApplicableClassesForEndpoint(state, "example.test/users/123")
	for _, banned := range []string{"csrf", "business-logic", "race-conditions", "mass-assignment"} {
		if containsClass(got, banned) {
			t.Fatalf("a bare GET must not activate %s, got %v", banned, got)
		}
	}
	recordEndpointMethod(state, "example.test/users/123", "PATCH")
	got = ApplicableClassesForEndpoint(state, "example.test/users/123")
	for _, want := range []string{"csrf", "business-logic", "race-conditions", "mass-assignment"} {
		if !containsClass(got, want) {
			t.Fatalf("PATCH observed later must activate %s, got %v", want, got)
		}
	}
}

// Method enrichment changes the surface revision.
func TestSurfaceRevision_MethodEnrichmentChangesRevision(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.test/orders"}
	rev := surfaceRevision(state)
	recordEndpointMethod(state, "example.test/orders", "POST")
	if surfaceRevision(state) == rev {
		t.Fatal("observing a new method on an existing endpoint must change the surface revision")
	}
}

// ── Content types (spec 5-8) ─────────────────────────────────────────────────

// An existing endpoint later observed with application/xml activates XXE.
func TestSurfaceContentTypes_XMLOnExistingEndpointActivatesXXE(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.test/api/import"}
	rev := surfaceRevision(state)
	recordEndpointContentType(state, "example.test/api/import", "application/xml")
	if surfaceRevision(state) == rev {
		t.Fatal("content-type enrichment must change the surface revision")
	}
	if got := ApplicableClassesForEndpoint(state, "example.test/api/import"); !containsClass(got, "xxe") {
		t.Fatalf("XML observed on an existing endpoint must activate XXE, got %v", got)
	}
}

// JSON on an existing endpoint activates NoSQLi.
func TestSurfaceContentTypes_JSONActivatesNoSQLi(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.test/api/users"}
	recordEndpointContentType(state, "example.test/api/users", "application/json")
	if got := ApplicableClassesForEndpoint(state, "example.test/api/users"); !containsClass(got, "nosqli") {
		t.Fatalf("JSON observed on an existing endpoint must activate NoSQLi, got %v", got)
	}
}

// Multipart activates file-upload.
func TestSurfaceContentTypes_MultipartActivatesFileUpload(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"example.test/api/profile"}
	recordEndpointContentType(state, "example.test/api/profile", "multipart/form-data")
	if got := ApplicableClassesForEndpoint(state, "example.test/api/profile"); !containsClass(got, "file-upload") {
		t.Fatalf("multipart must activate file-upload, got %v", got)
	}
}

// ── Parameters (spec 9-12) ──────────────────────────────────────────────────

// GET /fetch?url= observed at runtime enters the structured surface and
// activates SSRF + open-redirect applicability.
func TestSurfaceParams_URLParamActivatesSSRFAndRedirect(t *testing.T) {
	state := NewScanState()
	fireTerminal(state, "curl -sk \"https://example.test/fetch?url=https://example.com\"")
	if !endpointInInventory(state, "example.test/fetch") {
		t.Fatalf("observed traffic must promote the endpoint into the inventory, got %v", state.DiscoveredEndpoints)
	}
	params := state.ObservedEndpointParameters["example.test/fetch"]
	found := false
	for _, p := range params {
		if p.Name == "url" && p.Location == "query" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the url query parameter must be recorded, got %v", params)
	}
	got := ApplicableClassesForEndpoint(state, "example.test/fetch")
	if !containsClass(got, "ssrf") || !containsClass(got, "open-redirect") {
		t.Fatalf("a ?url= parameter must activate SSRF and open-redirect, got %v", got)
	}
}

// GET /download?file= activates path traversal.
func TestSurfaceParams_FileParamActivatesTraversal(t *testing.T) {
	state := NewScanState()
	fireTerminal(state, "curl -sk \"https://example.test/download?file=report.pdf\"")
	got := ApplicableClassesForEndpoint(state, "example.test/download")
	if !containsClass(got, "path_traversal") {
		t.Fatalf("a ?file= parameter must activate path traversal, got %v", got)
	}
}

// A JSON body with a role field activates mass-assignment/privilege testing;
// user_id activates object authorization.
func TestSurfaceParams_JSONBodyParamsActivateClasses(t *testing.T) {
	state := NewScanState()
	fireTerminal(state, "curl -sk -X PATCH https://example.test/api/user -H \"Content-Type: application/json\" -d '{\"user_id\":123,\"role\":\"user\"}'")
	got := ApplicableClassesForEndpoint(state, "example.test/api/user")
	for _, want := range []string{"mass-assignment", "privilege-escalation", "idor"} {
		if !containsClass(got, want) {
			t.Fatalf("JSON role/user_id fields must activate %s, got %v", want, got)
		}
	}
}

// Form fields observed in an HTML result attach to the form action endpoint.
func TestSurfaceParams_FormFieldsAttachToActionEndpoint(t *testing.T) {
	state := NewScanState()
	hookReconResultTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   "curl -s https://example.test/login",
		"output":    "<form action=\"/login\" method=\"POST\"><input name=\"username\"><input name=\"password\"></form>",
	})
	if !state.FormsObserved {
		t.Fatal("form evidence must set FormsObserved")
	}
	params := state.ObservedEndpointParameters["/login"]
	if len(params) < 2 {
		t.Fatalf("form fields must attach to the form action endpoint, got %v", params)
	}
	if !parameterizedSurfaceExists(state) {
		t.Fatal("form evidence must make input discovery applicable")
	}
}

// Parameters observed after plan creation trigger a plan refresh that adds
// the newly applicable engine obligations (spec 13).
func TestSurfaceParams_EnrichmentAfterPlanAddsObligations(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"example.test/fetch"}
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	state.PlanSurfaceRevision = surfaceRevision(state)
	if state.Plan.Get("test-open-redirect") != nil {
		t.Fatal("setup: no open-redirect obligation may exist yet")
	}
	// Later black-box observation: GET /fetch?url=...
	fireTerminal(state, "curl -sk \"https://example.test/fetch?url=https://example.com\"")
	refreshPlanForSurface(state)
	if state.Plan.Get("test-open-redirect") == nil {
		t.Fatal("a ?url= parameter observed after plan creation must add the open-redirect obligation")
	}
	if state.PlanSurfaceRevision != surfaceRevision(state) {
		t.Fatal("the refresh must absorb the new surface revision")
	}
}

// Parameter-specific hypotheses are seeded (spec 14).
func TestSurfaceParams_ParameterHypothesesSeeded(t *testing.T) {
	_, state := newTestCtxState(t)
	state.DiscoveredEndpoints = []string{"example.test/fetch", "example.test/download"}
	RecordSurfaceObservation(state, SurfaceObservation{
		Endpoint:   "example.test/fetch",
		Parameters: []SurfaceParameter{{Name: "url", Location: "query"}},
	})
	RecordSurfaceObservation(state, SurfaceObservation{
		Endpoint:   "example.test/download",
		Parameters: []SurfaceParameter{{Name: "file", Location: "query"}},
	})
	l := ledgerForState(state)
	if l == nil {
		t.Fatal("setup: ledger must be reachable")
	}
	if n := seedParamHypotheses(state, l); n < 3 {
		t.Fatalf("url+file parameters must seed SSRF/open-redirect/traversal hypotheses, got %d", n)
	}
	// Idempotent: re-seeding creates no duplicates.
	if n := seedParamHypotheses(state, l); n != 0 {
		t.Fatalf("re-seeding must be idempotent, added %d duplicates", n)
	}
}

// ── Mixed plans (spec 15-18) ────────────────────────────────────────────────

func newMixedPlanState(t *testing.T) (*ScanState, *Task) {
	t.Helper()
	state := NewScanState()
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"example.test/api/users"}
	state.Plan = AutoPlanFromState(state)
	custom := &Task{
		ID:     "custom-jwt-review",
		Title:  "Check JWT claims on /api/users",
		Phase:  6,
		Status: TaskActive,
		Origin: "llm",
		Notes:  "custom model task",
	}
	state.Plan.add(custom)
	state.PlanBuilt = true
	state.PlanSurfaceRevision = surfaceRevision(state)
	return state, custom
}

// A custom LLM task + later upload discovery still gets the engine
// file-upload task; no custom task is deleted; no engine task is duplicated.
func TestMixedPlan_LaterUploadDiscoveryAddsEngineTask(t *testing.T) {
	state, custom := newMixedPlanState(t)
	if planIsEngineAuthored(state.Plan) {
		t.Fatal("setup: the plan is mixed")
	}
	if !planHasEngineTasks(state.Plan) {
		t.Fatal("setup: the plan contains engine tasks")
	}
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "example.test/upload")
	if added := MergeRequiredEngineTasks(state, state.Plan); added == 0 {
		t.Fatal("upload discovery must add missing engine tasks to the mixed plan")
	}
	if state.Plan.Get("test-file-upload") == nil {
		t.Fatal("upload discovery must add the engine file-upload task")
	}
	if state.Plan.Get("custom-jwt-review") != custom {
		t.Fatal("no custom LLM task may be deleted by the merge")
	}
	if custom.Status != TaskActive {
		t.Fatal("the custom task must keep its status")
	}
	dup := 0
	for _, task := range state.Plan.Tasks {
		if task.ID == "test-sqli" {
			dup++
		}
	}
	if dup != 1 {
		t.Fatalf("merge must not duplicate engine tasks, got %d test-sqli tasks", dup)
	}
	// Idempotent: merging again adds nothing.
	if n := MergeRequiredEngineTasks(state, state.Plan); n != 0 {
		t.Fatalf("re-merge must be idempotent, added %d", n)
	}
}

// A custom LLM task + later workflow discovery gets business/race tasks.
func TestMixedPlan_LaterWorkflowDiscoveryAddsBusinessAndRaceTasks(t *testing.T) {
	state, _ := newMixedPlanState(t)
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "example.test/checkout")
	MergeRequiredEngineTasks(state, state.Plan)
	if state.Plan.Get("test-business-logic") == nil || state.Plan.Get("test-race-conditions") == nil {
		t.Fatalf("workflow discovery must add business-logic + race-condition tasks, plan has %d tasks", len(state.Plan.Tasks))
	}
}

// A recorded N/A skip is reopened when the enriched surface invalidates it.
func TestMixedPlan_InvalidNASkipIsReopenedByMerge(t *testing.T) {
	state, _ := newMixedPlanState(t)
	graphql := state.Plan.Get("test-graphql")
	if graphql == nil {
		graphql = &Task{ID: "test-graphql", Title: "Test graphql", Phase: 6, VulnClass: "graphql", Origin: "auto"}
		state.Plan.add(graphql)
	}
	graphql.Status = TaskSkipped
	graphql.Disposition = DispositionNotApplicable
	// Later a GraphQL endpoint appears.
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "example.test/graphql")
	MergeRequiredEngineTasks(state, state.Plan)
	if graphql.Status != TaskPending {
		t.Fatalf("a N/A skip contradicted by the new surface must be reopened, got %q", graphql.Status)
	}
}

// The refresh entry point drives the merge for mixed plans end to end.
func TestMixedPlan_RefreshPlanForSurfaceMergesObligations(t *testing.T) {
	state, _ := newMixedPlanState(t)
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "example.test/upload")
	refreshPlanForSurface(state)
	if state.Plan.Get("test-file-upload") == nil {
		t.Fatal("refreshPlanForSurface must merge the file-upload obligation into the mixed plan")
	}
	if state.PlanSurfaceRevision != surfaceRevision(state) {
		t.Fatal("the revision must be absorbed")
	}
}

// ── Recon dispositions (spec 19-23; see also completion_test.go) ────────────

// JS evidence blocks a false js_analysis N/A (spec 22).
func TestReconDispositions_JSEvidenceBlocksFalseNA(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/static/js/app.js"}
	if !jsAnalysisApplicable(state) {
		t.Fatal("setup: JS assets must make js_analysis applicable")
	}
	if MarkReconDimensionNA(state, "js_analysis") {
		t.Fatal("js_analysis N/A must be rejected while first-party JS assets exist")
	}
	if state.ReconCoverage.NAMarked["js_analysis"] {
		t.Fatal("a rejected N/A must not be recorded")
	}
}

// A domain scope cannot dismiss subdomain enumeration merely because the
// model does not want to perform it.
func TestReconDispositions_DomainScopeBlocksSubdomainNA(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"example.com"}
	if !subdomainScopeApplicable(state) {
		t.Fatal("setup: a bare-domain scope makes enumeration applicable")
	}
	if MarkReconDimensionNA(state, "subdomain_discovery") {
		t.Fatal("subdomain_discovery N/A must be rejected under a domain scope")
	}
}

// Blocked is distinct from N/A: recorded as its own typed state (spec 23).
func TestReconDispositions_BlockedDistinctFromNA(t *testing.T) {
	state := NewScanState()
	if !MarkReconDispositionBlocked(state, "service_discovery") {
		t.Fatal("blocked must be an accepted disposition")
	}
	if state.ReconCoverage.Dispositions["service_discovery"] != "blocked" {
		t.Fatalf("blocked must be recorded as its own typed state, got %q", state.ReconCoverage.Dispositions["service_discovery"])
	}
	if state.ReconCoverage.NAMarked["service_discovery"] {
		t.Fatal("blocked must never set NAMarked")
	}
	if !reconDimDispositionSettled(state, "service_discovery") {
		t.Fatal("blocked settles the dimension without claiming it complete")
	}
	if MarkReconDimensionNA(state, "made-up-dimension") {
		t.Fatal("unknown dimensions must be rejected")
	}
}

// ── Single-agent enforcement (spec 24-26) ───────────────────────────────────

func TestSingleAgentEnforcement_SpawnRejectedWhenDelegationDisabled(t *testing.T) {
	state := NewScanState()
	state.DelegationEnabled = false
	r := hookSingleAgentSpawnGuard(state, map[string]string{"tool_name": "spawn_agent", "name": "sqli-lane", "task": "test sql"})
	if !r.ForceSkip || r.Nudge == "" {
		t.Fatal("spawn_agent must be rejected with a message in single-agent mode")
	}
	r = hookSingleAgentSpawnGuard(state, map[string]string{"tool_name": "create_agent", "name": "x", "task": "y"})
	if !r.ForceSkip {
		t.Fatal("create_agent must be rejected in single-agent mode")
	}
	// Unrelated tools are unaffected.
	if r := hookSingleAgentSpawnGuard(state, map[string]string{"tool_name": "http_request"}); r.ForceSkip {
		t.Fatal("the guard must only affect delegation tools")
	}
	// With delegation enabled the tools pass through.
	state.DelegationEnabled = true
	if r := hookSingleAgentSpawnGuard(state, map[string]string{"tool_name": "spawn_agent"}); r.ForceSkip || r.Nudge != "" {
		t.Fatal("spawn must remain available when delegation is enabled")
	}
}

// ── Crawl (spec 27-29) ──────────────────────────────────────────────────────

// robots.txt 404 does not complete crawling.
func TestCrawlEvidence_Robots404DoesNotCompleteCrawl(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -s https://example.test/robots.txt", "HTTP/1.1 404 Not Found\n<!doctype html><html><body>404</body></html>")
	if state.ReconCoverage.Crawled {
		t.Fatal("a 404 robots.txt must not complete crawling")
	}
	if !state.ReconCoverage.Attempted[reconDimCrawl] {
		t.Fatal("the crawl attempt must still be recorded")
	}
}

// A valid empty katana pass completes crawling.
func TestCrawlEvidence_EmptyKatanaPassCompletesCrawl(t *testing.T) {
	state := NewScanState()
	fireExec(state, "katana -u https://example.test -d 2 -silent", "")
	if !state.ReconCoverage.Crawled {
		t.Fatal("a valid empty crawler pass (zero additional routes) completes crawling")
	}
}

// discover_client_routes valid-negative completes crawl/JS state.
func TestCrawlEvidence_DiscoverClientRoutesValidNegative(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/", "/static/js/app.js"}
	hookReconResultTracker(state, map[string]string{"tool_name": "discover_client_routes", "output": "0 client routes found"})
	if !state.ReconCoverage.Crawled {
		t.Fatal("a clean discover_client_routes run is a valid negative crawl")
	}
	if !state.ReconCoverage.JSAnalyzed {
		t.Fatal("with JS assets on the surface, a clean route-discovery run completes JS analysis")
	}
}

// ── JS analysis (spec 30-31) ────────────────────────────────────────────────

// The download-to-file + grep workflow counts as JS analysis.
func TestJSEvidence_DownloadThenGrepWorkflowCounts(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/static/js/app.js -o /tmp/app.js", "  % Total    % Received  100  1245")
	if state.ReconCoverage.JSAnalyzed {
		t.Fatal("a download alone (no JS in the output) must not complete JS analysis")
	}
	fireExec(state, "grep -c 'apiRoute' /tmp/app.js", "")
	if !state.ReconCoverage.JSAnalyzed {
		t.Fatal("a grep against the downloaded JS artifact is valid JS analysis, even with zero matches")
	}
}

// Successful JS analysis with zero interesting routes counts.
func TestJSEvidence_ZeroRouteBundleCounts(t *testing.T) {
	state := NewScanState()
	fireExec(state, "curl -sk https://example.test/static/js/app.js", "var a=1;function b(){}const c=2;")
	if !state.ReconCoverage.JSAnalyzed {
		t.Fatal("real JS content with zero interesting routes is a valid negative analysis")
	}
}

// ── Auth flows (spec 33-35) ─────────────────────────────────────────────────

// One login endpoint does not imply all discovered auth flows mapped;
// login + reset + OAuth are modeled independently.
func TestAuthFlows_LoginResponseDoesNotMapAllFlows(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/login", "/password-reset", "/oauth/authorize"}
	observed := authFlowsObservedForState(state)
	for _, family := range []string{"login", "password_reset", "oauth"} {
		if !containsClass(observed, family) {
			t.Fatalf("the surface must model the %s flow family, got %v", family, observed)
		}
	}
	// One live /login response maps ONLY the login flow.
	fireExec(state, "curl -s https://example.test/login", "HTTP/1.1 200 OK\nSet-Cookie: session=abc")
	if state.ReconCoverage.AuthMapped == "complete" {
		t.Fatal("one login response must not complete auth mapping while reset+oauth are observed but unmapped")
	}
	if state.AuthFlowsMapped["login"] != true {
		t.Fatal("the live /login request must map the login family")
	}
	// Mapping each remaining family independently completes the dimension.
	fireExec(state, "curl -s https://example.test/password-reset", "HTTP/1.1 200 OK\n<form action=\"/password-reset\" method=\"POST\">")
	if state.ReconCoverage.AuthMapped == "complete" {
		t.Fatal("mapping login+reset must still leave oauth outstanding")
	}
	fireExec(state, "curl -s https://example.test/oauth/authorize", "HTTP/1.1 302 Found\nLocation: /")
	if state.ReconCoverage.AuthMapped != "complete" {
		t.Fatalf("mapping every observed family completes auth mapping, unmapped: %v", authFlowsUnmapped(state))
	}
}

// Credential absence does not block auth-surface mapping.
func TestAuthFlows_CredentialAbsenceDoesNotBlockSurfaceMapping(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/login"}
	if state.AuthContextAvailable {
		t.Fatal("setup: no credentials exist")
	}
	fireExec(state, "curl -s https://example.test/login", "HTTP/1.1 200 OK\nSet-Cookie: sid=x")
	if state.ReconCoverage.AuthMapped != "complete" {
		t.Fatal("auth SURFACE mapping must complete without credentials")
	}
	if state.AuthContextAvailable {
		t.Fatal("a mapped surface must not fabricate credentials")
	}
}

// ── Domain scope (spec 36-39) ───────────────────────────────────────────────

func TestDomainScope_PublicSuffixCorrectness(t *testing.T) {
	for _, host := range []string{"example.co.uk", "example.com.au", "example.co.in"} {
		if !isBareDomain(host) {
			t.Fatalf("%s must be recognized as a registrable domain", host)
		}
	}
	if isBareDomain("app.example.co.uk") {
		t.Fatal("app.example.co.uk is an explicit host, not a domain scope")
	}
	if registrableDomain("co.uk") != "" {
		t.Fatal("a bare public suffix is never a registrable domain")
	}
}

func TestDomainScope_WildcardScopesUnderRegistrableDomain(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"*.example.co.uk"}
	suffixes := scopeDomainSuffixes(state)
	if len(suffixes) != 1 || suffixes[0] != "example.co.uk" {
		t.Fatalf("*.example.co.uk must scope to example.co.uk, got %v", suffixes)
	}
	for _, s := range suffixes {
		if s == "co.uk" {
			t.Fatal("wildcard scope must NEVER broaden to the public suffix")
		}
	}
	if !subdomainScopeApplicable(state) {
		t.Fatal("a wildcard scope owes subdomain enumeration")
	}
}

func TestDomainScope_ExplicitHostIsSingleHostScope(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.co.uk"}
	if subdomainScopeApplicable(state) {
		t.Fatal("an explicit host scope owes no subdomain enumeration")
	}
	suffixes := scopeDomainSuffixes(state)
	if len(suffixes) != 1 || suffixes[0] != "example.co.uk" {
		t.Fatalf("the registrable suffix must be example.co.uk, got %v", suffixes)
	}
}

// ── Host ranking (spec 40-41) ───────────────────────────────────────────────

func TestHostRanking_DeterministicSelection(t *testing.T) {
	build := func() *ScanState {
		state := NewScanState()
		state.DiscoveredEndpoints = []string{
			"files.example.test/x",
			"api.example.test/v1/users",
			"admin.example.test/panel",
			"app.example.test/dashboard",
			"pay.example.test/checkout",
			"misc.example.test/",
		}
		state.DiscoveredHosts["staging.example.test"] = true
		state.DiscoveredHosts["auth.example.test"] = true
		return state
	}
	a := distinctApplicationHosts(build())
	b := distinctApplicationHosts(build())
	if len(a) != maxReconHostRequirement {
		t.Fatalf("the host requirement must stay bounded at %d, got %d", maxReconHostRequirement, len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("the same candidate set must select the same hosts every run: %v vs %v", a, b)
		}
	}
	if a[0] != "admin.example.test" || a[1] != "api.example.test" {
		t.Fatalf("role evidence must dominate the ranking, got %v", a)
	}
	// Insertion order does not affect selection.
	shuffled := build()
	shuffled.DiscoveredEndpoints = []string{
		"misc.example.test/",
		"pay.example.test/checkout",
		"app.example.test/dashboard",
		"admin.example.test/panel",
		"api.example.test/v1/users",
		"files.example.test/x",
	}
	c := distinctApplicationHosts(shuffled)
	for i := range a {
		if a[i] != c[i] {
			t.Fatalf("map/insertion order must not affect selection: %v vs %v", a, c)
		}
	}
}

// ── Skills (spec 42-45) ─────────────────────────────────────────────────────

func TestLaneSkillGate_ActiveLanesRequireTheirSkills(t *testing.T) {
	state := NewScanState()
	state.PlanBuilt = true
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "test-graphql", Title: "Test graphql", Phase: 6, VulnClass: "graphql", Status: TaskPending, Origin: "auto"})
	state.Plan.add(&Task{ID: "test-race-conditions", Title: "Test race conditions", Phase: 6, VulnClass: "race-conditions", Status: TaskPending, Origin: "auto"})

	graphqlSkill, ok := VulnClassSkill("graphql")
	if !ok || graphqlSkill == "" {
		t.Fatal("setup: graphql must resolve a methodology skill")
	}
	r := hookLaneSkillGate(state, nil)
	if len(r.Directives) != 1 || !strings.Contains(r.Directives[0].Content, graphqlSkill) {
		t.Fatalf("the active GraphQL lane must require its methodology skill, got %+v", r.Directives)
	}
	// Spec 45: a delivered recommendation is NOT a loaded skill.
	state.SkillSuggestionsSent[graphqlSkill] = true
	r = hookLaneSkillGate(state, nil)
	if len(r.Directives) != 1 {
		t.Fatal("recommendation delivery must not satisfy the lane gate")
	}
	// A successful load satisfies the gate and the lane moves on.
	if state.LoadedSkills == nil {
		state.LoadedSkills = map[string]*LoadedSkillInfo{}
	}
	state.LoadedSkills[graphqlSkill] = &LoadedSkillInfo{Name: graphqlSkill}
	r = hookLaneSkillGate(state, nil)
	if len(r.Directives) != 1 {
		t.Fatalf("with GraphQL loaded, the gate must follow the next lane, got %+v", r.Directives)
	}
	raceSkill, _ := VulnClassSkill("race-conditions")
	if raceSkill == "" {
		t.Fatal("setup: race-conditions must resolve a methodology skill")
	}
	if !strings.Contains(r.Directives[0].Content, raceSkill) {
		t.Fatalf("the next lane must demand the race skill, got %q", r.Directives[0].Content)
	}
	state.LoadedSkills[raceSkill] = &LoadedSkillInfo{Name: raceSkill}
	if r = hookLaneSkillGate(state, nil); len(r.Directives) != 0 {
		t.Fatalf("with both lane skills loaded the gate must stay quiet, got %+v", r.Directives)
	}
}

// A failed skill lookup stays retryable (spec 44).
func TestSkillFailureRecovery_FailedLoadStaysRetryable(t *testing.T) {
	state := NewScanState()
	skill, ok := VulnClassSkill("graphql")
	if !ok || skill == "" {
		t.Fatal("setup: graphql must resolve a methodology skill")
	}
	state.SkillSuggestionsSent[skill] = true
	hookSkillLoadTracker(state, map[string]string{
		"tool_name": "read_skill",
		"name":      skill,
		"error":     "unknown skill name",
	})
	if state.FailedSkillLoads != 1 {
		t.Fatalf("the failure must be counted, got %d", state.FailedSkillLoads)
	}
	if state.SkillLoadFailures[skill] != 1 {
		t.Fatal("the per-skill failure must be recorded")
	}
	if state.SkillSuggestionsSent[skill] {
		t.Fatal("a failed load must clear the recommendation marker so the skill can be re-recommended")
	}
	// Repeated failures stop the gate from nagging, but the obligation stays.
	for i := 0; i < maxLaneSkillLoadRetries+1; i++ {
		hookSkillLoadTracker(state, map[string]string{"tool_name": "read_skill", "name": skill, "error": "unknown skill name"})
	}
	state.PlanBuilt = true
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "test-graphql", Title: "Test graphql", Phase: 6, VulnClass: "graphql", Status: TaskPending, Origin: "auto"})
	if r := hookLaneSkillGate(state, nil); len(r.Directives) != 0 {
		t.Fatal("the gate must stop nagging after bounded retries")
	}
}

// ── Plan freshness (spec 46-48) ────────────────────────────────────────────

// Observation order never changes the revision (determinism).
func TestSurfaceRevision_DeterministicAcrossObservationOrder(t *testing.T) {
	a := NewScanState()
	a.DiscoveredEndpoints = []string{"example.test/a", "example.test/b"}
	recordEndpointMethod(a, "example.test/a", "GET")
	recordEndpointMethod(a, "example.test/b", "POST")
	recordEndpointContentType(a, "example.test/a", "application/json")
	RecordSurfaceObservation(a, SurfaceObservation{Endpoint: "example.test/b", Parameters: []SurfaceParameter{{Name: "q", Location: "query"}}})

	b := NewScanState()
	b.DiscoveredEndpoints = []string{"example.test/b", "example.test/a"}
	RecordSurfaceObservation(b, SurfaceObservation{Endpoint: "example.test/b", Parameters: []SurfaceParameter{{Name: "q", Location: "query"}}})
	recordEndpointContentType(b, "example.test/a", "application/json")
	recordEndpointMethod(b, "example.test/b", "POST")
	recordEndpointMethod(b, "example.test/a", "GET")

	if surfaceRevision(a) != surfaceRevision(b) {
		t.Fatalf("observation order must not change the revision:\n%s\n%s", surfaceRevision(a), surfaceRevision(b))
	}
}

// The planner refreshes before finish; a stale plan can never evaluate as
// complete (spec 47-48).
func TestPlanFreshness_StalePlanCannotFinish(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveredEndpoints = []string{"example.test/api/users"}
	state.Plan = AutoPlanFromState(state)
	state.PlanBuilt = true
	state.PlanSurfaceRevision = surfaceRevision(state)
	for _, task := range state.Plan.Tasks {
		task.Status = TaskCompleted
	}
	// Semantic enrichment AFTER the plan completed: POST observed on an
	// existing route activates business-logic/race obligations.
	recordEndpointMethod(state, "example.test/api/users", "POST")
	gate := planFinishGate(state, 10)
	if !gate.Block {
		t.Fatal("finish must not pass while the plan is stale against the enriched surface")
	}
	if state.PlanSurfaceRevision != surfaceRevision(state) {
		t.Fatal("the finish gate must refresh the plan before evaluating it")
	}
	if state.Plan.Get("test-business-logic") == nil || state.Plan.Get("test-race-conditions") == nil {
		t.Fatal("the refreshed plan must carry the newly applicable obligations")
	}
}

// The notes-derived inventory is a fallback MERGED with the structured
// surface - never a replacement for it.
func TestSurfaceInventory_NotesMergePreservesStructuredObservations(t *testing.T) {
	state := NewScanState()
	state.ScanContextID = "surface-merge-test"
	state.EndpointInventorySaved = true
	fireTerminal(state, "curl -sk \"https://example.test/fetch?url=https://example.com\"")
	oldBlob := notesBlobForContext
	notesBlobForContext = func(id string) string {
		return "Endpoint Inventory:\n/admin\n/login\n"
	}
	defer func() { notesBlobForContext = oldBlob }()
	hookPlanner(state, map[string]string{})
	for _, want := range []string{"example.test/fetch", "/admin", "/login"} {
		if !endpointInInventory(state, want) {
			t.Fatalf("the merged inventory must keep %q, got %v", want, state.DiscoveredEndpoints)
		}
	}
}

// Provenance: observed endpoints record where they came from.
func TestSurfaceProvenance_RecordedPerEndpoint(t *testing.T) {
	state := NewScanState()
	fireTerminal(state, "curl -sk \"https://example.test/fetch?url=1\"")
	sources := endpointProvenance(state, "example.test/fetch")
	if len(sources) == 0 || sources[0] != "request" {
		t.Fatalf("observed traffic must record provenance, got %v", sources)
	}
}
