package agent

import "testing"

// withInventoryNotes swaps the notes accessor for one test so build_plan reads
// a fixed Endpoint Inventory blob instead of the shared notes store.
func withInventoryNotes(t *testing.T, blob string) {
	t.Helper()
	prev := notesBlobForContext
	notesBlobForContext = func(string) string { return blob }
	t.Cleanup(func() { notesBlobForContext = prev })
}

const buildPlanSurfaceTasks = `[
	{"id":"recon","title":"Map surface","phase":1},
	{"id":"test-eval-rce","title":"Test /eval RCE","phase":6,"vuln_class":"rce","endpoint":"/eval"}
]`

// build_plan must MERGE the notes inventory into the runtime surface, the same
// way the planner hook does. An endpoint promoted from observed traffic that
// the model never wrote into its inventory note is still attack surface.
func TestBuildPlanPreservesObservedSurface(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.ScanContextID = "build-plan-surface-merge"
	a.state.EndpointInventorySaved = true
	fireTerminal(a.state, "curl -sk \"https://example.test/fetch?url=https://example.com\"")
	if !endpointInInventory(a.state, "example.test/fetch") {
		t.Fatalf("precondition: observed traffic must promote example.test/fetch, got %v", a.state.DiscoveredEndpoints)
	}
	withInventoryNotes(t, "Endpoint Inventory:\n/admin\n/login\n")

	res, err := a.buildPlanTool(map[string]string{"tasks": buildPlanSurfaceTasks})
	if err != nil || res.Error != "" {
		t.Fatalf("build_plan failed: err=%v result=%q", err, res.Error)
	}
	for _, want := range []string{"example.test/fetch", "/admin", "/login"} {
		if !endpointInInventory(a.state, want) {
			t.Errorf("build_plan dropped %q from the discovered surface, got %v", want, a.state.DiscoveredEndpoints)
		}
	}
}

// With no inventory note saved, build_plan must leave the existing surface
// alone rather than wiping it to nil.
func TestBuildPlanEmptyNotesKeepsSurface(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.ScanContextID = "build-plan-empty-notes"
	a.state.DiscoveredEndpoints = []string{"/api/orders", "/api/users"}
	withInventoryNotes(t, "")

	res, err := a.buildPlanTool(map[string]string{"tasks": buildPlanSurfaceTasks})
	if err != nil || res.Error != "" {
		t.Fatalf("build_plan failed: err=%v result=%q", err, res.Error)
	}
	for _, want := range []string{"/api/orders", "/api/users"} {
		if !endpointInInventory(a.state, want) {
			t.Errorf("build_plan with no inventory note dropped %q, got %v", want, a.state.DiscoveredEndpoints)
		}
	}
}

// The coverage consequence: a wiped surface empties the coverage denominator,
// and taskCoverageComplete then falls back to the aggregate class flag, so a
// single exercised endpoint closed the whole class. After build_plan, a class
// task must still require coverage on every applicable discovered endpoint.
func TestBuildPlanSingleEndpointDoesNotCloseClass(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.ScanContextID = "build-plan-class-closure"
	a.state.DiscoveredEndpoints = []string{"/api/x", "/api/y"}
	withInventoryNotes(t, "")

	res, err := a.buildPlanTool(map[string]string{"tasks": buildPlanSurfaceTasks})
	if err != nil || res.Error != "" {
		t.Fatalf("build_plan failed: err=%v result=%q", err, res.Error)
	}
	if a.state.Plan.Get("test-sqli") == nil {
		t.Fatal("precondition: the coverage floor must append test-sqli")
	}

	markEndpointClassCoverage(a.state, "/api/x", "sqli")
	reconcilePlan(a.state)
	if got := a.state.Plan.Get("test-sqli").Status; got == TaskCompleted {
		t.Fatal("SQLi coverage on one of two discovered endpoints must not complete test-sqli")
	}

	markEndpointClassCoverage(a.state, "/api/y", "sqli")
	reconcilePlan(a.state)
	if got := a.state.Plan.Get("test-sqli").Status; got != TaskCompleted {
		t.Fatalf("test-sqli should complete once every discovered endpoint is covered, got %v", got)
	}
}

// The planner refresh that follows build_plan derives the applicability lanes
// (file-upload, GraphQL, business-logic, ...) from DiscoveredEndpoints. An
// observed upload route that is missing from the notes must still earn its
// file-upload lane once the planner hook reconciles the model-built plan.
func TestBuildPlanKeepsApplicabilityLanesForObservedRoutes(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.ScanContextID = "build-plan-upload-lane"
	a.state.EndpointInventorySaved = true
	a.state.ReconDone = true
	fireTerminal(a.state, "curl -sk -F \"file=@x.png\" \"https://example.test/api/upload\"")
	withInventoryNotes(t, "Endpoint Inventory:\n/admin\n/login\n")

	res, err := a.buildPlanTool(map[string]string{"tasks": buildPlanSurfaceTasks})
	if err != nil || res.Error != "" {
		t.Fatalf("build_plan failed: err=%v result=%q", err, res.Error)
	}
	hookPlanner(a.state, map[string]string{})

	for _, task := range a.state.Plan.Tasks {
		if normalizeCoverageClass(task.VulnClass) == "file-upload" {
			return
		}
	}
	t.Fatalf("observed upload route must keep its file-upload lane after build_plan; surface=%v", a.state.DiscoveredEndpoints)
}
