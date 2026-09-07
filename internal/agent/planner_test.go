package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// AutoPlan must produce a dependency-ordered graph: recon first, vuln-class
// tests depend on recon, IDOR depends on auth-session, and verify depends on
// the test tasks; report depends on verify.
func TestAutoPlanDependencyGraph(t *testing.T) {
	p := AutoPlan([]string{"/api/users", "/api/leads", "/login"}, map[string]bool{"java": true})

	if p.IsEmpty() {
		t.Fatal("AutoPlan produced an empty plan")
	}
	recon := p.Get("recon")
	if recon == nil {
		t.Fatal("missing recon task")
	}
	if recon.Phase != 1 {
		t.Errorf("recon phase = %d, want 1", recon.Phase)
	}
	for _, dep := range recon.DependsOn {
		t.Errorf("recon should have no dependencies, got %q", dep)
	}

	// SSTI is a baseline lane even when fingerprinting is incomplete.
	if p.Get("test-ssti") == nil {
		t.Error("java tech should produce an ssti task")
	}
	// seeded surface → no dirbust task
	if p.Get("dirbust") != nil {
		t.Error("seeded surface should skip the dirbust task")
	}

	// IDOR depends on recon AND auth-session
	idor := p.Get("idor")
	if idor == nil {
		t.Fatal("missing idor task")
	}
	if !dependsOn(idor, "auth-session") || !dependsOn(idor, "recon") {
		t.Errorf("idor deps = %v, want recon+auth-session", idor.DependsOn)
	}

	// verify depends on the test tasks; report depends on verify
	verify := p.Get("verify")
	if verify == nil {
		t.Fatal("missing verify task")
	}
	if len(verify.DependsOn) == 0 {
		t.Error("verify should depend on the test tasks")
	}
	report := p.Get("report")
	if report == nil {
		t.Fatal("missing report task")
	}
	if !dependsOn(report, "verify") {
		t.Error("report should depend on verify")
	}

	// Endpoint grounding: test tasks should mention the discovered endpoints.
	sqli := p.Get("test-sqli")
	if sqli == nil {
		t.Fatal("missing test-sqli task")
	}
	if !strings.Contains(sqli.Notes, "/api/users") {
		t.Errorf("test-sqli notes should list discovered endpoints, got %q", sqli.Notes)
	}
}

// A black-box target (no seeded endpoints) still gets a methodology plan with
// a dirbust task.
func TestAutoPlanBlackBox(t *testing.T) {
	p := AutoPlan(nil, nil)
	if p.Get("dirbust") == nil {
		t.Error("black-box plan should include a dirbust task")
	}
	if p.Get("test-sqli") == nil {
		t.Error("black-box plan should still include core vuln-class tasks")
	}
	for _, class := range requiredCoverageClasses() {
		taskID := "test-" + class
		if class == "idor" {
			taskID = "idor"
		}
		if p.Get(taskID) == nil {
			t.Errorf("coverage requires %q but auto-plan has no matching task %q", class, taskID)
		}
	}
}

// NextTasks returns pending tasks whose dependencies are satisfied, ordered by
// phase. Initially only recon is ready (everything depends on it).
func TestNextTasksDependencyOrder(t *testing.T) {
	p := AutoPlan([]string{"/api/x"}, nil)
	next := p.NextTasks(5)
	if len(next) == 0 {
		t.Fatal("NextTasks returned nothing for a fresh plan")
	}
	if next[0].ID != "recon" {
		t.Errorf("first ready task = %q, want recon (everything depends on it)", next[0].ID)
	}
	// After recon completes, the test tasks + auth + dirbust(omitted here) unblock.
	p.SetStatus("recon", TaskCompleted)
	next = p.NextTasks(10)
	ids := taskIDs(next)
	for _, want := range []string{"test-sqli", "test-xss", "auth-session"} {
		if !contains(ids, want) {
			t.Errorf("after recon, %q should be ready; got %v", want, ids)
		}
	}
	// idor should NOT be ready yet (depends on auth-session).
	if contains(ids, "idor") {
		t.Error("idor should not be ready until auth-session completes")
	}
}

// NextTasks must not deadlock: if dependencies are unmet but tasks are pending,
// it returns the lowest-phase pending tasks so the scan can still proceed.
func TestNextTasksNoDeadlock(t *testing.T) {
	p := NewPlan()
	p.add(&Task{ID: "a", Title: "a", Phase: 5, Status: TaskPending, DependsOn: []string{"b"}})
	p.add(&Task{ID: "b", Title: "b", Phase: 3, Status: TaskPending}) // b has no deps but neither is completed
	// Both pending, a depends on b which is pending → no dependency-ready task.
	// NextTasks must fall back to the lowest-phase pending (b).
	next := p.NextTasks(5)
	if len(next) == 0 {
		t.Fatal("NextTasks deadlocked on unmet dependency — must fall back to pending tasks")
	}
	if next[0].ID != "b" {
		t.Errorf("fallback should pick lowest-phase pending task 'b', got %q", next[0].ID)
	}
}

// CoverageGaps keeps endpoint × class evidence separate. Testing SQLi once (or
// merely touching an endpoint) must not collapse SQLi gaps across the surface.
func TestCoverageGaps(t *testing.T) {
	state := NewScanState()
	state.VulnClassesTested["sqli"] = true // aggregate evidence is not enough
	state.EndpointsTested["example.com/api/leads"] = true
	markEndpointClassCoverage(state, "https://example.com/api/users?id=1", "sqli")
	endpoints := []string{"/api/users", "/api/leads"}

	gaps := CoverageGaps(state, endpoints)
	var sqliGaps int
	for _, g := range gaps {
		if g.VulnClass == "sqli" {
			sqliGaps++
			if g.Endpoint != "/api/leads" {
				t.Errorf("unexpected SQLi gap after exact /api/users coverage: %+v", g)
			}
		}
	}
	if sqliGaps != 1 {
		t.Errorf("sqli gaps = %d, want 1; global class or generic endpoint evidence must not collapse it", sqliGaps)
	}
	// xss has no coverage → each discovered endpoint is a gap.
	var xssGaps int
	for _, g := range gaps {
		if g.VulnClass == "xss" {
			xssGaps++
		}
	}
	if xssGaps != 2 {
		t.Errorf("xss gaps = %d, want 2 (one per discovered endpoint)", xssGaps)
	}
}

// CoverageGaps with no discovered endpoints falls back to whole-target class
// gaps so the nudge still surfaces missing vuln classes.
func TestCoverageGapsBlackBox(t *testing.T) {
	state := NewScanState()
	state.VulnClassesTested["sqli"] = true
	gaps := CoverageGaps(state, nil)
	if len(gaps) == 0 {
		t.Fatal("black-box gap detection should still flag untested classes")
	}
	for _, g := range gaps {
		if g.VulnClass == "sqli" {
			t.Error("sqli is tested — should not be a whole-target gap")
		}
		if g.Endpoint != "" {
			t.Errorf("whole-target gap should have empty endpoint, got %q", g.Endpoint)
		}
	}
}

func TestHookPlannerDoesNotExpandDelegatedAgentIntoFullScan(t *testing.T) {
	state := NewScanState()
	state.DelegatedAgent = true
	state.ReconDone = true
	state.DiscoveredEndpoints = []string{"/assigned"}
	state.DetectedTechs["java"] = true

	if got := hookPlanner(state, nil); got.Nudge != "" {
		t.Fatalf("delegated specialist without a lane-local plan should not receive a root plan nudge: %s", got.Nudge)
	}
	if state.Plan != nil || state.PlanBuilt {
		t.Fatal("delegated specialist was incorrectly expanded into a whole-target AutoPlan")
	}
}

func TestEndpointCoverageKeepsQualifiedHostsSeparate(t *testing.T) {
	state := NewScanState()
	markEndpointClassCoverage(state, "https://api-a.example.test/search", "xss")
	if !endpointTestedForClass(state, "https://api-a.example.test/search", "xss") {
		t.Error("the tested host-qualified endpoint should be covered")
	}
	if endpointTestedForClass(state, "https://api-b.example.test/search", "xss") {
		t.Error("the same path on a different discovered host must remain a gap")
	}
}

func TestEndpointCoverageIsSharedAcrossDelegatedAgents(t *testing.T) {
	contextID := "shared-coverage-" + t.Name()
	ctx := scanctx.New(contextID, t.TempDir())
	scanctx.Activate(ctx)
	t.Cleanup(func() {
		scanctx.Deactivate(contextID)
		ctx.Close()
	})

	coordinator := NewScanState()
	coordinator.ScanContextID = contextID
	specialist := NewScanState()
	specialist.ScanContextID = contextID

	markEndpointClassCoverage(specialist, "https://target.example/api/users?id=1", "sqli")
	if !endpointTestedForClass(coordinator, "https://target.example/api/users", "sqli") {
		t.Fatal("coordinator did not observe exact coverage executed by its specialist")
	}
	if endpointTestedForClass(coordinator, "https://target.example/api/admin", "sqli") {
		t.Fatal("specialist coverage leaked to an untested endpoint")
	}
	if endpointTestedForClass(coordinator, "https://target.example/api/users", "xss") {
		t.Fatal("specialist coverage leaked to an untested class")
	}
}

// reconcilePlan marks tasks completed from live coverage evidence, so the plan
// reflects reality without the model calling update_plan.
func TestReconcilePlan(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/api/x", "/api/y"}
	state.Plan = AutoPlan(state.DiscoveredEndpoints, nil)
	state.ReconDone = true
	state.VulnClassesTested["sqli"] = true
	state.DirBustingDone = true

	reconcilePlan(state)
	if state.Plan.Get("recon").Status != TaskCompleted {
		t.Error("recon should be completed after ReconDone")
	}
	if state.Plan.Get("test-sqli").Status == TaskCompleted {
		t.Error("aggregate SQLi evidence must not complete a grouped endpoint task")
	}
	markEndpointClassCoverage(state, "/api/x", "sqli")
	reconcilePlan(state)
	if state.Plan.Get("test-sqli").Status == TaskCompleted {
		t.Error("coverage on only one of two endpoints must not complete test-sqli")
	}
	markEndpointClassCoverage(state, "/api/y", "sqli")
	reconcilePlan(state)
	if state.Plan.Get("test-sqli").Status != TaskCompleted {
		t.Error("test-sqli should complete after exact coverage on every discovered endpoint")
	}
	// verify/report stay pending (they complete via finish, not coverage).
	if state.Plan.Get("verify").Status == TaskCompleted {
		t.Error("verify should not auto-complete from coverage evidence")
	}
}

// buildPlanTool replaces the plan from a JSON task array and rejects malformed
// input without erroring the loop.
func TestBuildPlanTool(t *testing.T) {
	a := &Agent{state: NewScanState()}

	// Malformed JSON → error result, no panic.
	res, err := a.buildPlanTool(map[string]string{"tasks": "{not json"})
	if err != nil {
		t.Fatalf("malformed input should return a tool error, not a Go error: %v", err)
	}
	if res.Error == "" {
		t.Error("malformed JSON should produce an error result")
	}
	if a.state.Plan != nil {
		t.Error("malformed input should not create a plan")
	}

	// Valid plan.
	res, err = a.buildPlanTool(map[string]string{"tasks": `[
		{"id":"recon","title":"recon","phase":1},
		{"id":"test-sqli","title":"test sqli","phase":6,"vuln_class":"sqli","depends_on":["recon"]}
	]`})
	if err != nil {
		t.Fatalf("valid input errored: %v", err)
	}
	if a.state.Plan == nil || a.state.Plan.IsEmpty() {
		t.Fatal("valid input should create a plan")
	}
	if !a.state.PlanBuilt {
		t.Error("PlanBuilt should be true after build_plan")
	}
	if a.state.Plan.Get("test-sqli").Phase != 6 {
		t.Errorf("test-sqli phase = %d, want 6", a.state.Plan.Get("test-sqli").Phase)
	}
	if res.Output == "" {
		t.Error("build_plan should return a summary")
	}
}

// buildPlanTool rejects duplicate task ids and empty arrays.
func TestBuildPlanToolValidation(t *testing.T) {
	a := &Agent{state: NewScanState()}

	res, _ := a.buildPlanTool(map[string]string{"tasks": "[]"})
	if res.Error == "" {
		t.Error("empty tasks array should error")
	}

	res, _ = a.buildPlanTool(map[string]string{"tasks": `[
		{"id":"x","title":"x","phase":1},
		{"id":"x","title":"dup","phase":2}
	]`})
	if a.state.Plan == nil || len(a.state.Plan.Tasks) != 1 {
		t.Errorf("duplicate ids: expected 1 task kept, got %d", len(a.state.Plan.Tasks))
	}
}

// updatePlanTool transitions status and rejects unknown ids / bad status.
func TestUpdatePlanTool(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.Plan = AutoPlan([]string{"/x"}, nil)

	res, _ := a.updatePlanTool(map[string]string{"task_id": "recon", "status": "completed"})
	if res.Error != "" {
		t.Fatalf("valid update errored: %s", res.Error)
	}
	if a.state.Plan.Get("recon").Status != TaskCompleted {
		t.Error("recon should be completed")
	}

	// Models commonly infer test-idor from all the other test-* tasks. The
	// alias must resolve to the dependency-aware idor task rather than reject.
	res, _ = a.updatePlanTool(map[string]string{"task_id": "test-idor", "status": "active"})
	if res.Error != "" {
		t.Fatalf("test-idor alias should resolve to idor: %s", res.Error)
	}
	if a.state.Plan.Get("idor").Status != TaskActive {
		t.Error("test-idor alias did not update the idor task")
	}

	// Unknown id.
	res, _ = a.updatePlanTool(map[string]string{"task_id": "nope", "status": "completed"})
	if res.Error == "" {
		t.Error("unknown task id should error")
	}

	// Bad status.
	res, _ = a.updatePlanTool(map[string]string{"task_id": "recon", "status": "bogus"})
	if res.Error == "" {
		t.Error("bad status should error")
	}
}

// extractPaths pulls endpoints out of an inventory blob, filtering static
// assets and the SVG namespace noise JS bundles embed.
func TestExtractPaths(t *testing.T) {
	blob := `Discovered Endpoints:
- /api/users
- /api/leads
- /admin/login
- /static/style.css
- /logo.png
http://www.w3.org/2000/svg
https://ok.ru/profile/123`
	paths := extractPaths(blob)
	want := []string{"/admin/login", "/api/leads", "/api/users", "https://ok.ru/profile/123"}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for _, w := range want {
		if !contains(paths, w) {
			t.Errorf("missing %q in %v", w, paths)
		}
	}
	for _, p := range paths {
		if strings.HasSuffix(p, ".css") || strings.HasSuffix(p, ".png") || strings.Contains(p, "w3.org") {
			t.Errorf("static asset / svg namespace should be filtered, got %q", p)
		}
	}
}

func TestHookPlannerSeedsFromObservedRequestsBeforeInventory(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.EndpointsTested["example.test/api/health"] = true
	state.EndpointsTested["example.test/login"] = true

	result := hookPlanner(state, nil)
	if state.Plan == nil || !state.PlanBuilt {
		t.Fatal("observed live requests should seed the plan before an explicit inventory note")
	}
	want := []string{"example.test/api/health", "example.test/login"}
	if !slices.Equal(state.DiscoveredEndpoints, want) {
		t.Fatalf("provisional endpoints = %v, want %v", state.DiscoveredEndpoints, want)
	}
	if result.Nudge == "" || !strings.Contains(result.Nudge, "Active Plan") {
		t.Fatalf("new provisional plan should be surfaced to the coordinator: %q", result.Nudge)
	}
}

func TestObservedEndpointsForPlanningIsSortedAndBounded(t *testing.T) {
	observed := map[string]bool{
		"example.test/z":  true,
		"example.test/a":  true,
		"example.test/m":  true,
		"example.test/no": false,
	}
	got := observedEndpointsForPlanning(observed, 2)
	want := []string{"example.test/a", "example.test/m"}
	if !slices.Equal(got, want) {
		t.Fatalf("observed endpoints = %v, want %v", got, want)
	}
}

// ProgressPct and Counts track plan completion correctly.
func TestPlanProgress(t *testing.T) {
	p := AutoPlan([]string{"/x"}, nil)
	if p.ProgressPct() != 0 {
		t.Errorf("fresh plan progress = %d, want 0", p.ProgressPct())
	}
	total := len(p.Tasks)
	half := total / 2
	done := 0
	for _, t2 := range p.Tasks {
		if done >= half {
			break
		}
		t2.Status = TaskCompleted
		done++
	}
	if p.ProgressPct() == 0 {
		t.Error("progress should be > 0 after completing some tasks")
	}
	if p.RemainingCount() == 0 {
		t.Error("plan with uncompleted tasks should have remaining work")
	}
}

// helpers
func dependsOn(t *Task, id string) bool {
	for _, d := range t.DependsOn {
		if d == id {
			return true
		}
	}
	return false
}

func taskIDs(tasks []*Task) []string {
	out := make([]string, len(tasks))
	for i, t := range tasks {
		out[i] = t.ID
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestUpdatePlanToolTolerance covers the friction-reducing inference: a model
// that omits status or task_id (the two shapes it botches most) no longer burns
// an iteration on a "missing required parameter" rejection.
func TestUpdatePlanToolTolerance(t *testing.T) {
	newAgent := func() *Agent {
		a := &Agent{state: NewScanState()}
		a.state.Plan = AutoPlan([]string{"/x"}, nil)
		return a
	}

	// status omitted → defaults to active.
	a := newAgent()
	if res, _ := a.updatePlanTool(map[string]string{"task_id": "recon"}); res.Error != "" {
		t.Fatalf("omitted status should default to active, got error: %s", res.Error)
	}
	if got := a.state.Plan.Get("recon"); got == nil || got.Status != TaskActive {
		t.Fatalf("recon should be active after status-defaulted update, got %v", got)
	}

	// task_id omitted with a single active task → applies to that task.
	if res, _ := a.updatePlanTool(map[string]string{"status": "completed"}); res.Error != "" {
		t.Fatalf("task_id inference (single active) should succeed, got error: %s", res.Error)
	}
	if got := a.state.Plan.Get("recon"); got == nil || got.Status != TaskCompleted {
		t.Fatalf("recon should be completed via single-active inference, got %v", got)
	}

	// task_id omitted, none active, status=active → the next pending task.
	a2 := newAgent()
	if res, _ := a2.updatePlanTool(map[string]string{"status": "active"}); res.Error != "" {
		t.Fatalf("marking the next pending task active should succeed, got error: %s", res.Error)
	}
	if _, active, _, _ := a2.state.Plan.Counts(); active != 1 {
		t.Fatalf("exactly one task should be active after next-pending inference, got %d", active)
	}

	// task_id omitted, multiple active → ambiguous → a helpful error (not a silent wrong update).
	a3 := newAgent()
	a3.state.Plan.SetStatus("recon", TaskActive)
	var other string
	for _, tk := range a3.state.Plan.Tasks {
		if tk.ID != "recon" {
			other = tk.ID
			break
		}
	}
	a3.state.Plan.SetStatus(other, TaskActive)
	if res, _ := a3.updatePlanTool(map[string]string{"status": "completed"}); res.Error == "" {
		t.Fatal("ambiguous task_id (multiple active) should error with a task-id hint")
	}
}
