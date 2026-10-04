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
		return
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
	// Seeded surfaces still get a phase-3 task: hidden non-API paths
	// (debug consoles, backups) only surface via wordlist enumeration, and
	// suppressing the task pushed discovery to finish-gate time.
	if p.Get("dirbust") == nil {
		t.Error("seeded surface must still create the (bounded) dirbust task")
	}
	// Step-by-step: class tasks wait for recon AND dirbust.
	if sqli := p.Get("test-sqli"); sqli != nil && !dependsOn(sqli, "dirbust") {
		t.Errorf("test-sqli deps = %v, want recon+dirbust", sqli.DependsOn)
	}

	// IDOR depends on recon AND auth-session
	idor := p.Get("idor")
	if idor == nil {
		t.Fatal("missing idor task")
		return
	}
	if !dependsOn(idor, "auth-session") || !dependsOn(idor, "recon") {
		t.Errorf("idor deps = %v, want recon+auth-session", idor.DependsOn)
	}

	// Phase 20 (exploit verification) and Phase 22 (final report) are
	// DERIVED states — verification runs inline via the deterministic
	// verifiers and the hypothesis ledger, reporting is the terminal
	// lifecycle. The plan must NOT carry permanently-pending fake tasks
	// for them.
	if p.Get("verify") != nil {
		t.Error("plan must not carry a fake verify task (Phase 20 is a derived verification state)")
	}
	if p.Get("report") != nil {
		t.Error("plan must not carry a fake report task (Phase 22 is the terminal reporting state)")
	}

	// Endpoint grounding: test tasks should mention the discovered endpoints.
	sqli := p.Get("test-sqli")
	if sqli == nil {
		t.Fatal("missing test-sqli task")
		return
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

// Coverage requirement: even with no operator-supplied credentials, the plan
// must retain the full auth lane and a pending IDOR task. Vulnerability
// classes are never skipped based on scan context.
func TestAutoPlanAlwaysKeepsAuthAndIDOR(t *testing.T) {
	p := AutoPlan([]string{"/login", "/public/api"}, nil)

	auth := p.Get("auth-session")
	if auth == nil || auth.Status != TaskPending {
		t.Fatalf("auth task = %+v, want pending full authentication lane", auth)
	}
	if !strings.Contains(auth.Title, "Authentication & session testing") {
		t.Fatalf("auth task was downgraded: %+v", auth)
	}

	idor := p.Get("idor")
	if idor == nil || idor.Status != TaskPending {
		t.Fatalf("IDOR task = %+v, want pending regardless of auth context", idor)
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
	// Step-by-step: after recon completes, ONLY dirbust is ready — the
	// testing lanes (phases 5+) must not open before content discovery.
	p.SetStatus("recon", TaskCompleted)
	next = p.NextTasks(10)
	ids := taskIDs(next)
	if contains(ids, "test-sqli") || contains(ids, "auth-session") {
		t.Errorf("testing lanes opened before dirbust: %v", ids)
	}
	if !contains(ids, "dirbust") {
		t.Errorf("dirbust should be the ready task after recon, got %v", ids)
	}
	// After dirbust completes, the test tasks + auth unblock.
	p.SetStatus("dirbust", TaskCompleted)
	next = p.NextTasks(10)
	ids = taskIDs(next)
	for _, want := range []string{"test-sqli", "test-xss", "auth-session"} {
		if !contains(ids, want) {
			t.Errorf("after recon+dirbust, %q should be ready; got %v", want, ids)
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

	if got := fireDirectives(t, state, hookPlanner); got.Nudge != "" {
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

func TestEndpointCoverageStaysAgentLocal(t *testing.T) {
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
	// Specialist coverage must NOT satisfy the coordinator's own plan: a
	// shallow delegated probe closing root tasks is what collapsed scan depth
	// from a full multi-hour assessment into a minutes-long run. Only the
	// executing agent's own matrix counts.
	if endpointTestedForClass(coordinator, "https://target.example/api/users", "sqli") {
		t.Fatal("specialist coverage must not satisfy the coordinator's own plan")
	}
	if !endpointTestedForClass(specialist, "https://target.example/api/users", "sqli") {
		t.Fatal("specialist must observe its own coverage")
	}
	if !endpointTestedForClass(specialist, "https://target.example/api/users?id=1", "sqli") {
		t.Fatal("specialist must observe its own coverage under a query-qualified alias")
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
	if state.Plan.Get("recon").Status == TaskCompleted {
		t.Error("ReconDone alone must not complete the recon task while comprehensive recon is outstanding")
	}
	satisfyComprehensiveRecon(state)
	// The /api/* inventory carries API signals; a completed API mapping is
	// part of the comprehensive evidence.
	state.ReconCoverage.APISurfaceDiscovered = true
	reconcilePlan(state)
	if state.Plan.Get("recon").Status != TaskCompleted {
		t.Error("recon should complete once the comprehensive predicate is satisfied")
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
	// 1 deduped model task + the required-class coverage floor + the final
	// ReDoS obligation (empty techs map suppresses the tech lanes).
	wantTasks := 2 + len(defaultVulnClasses(map[string]bool{}))
	if a.state.Plan == nil || len(a.state.Plan.Tasks) != wantTasks {
		t.Errorf("duplicate ids: expected %d task(s) kept (1 deduped + coverage floor), got %d", wantTasks, len(a.state.Plan.Tasks))
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

func TestHookPlannerWaitsForEndpointInventory(t *testing.T) {
	state := NewScanState()
	state.ReconDone = true
	state.Iteration = 5
	state.EndpointsTested["example.test/api/health"] = true
	state.EndpointsTested["example.test/login"] = true

	result := fireDirectives(t, state, hookPlanner)
	if state.Plan != nil || state.PlanBuilt || len(state.DiscoveredEndpoints) != 0 {
		t.Fatal("two observed requests must not become a complete attack-surface plan")
	}
	if !strings.Contains(result.Nudge, "Endpoint Inventory") {
		t.Fatalf("planner should request a grounded route inventory: %q", result.Nudge)
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

// A model-authored plan may be narrower than the required class coverage
// contract; build_plan must append the engine's per-class tasks so the finish
// gate still enforces every vulnerability class. The LLM's own tasks stay
// untouched.
func TestBuildPlanCoverageFloorAppendsRequiredClasses(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.DiscoveredEndpoints = []string{"/eval", "/tokens"}
	args := map[string]string{"tasks": `[
		{"id":"recon","title":"Map surface","phase":1},
		{"id":"test-eval-rce","title":"Test /eval RCE","phase":6,"vuln_class":"rce","endpoint":"/eval"}
	]`}
	res, err := a.buildPlanTool(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("build_plan failed: %s", res.Error)
	}
	represented := map[string]bool{}
	for _, task := range a.state.Plan.Tasks {
		if c := normalizeCoverageClass(task.VulnClass); c != "" {
			represented[c] = true
		}
		if task.ID == "test-eval-rce" && task.Origin != "llm" {
			t.Fatal("LLM-authored task must keep Origin llm")
		}
	}
	for _, class := range defaultVulnClasses(nil) {
		if !represented[class] {
			t.Errorf("coverage floor missing required class %q after build_plan", class)
		}
	}
	if !strings.Contains(res.Output, "Coverage floor") {
		t.Errorf("build_plan output should report the appended coverage floor: %s", res.Output)
	}
}

// Engine coverage-floor tasks cannot be hand-completed without evidence; one
// update_plan call must not substitute for testing the discovered surface.
func TestUpdatePlanAutoTaskRequiresCoverageEvidence(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.Plan = AutoPlan([]string{"/eval"}, nil)

	if res, _ := a.updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "completed"}); res.Error == "" {
		t.Fatal("auto class task completed without evidence must be rejected")
	}
	if got := a.state.Plan.Get("test-sqli").Status; got != TaskPending {
		t.Fatalf("rejected completion must not change status, got %v", got)
	}

	// Cover the endpoint for the class, then completion must succeed.
	markEndpointClassCoverage(a.state, "/eval", "sqli")
	if res, _ := a.updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "completed"}); res.Error != "" {
		t.Fatalf("evidence-backed completion rejected: %s", res.Error)
	}
	if got := a.state.Plan.Get("test-sqli").Status; got != TaskCompleted {
		t.Fatalf("evidence-backed completion should stick, got %v", got)
	}
}

// A coverage-floor task cannot be skipped without a justification note: bare
// no-note skips were the cheapest end-run around the coverage contract.
func TestUpdatePlanAutoTaskSkipRequiresJustification(t *testing.T) {
	a := &Agent{state: NewScanState()}
	a.state.Plan = AutoPlan([]string{"/eval"}, nil)

	if res, _ := a.updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "skipped"}); res.Error == "" {
		t.Fatal("bare no-note skip of an auto class task must be rejected")
	}
	if got := a.state.Plan.Get("test-sqli").Status; got != TaskPending {
		t.Fatalf("rejected skip must not change status, got %v", got)
	}
	res, _ := a.updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "skipped", "notes": "No SQL-backed parameters exist: every discovered endpoint is static content."})
	if res.Error != "" {
		t.Fatalf("justified skip must be accepted: %s", res.Error)
	}
	if got := a.state.Plan.Get("test-sqli").Status; got != TaskSkipped {
		t.Fatalf("justified skip should stick, got %v", got)
	}
}

// LLM-authored tasks keep free status transitions: the model's own scoped
// contract (e.g. "test /eval for RCE") is completed by the model, not gated by
// the engine's per-endpoint matrix heuristics.
func TestUpdatePlanLLMTaskCompletionIsNotEvidenceGated(t *testing.T) {
	a := &Agent{state: NewScanState()}
	plan := NewPlan()
	plan.add(&Task{ID: "test-eval-rce", Title: "Test /eval RCE", Phase: 6, VulnClass: "rce", Endpoint: "/eval", Origin: "llm"})
	a.state.Plan = plan
	if res, _ := a.updatePlanTool(map[string]string{"task_id": "test-eval-rce", "status": "completed"}); res.Error != "" {
		t.Fatalf("LLM task completion must not be evidence-gated: %s", res.Error)
	}
}

// PlanWorkedPhases is the richest per-phase work signal: only COMPLETED tasks
// contribute their phase - skips are dispositions, not work.
func TestPlanWorkedPhasesCountsOnlyCompletedTasks(t *testing.T) {
	a := &Agent{state: NewScanState()}
	plan := NewPlan()
	plan.add(&Task{ID: "auth-session", Title: "Auth", Phase: 5, Status: TaskCompleted})
	plan.add(&Task{ID: "test-sqli", Title: "SQLi", Phase: 6, Status: TaskCompleted})
	plan.add(&Task{ID: "test-xss", Title: "XSS", Phase: 6, Status: TaskCompleted}) // dup phase
	plan.add(&Task{ID: "test-csrf", Title: "CSRF", Phase: 5, Status: TaskSkipped}) // skipped, not worked
	plan.add(&Task{ID: "recon", Title: "Recon", Phase: 1, Status: TaskPending})
	a.state.Plan = plan

	phases := a.PlanWorkedPhases()
	if len(phases) != 2 {
		t.Fatalf("expected phases {5,6}, got %v", phases)
	}
	for _, want := range []int{5, 6} {
		found := false
		for _, p := range phases {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected phase %d in %v", want, phases)
		}
	}
}

// ── Recon coverage model tests ─────────────────────────────────────────────

// Recon must NOT complete with only the legacy booleans (one curl, one
// ffuf, a note, a tech header). The coverage model demands HTTP probing,
// tech fingerprinting, and crawling/JS analysis.
func TestReconIncompleteWithOnlyLegacyBooleans(t *testing.T) {
	a := &Agent{state: NewScanState()}
	s := a.state
	s.ReconDone = true
	s.EndpointInventorySaved = true
	s.DirBustingDone = true
	s.DetectedTechs["nginx"] = true
	// No coverage evidence set.

	if a.reconPhaseComplete() {
		t.Fatal("recon must not complete without coverage evidence (HTTP probing, tech fingerprinting, crawling)")
	}
	reasons := a.reconIncompleteReasons()
	if len(reasons) == 0 {
		t.Fatal("missing-dimension reasons must be reported")
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "HTTP probing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("HTTP probing dimension missing from reasons: %v", reasons)
	}
}

// Full coverage evidence completes recon.
func TestReconCompleteWithCoverageEvidence(t *testing.T) {
	a := &Agent{state: NewScanState()}
	s := a.state
	s.ReconDone = true
	s.EndpointInventorySaved = true
	s.DirBustingDone = true
	s.DirBustingUsedWordlist = true
	s.DetectedTechs["flask"] = true
	s.ReconCoverage.HTTPProbed = true
	s.ReconCoverage.TechFingerprinted = true
	s.ReconCoverage.Crawled = true
	s.ReconCoverage.ContentDiscoveredHosts["example.test"] = true

	if !a.reconPhaseComplete() {
		reasons := a.reconIncompleteReasons()
		t.Fatalf("recon should complete with full evidence, missing: %v", reasons)
	}
}

// N/A marks skip dimensions that genuinely do not apply.
func TestReconNAExempt(t *testing.T) {
	a := &Agent{state: NewScanState()}
	s := a.state
	s.ReconDone = true
	s.EndpointInventorySaved = true
	s.DirBustingDone = true
	s.DirBustingUsedWordlist = true
	s.DetectedTechs["static"] = true
	s.ReconCoverage.HTTPProbed = true
	s.ReconCoverage.TechFingerprinted = true
	s.ReconCoverage.ContentDiscoveredHosts["example.test"] = true
	// No crawling or JS analysis — a static site with no JS.
	s.ReconCoverage.NAMarked["crawling"] = true

	if !a.reconPhaseComplete() {
		reasons := a.reconIncompleteReasons()
		t.Fatalf("crawling N/A should not block completion, missing: %v", reasons)
	}
}

// WorkTracker populates the coverage model from commands.
func TestReconCoverageFromCommands(t *testing.T) {
	state := NewScanState()
	fire := func(command, output string) {
		hookWorkTracker(state, map[string]string{"tool_name": "terminal_execute", "command": command})
		hookReconResultTracker(state, map[string]string{"tool_name": "terminal_execute", "command": command, "output": output})
	}

	// HTTP probe
	fire("curl -sk https://example.test/ -o tmp/main.html", "<html><body>hello</body></html>")
	if !state.ReconCoverage.HTTPProbed {
		t.Fatal("curl should mark HTTPProbed after a valid result")
	}

	// Tech fingerprint
	fire("whatweb https://example.test", "https://example.test [200 OK] Title|x")
	if !state.ReconCoverage.TechFingerprinted {
		t.Fatal("whatweb should mark TechFingerprinted after a valid result")
	}

	// Crawling
	fire("curl -sk https://example.test/robots.txt -o tmp/robots.txt; cat tmp/robots.txt", "User-agent: *\nDisallow: /admin")
	if !state.ReconCoverage.Crawled {
		t.Fatal("robots.txt fetch should mark Crawled after a valid result")
	}

	// JS analysis
	fire("curl -sk https://example.test/static/app.js -o tmp/app.js; grep -oP 'api[^\"]+' tmp/app.js", `webpackChunk(["app"],{42:function(e,t){fetch("/api/v1/orders")}})`)
	if !state.ReconCoverage.JSAnalyzed {
		t.Fatal("JS download should mark JSAnalyzed after a valid result")
	}

	// Content discovery per-host
	fire("ffuf -w /usr/share/wordlists/common.txt -u https://example.test/FUZZ -mc 200", "Progress: 100/100 :: Status: 404")
	if !state.ReconCoverage.ContentDiscoveredHosts["example.test"] {
		t.Fatal("ffuf should mark ContentDiscoveredHosts for the host after a valid result")
	}
}
