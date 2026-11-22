package agent

import (
	"strings"
	"testing"
)

// newCarryOverAgent returns an agent whose saved endpoint inventory is the
// given paths, so build_plan grounds DiscoveredEndpoints in that surface the
// way production does. Returns a setter to change the inventory later.
func newCarryOverAgent(t *testing.T, paths ...string) (*Agent, func(...string)) {
	t.Helper()
	state := NewScanState()
	state.ScanContextID = "plan-carryover-test"
	inventory := ""
	setInventory := func(paths ...string) {
		var sb strings.Builder
		sb.WriteString("## Endpoint Inventory\n")
		for _, p := range paths {
			sb.WriteString("- " + p + "\n")
		}
		inventory = sb.String()
		state.DiscoveredEndpoints = append([]string(nil), paths...)
	}
	setInventory(paths...)
	prev := notesBlobForContext
	notesBlobForContext = func(string) string { return inventory }
	t.Cleanup(func() { notesBlobForContext = prev })
	return &Agent{state: state}, setInventory
}

func mustBuildPlan(t *testing.T, a *Agent, tasks string) string {
	t.Helper()
	res, err := a.buildPlanTool(map[string]string{"tasks": tasks})
	if err != nil {
		t.Fatalf("build_plan returned a Go error: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("build_plan failed: %s", res.Error)
	}
	return res.Output
}

func mustUpdatePlan(t *testing.T, a *Agent, id, status, notes string) {
	t.Helper()
	res, _ := a.updatePlanTool(map[string]string{"task_id": id, "status": status, "notes": notes})
	if res.Error != "" {
		t.Fatalf("update_plan %s → %s failed: %s", id, status, res.Error)
	}
}

func planTaskStatus(t *testing.T, a *Agent, id string) TaskStatus {
	t.Helper()
	task := a.state.Plan.Get(id)
	if task == nil {
		t.Fatalf("task %q missing from plan %s", id, planIDList(a.state.Plan))
		return ""
	}
	return task.Status
}

// A rebuild keeps completed and skipped tasks that are the same task, and
// everything else in the new plan (unsettled, new, and coverage-floor tasks)
// starts pending. This is the observed failure: each mid-scan rebuild reset
// plan progress to zero.
func TestBuildPlanRebuildKeepsMatchingSettledTasks(t *testing.T) {
	a, _ := newCarryOverAgent(t, "/login", "/search", "/api/users")
	mustBuildPlan(t, a, `[
		{"id":"recon","title":"Recon","phase":1},
		{"id":"sqli-login","title":"SQLi on login","phase":6,"vuln_class":"sqli","endpoint":"/login","depends_on":["recon"]},
		{"id":"xss-search","title":"XSS on search","phase":6,"vuln_class":"xss","endpoint":"/search","depends_on":["recon"]},
		{"id":"idor-users","title":"IDOR on users","phase":8,"vuln_class":"idor","endpoint":"/api/users","depends_on":["recon"]},
		{"id":"ssti-search","title":"SSTI on search","phase":6,"vuln_class":"ssti","endpoint":"/search","depends_on":["recon"]}
	]`)
	mustUpdatePlan(t, a, "recon", "completed", "")
	mustUpdatePlan(t, a, "sqli-login", "completed", "username and password tested with boolean and time payloads, no injection")
	mustUpdatePlan(t, a, "xss-search", "blocked_policy", "search is out of scope per the engagement rules")
	mustUpdatePlan(t, a, "idor-users", "active", "")

	// Same tasks, with harmless endpoint spelling differences, plus one new
	// task. The class is written as an alias on one task.
	out := mustBuildPlan(t, a, `[
		{"id":"recon","title":"Recon","phase":1},
		{"id":"sqli-login","title":"SQLi on login form","phase":6,"vuln_class":"sql-injection","endpoint":" /login/ ","depends_on":["recon"]},
		{"id":"xss-search","title":"XSS on search","phase":6,"vuln_class":"xss","endpoint":"/search?q=1","depends_on":["recon"]},
		{"id":"idor-users","title":"IDOR on users","phase":8,"vuln_class":"idor","endpoint":"/api/users","depends_on":["recon"]},
		{"id":"ssti-search","title":"SSTI on search","phase":6,"vuln_class":"ssti","endpoint":"/search","depends_on":["recon"]},
		{"id":"ssrf-fetch","title":"SSRF on fetch","phase":7,"vuln_class":"ssrf","endpoint":"/fetch","depends_on":["recon"]}
	]`)

	if got := planTaskStatus(t, a, "recon"); got != TaskCompleted {
		t.Errorf("recon = %s, want completed (kept)", got)
	}
	sqli := a.state.Plan.Get("sqli-login")
	if sqli.Status != TaskCompleted {
		t.Errorf("sqli-login = %s, want completed (kept)", sqli.Status)
	}
	if !strings.Contains(sqli.Notes, "boolean and time payloads") {
		t.Errorf("sqli-login lost its completion notes: %q", sqli.Notes)
	}
	xss := a.state.Plan.Get("xss-search")
	if xss.Status != TaskSkipped || xss.Disposition != DispositionBlockedPolicy {
		t.Errorf("xss-search = %s/%q, want skipped/%s (kept)", xss.Status, xss.Disposition, DispositionBlockedPolicy)
	}
	if !strings.Contains(xss.Notes, "out of scope") {
		t.Errorf("xss-search lost its disposition notes: %q", xss.Notes)
	}

	// Never completed before → never completed by the rebuild. Active work
	// and new tasks start pending, and so does every coverage-floor task.
	for _, task := range a.state.Plan.Tasks {
		switch task.ID {
		case "recon", "sqli-login", "xss-search":
			continue
		}
		if task.Status != TaskPending {
			t.Errorf("task %q (origin %s) = %s, want pending", task.ID, task.Origin, task.Status)
		}
	}
	if _, _, completed, skipped := a.state.Plan.Counts(); completed != 2 || skipped != 1 {
		t.Errorf("counts after rebuild: %d completed, %d skipped; want 2 and 1", completed, skipped)
	}

	for _, want := range []string{
		"Progress kept: 3 task(s)",
		"(2 completed, 1 skipped)",
		"[sqli-login] phase 6 — SQLi on login form (completed, kept from the previous plan)",
		"(skipped: blocked_policy, kept from the previous plan)",
		"Record progress with update_plan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("build_plan output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Reopened") {
		t.Errorf("nothing should be reported reopened:\n%s", out)
	}
}

// Reusing an id for different work (another class, another endpoint, or an
// engine coverage task in place of a model task) is not the same task and
// must start pending.
func TestBuildPlanRebuildDoesNotCarryChangedTask(t *testing.T) {
	a, _ := newCarryOverAgent(t, "/login", "/search", "/profile")
	mustBuildPlan(t, a, `[
		{"id":"recon","title":"Recon","phase":1},
		{"id":"probe-a","title":"Probe A","phase":6,"vuln_class":"sqli","endpoint":"/login","depends_on":["recon"]},
		{"id":"probe-b","title":"Probe B","phase":6,"vuln_class":"xss","endpoint":"/search","depends_on":["recon"]},
		{"id":"probe-c","title":"Probe C","phase":6,"vuln_class":"ssti","endpoint":"/search","depends_on":["recon"]},
		{"id":"test-path_traversal","title":"LFI everywhere","phase":6,"vuln_class":"lfi","depends_on":["recon"]}
	]`)
	mustUpdatePlan(t, a, "probe-a", "completed", "login tested for sqli")
	mustUpdatePlan(t, a, "probe-b", "completed", "search tested for xss")
	mustUpdatePlan(t, a, "probe-c", "exhausted", "every reflected parameter on /search was tried with template payloads")
	mustUpdatePlan(t, a, "test-path_traversal", "completed", "model-marked without engine coverage")

	// probe-a: same endpoint, different class. probe-b: same class,
	// different endpoint. probe-c: same class, different endpoint (a skip).
	// test-path_traversal: the model drops lfi, so the engine's coverage-floor task
	// takes the id test-path_traversal; a model task's completion must not close it.
	out := mustBuildPlan(t, a, `[
		{"id":"recon","title":"Recon","phase":1},
		{"id":"probe-a","title":"Probe A","phase":6,"vuln_class":"ssti","endpoint":"/login","depends_on":["recon"]},
		{"id":"probe-b","title":"Probe B","phase":6,"vuln_class":"xss","endpoint":"/profile","depends_on":["recon"]},
		{"id":"probe-c","title":"Probe C","phase":6,"vuln_class":"ssti","endpoint":"/profile","depends_on":["recon"]}
	]`)
	lfi := a.state.Plan.Get("test-path_traversal")
	if lfi == nil || lfi.Origin != "auto" {
		t.Fatalf("expected the path_traversal coverage-floor task under id test-path_traversal, got %+v", lfi)
	}
	for _, id := range []string{"probe-a", "probe-b", "probe-c", "test-path_traversal"} {
		if got := planTaskStatus(t, a, id); got != TaskPending {
			t.Errorf("%s = %s, want pending (scope changed)", id, got)
		}
	}
	if !strings.Contains(out, "Reopened as pending (4)") {
		t.Errorf("build_plan output should report the 4 reopened tasks:\n%s", out)
	}
	if !strings.Contains(out, "Progress kept: 0 task(s)") {
		t.Errorf("build_plan output should report that no progress was kept:\n%s", out)
	}
}

// Engine coverage-floor tasks close only on engine-verified coverage. A
// rebuild keeps such a completion while the coverage still holds, and
// reopens it when the surface grew and the class is untested on the new
// endpoint, exactly as reconcilePlan would judge it.
func TestBuildPlanRebuildCoverageFloorTaskFollowsCoverage(t *testing.T) {
	a, setInventory := newCarryOverAgent(t, "/api/search")
	const tasks = `[{"id":"recon","title":"Recon","phase":1}]`
	mustBuildPlan(t, a, tasks)
	floor := a.state.Plan.Get("test-sqli")
	if floor == nil || floor.Origin != "auto" {
		t.Fatalf("expected an engine coverage-floor task test-sqli, got %+v", floor)
	}
	if len(ApplicableEndpointsForClass(a.state, "sqli")) == 0 {
		t.Fatal("test precondition: sqli must apply to /api/search")
	}
	// The existing rule: no hand-completion without coverage evidence.
	if res, _ := a.updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "completed", "notes": "done"}); res.Error == "" {
		t.Fatal("test-sqli must not be hand-completable without coverage")
	}
	markEndpointClassCoverage(a.state, "/api/search", "sqli")
	mustUpdatePlan(t, a, "test-sqli", "completed", "")

	// Same surface: the coverage still holds, so the completion is kept.
	mustBuildPlan(t, a, tasks)
	if got := planTaskStatus(t, a, "test-sqli"); got != TaskCompleted {
		t.Fatalf("test-sqli = %s, want completed (coverage still holds)", got)
	}

	// The surface grows; the new endpoint has no sqli coverage. The old
	// completion no longer meets the coverage rule, so it is reopened.
	setInventory("/api/search", "/api/users")
	out := mustBuildPlan(t, a, tasks)
	if got := planTaskStatus(t, a, "test-sqli"); got != TaskPending {
		t.Fatalf("test-sqli = %s, want pending (/api/users untested for sqli)", got)
	}
	if !strings.Contains(out, "Reopened as pending (1): test-sqli") {
		t.Errorf("build_plan output should report test-sqli reopened:\n%s", out)
	}
	if !taskNeedsCoverage(a.state, a.state.Plan.Get("test-sqli")) {
		t.Error("the reopened task must still need coverage on /api/users")
	}

	// Once the new endpoint is covered the engine closes it as before.
	markEndpointClassCoverage(a.state, "/api/users", "sqli")
	reconcilePlan(a.state)
	if got := planTaskStatus(t, a, "test-sqli"); got != TaskCompleted {
		t.Fatalf("test-sqli = %s, want completed after full coverage", got)
	}
}

// Engine-only closures record work that was NOT done (stuck-task recovery,
// the principled finish). A rebuild has always reopened them and still must.
func TestBuildPlanRebuildReopensEngineOnlyClosures(t *testing.T) {
	a, _ := newCarryOverAgent(t, "/api/search")
	const tasks = `[{"id":"recon","title":"Recon","phase":1}]`
	mustBuildPlan(t, a, tasks)
	closures := map[string]string{
		"test-sqli": DispositionBlockedNoProgress,
		"test-xss":  DispositionUntestedAtFinish,
		"test-ssti": DispositionCoverageSufficient,
	}
	for id, d := range closures {
		task := a.state.Plan.Get(id)
		if task == nil {
			t.Fatalf("missing coverage-floor task %q", id)
			return
		}
		task.Status = TaskSkipped
		task.Disposition = d
		task.Notes = "engine closure"
	}
	mustBuildPlan(t, a, tasks)
	for id := range closures {
		if got := planTaskStatus(t, a, id); got != TaskPending {
			t.Errorf("%s = %s, want pending (engine-only closure must not carry)", id, got)
		}
	}
}

// A typed skip of a coverage-floor task carries while the surface it was
// judged on still supports it, and reopens when the surface contradicts it.
func TestBuildPlanRebuildCoverageFloorSkipRevalidated(t *testing.T) {
	a, _ := newCarryOverAgent(t, "/api/search")
	const tasks = `[{"id":"recon","title":"Recon","phase":1}]`
	mustBuildPlan(t, a, tasks)

	// A blocked_* disposition is not a surface claim: it is kept.
	mustUpdatePlan(t, a, "test-ssti", "blocked_unreachable", "the template preview service times out on every request")
	// A not_applicable claim with applicable endpoints, judged on this exact
	// surface: kept while the surface is unchanged.
	if len(ApplicableEndpointsForClass(a.state, "sqli")) == 0 {
		t.Fatal("test precondition: sqli must apply to /api/search")
	}
	mustUpdatePlan(t, a, "test-sqli", "not_applicable", "the search endpoint is served from a static prebuilt index with no database")

	mustBuildPlan(t, a, tasks)
	if task := a.state.Plan.Get("test-ssti"); task.Status != TaskSkipped || task.Disposition != DispositionBlockedUnreachable {
		t.Errorf("test-ssti = %s/%q, want skipped/%s (kept)", task.Status, task.Disposition, DispositionBlockedUnreachable)
	}
	if task := a.state.Plan.Get("test-sqli"); task.Status != TaskSkipped || task.Disposition != DispositionNotApplicable {
		t.Errorf("test-sqli = %s/%q, want skipped/%s (kept on an unchanged surface)", task.Status, task.Disposition, DispositionNotApplicable)
	}

	// Change the surface the N/A was judged on: the judgment no longer
	// matches, applicable endpoints exist, so the task is reopened.
	a.state.Plan.Get("test-sqli").DispositionSurface = "stale-surface"
	mustBuildPlan(t, a, tasks)
	if got := planTaskStatus(t, a, "test-sqli"); got != TaskPending {
		t.Errorf("test-sqli = %s, want pending (N/A contradicted by the current surface)", got)
	}
}

// taskNeedsCoverage is the reconcile-side view: the engine would not close the
// task from the current coverage matrix.
func taskNeedsCoverage(state *ScanState, task *Task) bool {
	return task != nil && !taskCoverageComplete(state, task)
}
