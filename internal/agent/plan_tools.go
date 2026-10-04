// Package agent — plan_tools.go registers the build_plan / update_plan tools.
//
// The structural planner (planner.go) auto-builds a plan from the seeded attack
// surface + recon once an endpoint inventory exists. These tools let the LLM
// replace or refine that plan with knowledge only it has — the live recon
// output the engine can't fully parse (e.g. JS-bundle-mined API routes, an auth
// flow it traced through the browser). The engine tracks the resulting plan and
// the finish gate + per-iteration nudge consult it, so an LLM-authored plan gets
// the same coverage enforcement as an auto-generated one.
//
// Why both tools exist:
//   - build_plan: replace the whole plan (used once after recon, or when the
//     model realizes the auto-plan missed a class/endpoint).
//   - update_plan: transition one task's status (pending→active→completed/
//     skipped) as the model works it, so the plan reflects progress without a
//     full rebuild.
//
// The tools are intentionally tolerant of malformed input — a bad task ID or
// status is reported back as a tool result (so the model self-corrects) rather
// than erroring out of the loop.
package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// planTaskInput is the LLM-supplied task shape for build_plan.
type planTaskInput struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Phase     int      `json:"phase"`
	VulnClass string   `json:"vuln_class"`
	Endpoint  string   `json:"endpoint"`
	DependsOn []string `json:"depends_on"`
	Notes     string   `json:"notes"`
}

// registerPlanTools adds build_plan and update_plan to the registry. The agent
// state is captured by closure so the tools mutate the live ScanState plan
// (shared across sub-agents via the ScanContext).
func (a *Agent) registerPlanTools(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name: "build_plan",
		Description: "Build or replace the structured scan plan as an ordered task graph. " +
			"Call this after recon once you know the real endpoint surface, OR when you realize the " +
			"current plan missed a vuln class / endpoint. Each task is coarse-grained (e.g. " +
			"'test /api/users for injection'), maps to a methodology phase (1-22), and may depend on " +
			"other task IDs. The engine tracks completion and will NOT let you finish until the plan " +
			"is complete (or the surface is exhausted). Pass tasks as a JSON array.",
		Parameters: []tools.Parameter{
			{Name: "tasks", Description: "JSON array of tasks: [{\"id\",\"title\",\"phase\",\"vuln_class\",\"endpoint\",\"depends_on\":[ids],\"notes\"}]. Use stable ids like 'test-sqli'. phase is 1-22.", Required: true},
		},
		Execute: a.buildPlanTool,
	})

	reg.Register(&tools.Tool{
		Name: "update_plan",
		Description: "Update a task only when the engine cannot infer its state: mark it active, " +
			"record a typed concrete disposition, or complete exploratory work with notes naming " +
			"the tests performed. The engine auto-completes coverage-backed tasks; do not " +
			"hand-complete uncovered inputs. Every skipped engine-owned task needs a concrete " +
			"reason note, and observed testable inputs must be tested rather than skipped.",
		Parameters: []tools.Parameter{
			{Name: "task_id", Description: "The task id from build_plan. If omitted, the single currently-active task is updated (or, when marking one active, the next pending task).", Required: false},
			{Name: "status", Description: "One of: active, completed, skipped, or a typed disposition: not_applicable, blocked_missing_auth, blocked_missing_second_identity, blocked_unreachable, blocked_policy, exhausted, superseded. A skip or typed disposition on an engine-owned task requires notes with a concrete observed reason; a bare skip is rejected.", Required: false},
			{Name: "notes", Description: "Concrete rationale / finding reference. Required for skipped or typed dispositions on engine-owned tasks and for exploratory completions; name the observed absent surface, blocker, or tests performed. For the recon task, N/A dimensions use lines like 'service_discovery: raw IP target, no port surface beyond HTTP'.", Required: false},
		},
		Execute: a.updatePlanTool,
	})
}

// buildPlanTool replaces the scan plan from a JSON task array.
func (a *Agent) buildPlanTool(args map[string]string) (tools.Result, error) {
	raw := strings.TrimSpace(args["tasks"])
	if raw == "" {
		return tools.Result{Error: "tasks is required (a JSON array of task objects)"}, nil
	}
	var inputs []planTaskInput
	if err := json.Unmarshal([]byte(raw), &inputs); err != nil {
		return tools.Result{Error: "invalid tasks JSON: " + err.Error() + " — expected an array like [{\"id\":\"test-sqli\",\"title\":\"...\",\"phase\":6,\"vuln_class\":\"sqli\",\"depends_on\":[\"recon\"]}]"}, nil
	}
	if len(inputs) == 0 {
		return tools.Result{Error: "tasks array is empty — pass at least one task"}, nil
	}

	plan := NewPlan()
	var warnings []string
	for _, in := range inputs {
		id := strings.TrimSpace(in.ID)
		if id == "" {
			warnings = append(warnings, "a task with no id was dropped")
			continue
		}
		t := &Task{
			ID:        id,
			Title:     strings.TrimSpace(in.Title),
			Phase:     clampPhase(in.Phase),
			VulnClass: strings.ToLower(strings.TrimSpace(in.VulnClass)),
			Endpoint:  strings.TrimSpace(in.Endpoint),
			Status:    TaskPending,
			DependsOn: trimIDList(in.DependsOn),
			Notes:     strings.TrimSpace(in.Notes),
			Origin:    "llm",
		}
		if isReDoSTask(t) {
			t.VulnClass = "redos"
			t.WholeTarget = true
		}
		if t.Title == "" {
			t.Title = id
		}
		if a.state.DelegatedAgent && a.state.LaneScoped && t.VulnClass != "" && !classAllowedForState(a.state, t.VulnClass) {
			return tools.Result{Error: fmt.Sprintf("class %q is outside your delegated lane; plan only your assigned classes", t.VulnClass)}, nil
		}
		if !plan.add(t) {
			warnings = append(warnings, fmt.Sprintf("duplicate task id %q was dropped", id))
		}
	}
	if plan.IsEmpty() {
		return tools.Result{Error: "no valid tasks after parsing (every task needs a unique id)"}, nil
	}

	// ── Coverage floor ──
	// A model-authored plan can be as narrow as the hypotheses the model found
	// interesting half a minute into the scan, and the finish gate trusts the
	// plan as the whole completion contract — so a narrow plan silently drops
	// entire vulnerability classes (observed in production: an 11-task bespoke
	// plan completed in 132 iterations yielded 5 findings on a target that
	// yields 17+). Append the engine's per-class task for every required class
	// the plan does not already cover. These tasks carry Origin "auto": they
	// close only on engine-verified endpoint x class coverage, never on a bare
	// update_plan call.
	represented := map[string]bool{}
	for _, t := range plan.Tasks {
		if c := normalizeCoverageClass(t.VulnClass); c != "" {
			represented[c] = true
		}
	}
	var floorClasses []string
	for _, class := range defaultVulnClasses(a.state.DetectedTechs) {
		if a.state.DelegatedAgent && !a.state.LaneScoped {
			continue
		}
		if represented[class] {
			continue
		}
		// Phase scope: the coverage floor only demands classes whose
		// canonical phase is part of the operator's selection.
		if !classAllowedForState(a.state, class) {
			continue
		}
		t := newCoverageTask(class, a.state.DiscoveredEndpoints)
		if plan.Get(t.ID) != nil {
			t.ID += "-coverage"
		}
		if plan.add(t) {
			floorClasses = append(floorClasses, class)
		}
	}
	if !a.state.DelegatedAgent && classAllowedForState(a.state, "redos") && !hasReDoSTask(plan) {
		if plan.add(newReDoSTask()) {
			floorClasses = append(floorClasses, "redos")
		}
	}

	a.state.Plan = plan
	a.state.PlanBuilt = true
	// Ground the new plan in the discovered endpoints so coverage-gap detection
	// works against it immediately.
	a.state.DiscoveredEndpoints = extractEndpointsFromNotes(a.state)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Plan built: %d tasks.\n", len(plan.Tasks)))
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("  • [%s] phase %d — %s\n", t.ID, t.Phase, t.Title))
	}
	if len(floorClasses) > 0 {
		sb.WriteString(fmt.Sprintf("\nCoverage floor: appended %d required-class tasks (%s). Every vulnerability class is tested before finish; these tasks close only on engine-verified endpoint x class coverage.\n", len(floorClasses), strings.Join(floorClasses, ", ")))
	}
	if len(warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range warnings {
			sb.WriteString("  - " + w + "\n")
		}
	}
	pending, active, completed, skipped := plan.Counts()
	sb.WriteString(fmt.Sprintf("\nStatus: %d pending, %d active, %d completed, %d skipped. Work the tasks in dependency order; the engine tracks completion and gates finish on a complete plan.", pending, active, completed, skipped))
	return tools.Result{Output: sb.String()}, nil
}

// updatePlanTool transitions a task's status.
func (a *Agent) updatePlanTool(args map[string]string) (tools.Result, error) {
	id := strings.TrimSpace(args["task_id"])
	status := strings.ToLower(strings.TrimSpace(args["status"]))
	notes := strings.TrimSpace(args["notes"])

	plan := a.state.Plan
	if plan == nil || plan.IsEmpty() {
		return tools.Result{Error: "no plan exists yet — call build_plan first"}, nil
	}

	// Tolerate the two malformed shapes models emit most — each otherwise burns a
	// whole iteration on a "missing required parameter" rejection, and plan status
	// is advisory bookkeeping that never gates a finding, so inferring is safe:
	//   - status omitted  → "active" (the common intent: the task is being started).
	//   - task_id omitted → the single currently-active task when unambiguous (the
	//                       agent is almost always updating what it is on), else the
	//                       next pending task when marking one active.
	if status == "" {
		status = "active"
	}
	if id == "" {
		if inferred := inferPlanTaskID(plan, status); inferred != "" {
			id = inferred
		} else {
			return tools.Result{Error: fmt.Sprintf("task_id is required — current task ids: %s", planIDList(plan))}, nil
		}
	}
	t := plan.Get(id)
	// Auto-plans use the dependency-aware id "idor" for the IDOR/BOLA lane,
	// while models often extrapolate the otherwise-consistent "test-<class>"
	// naming scheme and call it "test-idor". Resolve a missing test-* id to a
	// unique task with the same canonical class instead of wasting a turn.
	if t == nil && strings.HasPrefix(id, "test-") {
		class := normalizeCoverageClass(strings.TrimPrefix(id, "test-"))
		var match *Task
		for _, candidate := range plan.Tasks {
			if class == "" || normalizeCoverageClass(candidate.VulnClass) != class {
				continue
			}
			if match != nil {
				match = nil // ambiguous: preserve the normal unknown-id error
				break
			}
			match = candidate
		}
		if match != nil {
			t = match
			id = match.ID
		}
	}
	if t == nil {
		return tools.Result{Error: fmt.Sprintf("unknown task id %q — current task ids: %s", id, planIDList(plan))}, nil
	}
	var st TaskStatus
	disposition := ""
	switch status {
	case "active", "in_progress", "in-progress", "inprogress", "started", "start", "working", "doing":
		st = TaskActive
	case "completed", "complete", "done", "finished", "covered":
		st = TaskCompleted
	case "skipped", "skip", "n/a", "na", "not-applicable", "not_applicable", "notapplicable":
		st = TaskSkipped
		disposition = DispositionNotApplicable
	case "blocked_missing_auth", "blocked_missing_second_identity", "blocked_unreachable", "blocked_policy", "exhausted", "superseded":
		st = TaskSkipped
		disposition = status
	default:
		return tools.Result{Error: "status must be one of: active, completed, skipped, or a typed disposition (not_applicable, blocked_missing_auth, blocked_missing_second_identity, blocked_unreachable, blocked_policy, exhausted, superseded) — got " + args["status"]}, nil
	}
	if st == TaskCompleted && isReDoSTask(t) && !a.state.VulnClassesTested["redos"] {
		return tools.Result{Error: "ReDoS testing requires a completed bounded probe against an input before this task can be marked done. A plan update alone is not test evidence."}, nil
	}
	if st == TaskSkipped && isReDoSTask(t) && !a.state.VulnClassesTested["redos"] {
		inputs := observedReDoSInputs(a.state)
		if len(inputs) > 0 && (disposition == DispositionNotApplicable || disposition == DispositionExhausted || disposition == DispositionSuperseded || disposition == DispositionBlockedMissingSecondID) {
			return tools.Result{Error: fmt.Sprintf(
				"ReDoS remains testable on %d observed endpoint(s) (%s). Run a bounded probe in the final stage; only a concrete access, reachability, or policy blocker can disposition this task without a probe.",
				len(inputs), truncList(inputs, 3))}, nil
		}
	}
	// Engine coverage-floor tasks (Origin "auto" with a vulnerability class)
	// cannot be hand-completed: a single update_plan call must not substitute
	// for actually testing the discovered surface. reconcilePlan closes them
	// automatically once the endpoint x class coverage matrix is complete, so
	// a rejection here always means the class is not yet covered.
	// The auth-session task completes on its dimension contract, not on the
	// endpoint x class matrix (auth dimensions are tracked separately).
	authLaneSettled := t.VulnClass == "auth" && authTaskComplete(a.state)
	// Exploratory whole-target lanes (novel discovery, content spoofing,
	// broken-link verification): the engine cannot mechanically verify the
	// exploration itself, so a CONCRETE, non-vague note describing what was
	// exercised is accepted as completion evidence.
	exploratorySettled := t.WholeTarget && VulnClassExploratory(t.VulnClass) &&
		!isVagueDispositionReason(notes) && len(notes) >= 40
	if st == TaskCompleted && t.Origin == "auto" && t.VulnClass != "" && !authLaneSettled && !exploratorySettled && a.state != nil &&
		!taskCoverageComplete(a.state, t) {
		return tools.Result{Error: fmt.Sprintf(
			"task %q (%s) needs coverage evidence before completion. %s Continue testing those inputs, or use status 'not_applicable' with a concrete absent-surface reason if the class does not apply. Notes alone cannot mark untested work completed.",
			id, t.VulnClass, taskCoverageRequirement(a.state, t))}, nil
	}
	// ── Typed disposition validation for engine-owned coverage work ──
	// A coverage-floor task may only be skipped with a TYPED, concrete
	// justification. A bare no-note skip is the cheapest end-run around the
	// coverage contract (a scan was observed issuing ten simultaneous no-note
	// skips to satisfy the finish gate), and vague prose ("probably not
	// applicable") launders exactly the same shortcut, so both are rejected
	// at the transition itself. The engine independently verifies
	// not_applicable claims against the observed surface when it can.
	if st == TaskSkipped && t.Origin == "auto" && t.VulnClass != "" {
		if notes == "" {
			return tools.Result{Error: fmt.Sprintf(
				"task %q (%s) cannot be skipped without a justification note. Use a typed status (not_applicable, blocked_missing_auth, blocked_missing_second_identity, blocked_unreachable, blocked_policy, exhausted, superseded) and state the concrete surface fact (for example: 'no XML input surface exists'); otherwise test it.",
				id, t.VulnClass)}, nil
		}
		if isVagueDispositionReason(notes) {
			return tools.Result{Error: fmt.Sprintf(
				"task %q (%s): %q is a shortcut rationale, not a disposition. State the concrete surface fact (what input/protocol/auth surface is absent or blocked), or use a typed blocked_* status with the specific blocker.",
				id, t.VulnClass, notes)}, nil
		}
		if disposition == DispositionNotApplicable {
			// Engine-verifiable N/A: when the observed surface carries no
			// applicable endpoint for the class, the N/A is confirmed. When
			// applicable endpoints DO exist, the note must at least name the
			// blocking/absent surface element explicitly, and the
			// applicability disagreement is recorded for the audit trail.
			applicable := ApplicableEndpointsForClass(a.state, t.VulnClass)
			if len(applicable) > 0 && len(notes) < 25 {
				return tools.Result{Error: fmt.Sprintf(
					"task %q (%s): the observed surface has %d endpoint(s) where %s applies (%s). not_applicable needs a concrete reason naming the absent surface element, or test the class.",
					id, t.VulnClass, len(applicable), t.VulnClass, truncList(applicable, 3))}, nil
			}
		}
	}
	// Auth-task notes carry per-dimension typed dispositions
	// (token_identity: blocked_missing_second_identity — ...).
	if st == TaskSkipped && t.VulnClass == "auth" && notes != "" {
		if extras := applyAuthDispositions(a.state, notes); len(extras) > 0 {
			notes = notes + "\n[engine recorded] " + strings.Join(extras, "; ")
		}
	}
	// Recon-task typed N/A also wires the ReconCoverage dimension dispositions
	// (the only real mutation path for NAMarked) and per-host discovery
	// dispositions: notes lines like "service_discovery: reason" or
	// "host api.example.com: blocked".
	if st == TaskSkipped && t.VulnClass == "" && notes != "" {
		if extras := applyReconDispositions(a.state, notes); len(extras) > 0 {
			notes = notes + "\n[engine recorded] " + strings.Join(extras, "; ")
		}
	}
	t.Status = st
	t.Disposition = disposition
	t.DispositionSurface = ""
	if st == TaskSkipped && disposition == DispositionNotApplicable && t.Origin == "auto" && t.VulnClass != "" {
		t.DispositionSurface = dispositionSurfaceSignature(a.state, t)
	}
	if notes != "" {
		if t.Notes != "" {
			t.Notes += " | " + notes
		} else {
			t.Notes = notes
		}
	}
	pending, active, completed, skipped := plan.Counts()
	label := string(st)
	if disposition != "" {
		label += " (" + disposition + ")"
	}
	return tools.Result{Output: fmt.Sprintf("Task %q → %s. Plan: %d pending, %d active, %d completed, %d skipped (%d%% executed; skips are not executed coverage).", id, label, pending, active, completed, skipped, plan.ProgressPct())}, nil
}

func taskCoverageRequirement(state *ScanState, task *Task) string {
	if task.WholeTarget {
		return "The target-level class evidence is still missing."
	}
	var missing []string
	for _, endpoint := range ApplicableEndpointsForClass(state, task.VulnClass) {
		if !endpointTestedForClass(state, endpoint, task.VulnClass) {
			missing = append(missing, endpoint)
		}
	}
	if len(missing) == 0 {
		return "The class evidence is still missing."
	}
	return fmt.Sprintf("Untested applicable endpoints (%d): %s.", len(missing), truncList(missing, 6))
}

// inferPlanTaskID picks the task an update_plan call with no task_id most likely
// means: the single task currently active (the agent is updating what it is
// working on) or — when marking something active with none active yet — the next
// pending task. Returns "" when the choice is ambiguous, so the caller can ask
// for an explicit id.
func inferPlanTaskID(plan *Plan, status string) string {
	if plan == nil {
		return ""
	}
	var active []*Task
	for _, t := range plan.Tasks {
		if t.Status == TaskActive {
			active = append(active, t)
		}
	}
	if len(active) == 1 {
		return active[0].ID
	}
	if len(active) == 0 {
		switch status {
		case "active", "in_progress", "in-progress", "inprogress", "started", "start", "working", "doing":
			if next := plan.NextTasks(1); len(next) == 1 {
				return next[0].ID
			}
		}
	}
	return ""
}

// clampPhase forces a phase into the 1-22 methodology range.
func clampPhase(p int) int {
	if p < 1 {
		return 1
	}
	if p > 22 {
		return 22
	}
	return p
}

// trimIDList cleans a dependency ID list (drops empties).
func trimIDList(ids []string) []string {
	var out []string
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// planIDList returns a comma-separated list of a plan's task ids for error
// messages.
func planIDList(p *Plan) string {
	if p == nil {
		return ""
	}
	ids := make([]string, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		ids = append(ids, t.ID)
	}
	return strings.Join(ids, ", ")
}
