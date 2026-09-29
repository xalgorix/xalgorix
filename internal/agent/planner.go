// Package agent — planner.go implements a structural, coverage-grounded task
// planner. This is the "decomposition" layer that was previously left entirely
// to the LLM: instead of the model self-decomposing by following the 22-phase
// methodology text and hoping it covers the surface, the engine now turns a
// scan goal into an ordered, dependency-tracked Task graph grounded in the REAL
// recon data (discovered endpoints + detected technologies + seeded attack
// surface), tracks completion against the existing coverage counters, and
// surfaces the next pending task + remaining coverage gaps to the model every
// iteration.
//
// The planner is deliberately model-in-the-loop, not a rigid waterfall:
//   - The LLM builds/adjusts the plan via the build_plan tool after recon (it
//     knows the live recon output that the engine can't parse), OR the engine
//     auto-generates a plan from the seeded attack surface + methodology.
//   - The engine tracks task status and recomputes coverage gaps from
//     ScanState so a model that "forgets" a phase or an endpoint is nudged back
//     to the next pending task instead of looping or finishing early.
//   - The finish gate consults the plan: an unfinished plan blocks finish
//     (with the specific remaining tasks) unless the operator scoped to recon
//     only or the surface is genuinely exhausted.
//
// Design constraints:
//   - No new goroutines / no external state — each agent's Plan lives in its
//     own ScanState. The shared ScanContext remains the cross-agent evidence
//     and memory channel.
//   - Coverage grounding uses EndpointClassCoverage as its authoritative
//     endpoint × class matrix, while retaining the aggregate counters for
//     depth metrics and compatibility with scans created by older versions.
//   - Task generation is bounded: a target with 500 endpoints does not emit
//     500×N tasks; endpoints are grouped by vuln class into a tractable set.
package agent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
)

// TaskStatus is the lifecycle state of a single planned task.
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"   // not yet started
	TaskActive    TaskStatus = "active"    // the model is currently working it
	TaskCompleted TaskStatus = "completed" // done (covered or ruled out)
	TaskSkipped   TaskStatus = "skipped"   // not applicable (e.g. no auth surface)
)

// Task is one unit of work in the plan. A task is coarse-grained on purpose —
// "test endpoint /api/users for injection" is a task; "send a single quote to
// /api/users?id=1" is the model's job inside it. Coarse tasks keep the graph
// small and the coverage math meaningful.
type Task struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Phase     int        `json:"phase"`      // methodology phase this task maps to (1-22)
	VulnClass string     `json:"vuln_class"` // "sqli","xss","idor","ssrf","ssti",... ("" for recon/ops)
	Endpoint  string     `json:"endpoint"`   // specific endpoint/URL this targets ("" = whole target)
	Status    TaskStatus `json:"status"`
	DependsOn []string   `json:"depends_on"`       // task IDs that must complete first
	Notes     string     `json:"notes,omitempty"`  // free-form rationale / finding refs
	Origin    string     `json:"origin,omitempty"` // "auto" (engine-generated) or "llm" (model-built)
	// Disposition is the TYPED terminal reason when a task does not complete:
	// not_applicable, blocked_missing_auth, blocked_missing_second_identity,
	// blocked_unreachable, blocked_policy, exhausted, superseded — or "" when
	// the task completed (or was skipped legacy-style before typed
	// dispositions existed). Skipped-without-disposition remains readable for
	// old persisted plans.
	Disposition string `json:"disposition,omitempty"`
	// Prerequisite marks a task as a TECHNICAL PREREQUISITE for the
	// selected phases rather than a methodology obligation of its own
	// phase: a restricted phase selection still needs bounded discovery
	// (routes to find upload functionality, subdomains for takeover
	// checks), but that work must never make its phase read as
	// selected/executed methodology.
	Prerequisite bool `json:"prerequisite,omitempty"`
	// WholeTarget marks engine tasks whose class methodology is
	// target-scoped (CORS policy, mail posture, CMS posture, ...): they
	// complete on scan-level class evidence (VulnClassesTested) instead of
	// the per-endpoint coverage matrix.
	WholeTarget bool `json:"whole_target,omitempty"`
}

// Typed disposition values (Part 13). All map onto TaskSkipped for plan
// counting — they are terminal "not executed" states, never completed
// coverage — but each carries an explicit, auditable reason category so vague
// prose cannot launder work away.
const (
	DispositionNotApplicable          = "not_applicable"
	DispositionBlockedMissingAuth     = "blocked_missing_auth"
	DispositionBlockedMissingSecondID = "blocked_missing_second_identity"
	DispositionBlockedUnreachable     = "blocked_unreachable"
	DispositionBlockedPolicy          = "blocked_policy"
	DispositionExhausted              = "exhausted"
	DispositionSuperseded             = "superseded"
)

// vagueDispositionReasons are the shortcut rationalizations that cannot clear
// an engine-owned coverage task. The model must state a concrete surface fact
// or a typed blocked reason instead.
var vagueDispositionReasons = []string{
	"likely not vulnerable",
	"probably not applicable",
	"probably not relevant",
	"nothing interesting",
	"nothing found",
	"no obvious",
	"already found another bug",
	"one finding is enough",
	"already achieved",
	"not worth",
	"low value",
	"low priority",
	"out of time",
	"no time to",
	"moving on",
	"skipping for now",
	"seems fine",
	"looks safe",
}

// Plan is the ordered task graph for one scan.
type Plan struct {
	Tasks []*Task `json:"tasks"`
	// index is rebuilt on every mutation for O(1) lookup by ID.
	index map[string]*Task
}

// NewPlan returns an empty plan with its index initialized.
func NewPlan() *Plan {
	return &Plan{index: make(map[string]*Task)}
}

// add inserts a task, rebuilding the index. Duplicate IDs are rejected.
func (p *Plan) add(t *Task) bool {
	if t.ID == "" {
		return false
	}
	if _, exists := p.index[t.ID]; exists {
		return false
	}
	p.Tasks = append(p.Tasks, t)
	p.index[t.ID] = t
	return true
}

// Get returns the task by ID, or nil.
func (p *Plan) Get(id string) *Task {
	if p == nil {
		return nil
	}
	return p.index[id]
}

// SetStatus transitions a task and returns the task (or nil if not found).
func (p *Plan) SetStatus(id string, status TaskStatus) *Task {
	t := p.Get(id)
	if t == nil {
		return nil
	}
	t.Status = status
	return t
}

// Counts returns aggregate status counts for the plan.
func (p *Plan) Counts() (pending, active, completed, skipped int) {
	if p == nil {
		return
	}
	for _, t := range p.Tasks {
		switch t.Status {
		case TaskPending:
			pending++
		case TaskActive:
			active++
		case TaskCompleted:
			completed++
		case TaskSkipped:
			skipped++
		}
	}
	return
}

// IsEmpty reports whether the plan has no tasks.
func (p *Plan) IsEmpty() bool {
	return p == nil || len(p.Tasks) == 0
}

// RemainingCount is the number of tasks not yet completed or skipped.
func (p *Plan) RemainingCount() int {
	pending, active, _, _ := p.Counts()
	return pending + active
}

// ProgressPct returns the whole-percent share of tasks actually EXECUTED
// (completed over total). Skipped work is deliberately excluded: a plan with
// 12 completed and 8 justified-skip tasks is 60% executed, not 100% — folding
// skips into a completion percentage presented a dispositioned plan as full
// assessed coverage. Returns 0 for an empty plan.
func (p *Plan) ProgressPct() int {
	if p == nil || len(p.Tasks) == 0 {
		return 0
	}
	_, _, completed, _ := p.Counts()
	return int(float64(completed) / float64(len(p.Tasks)) * 100)
}

// NextTasks returns the tasks that are ready to run: status pending AND every
// dependency is completed or skipped. Limited to `limit` results, ordered by
// phase then ID for deterministic output. When no dependency-ready tasks remain
// but pending tasks exist (stuck on an unmet dependency), it returns the
// lowest-phase pending tasks so the scan never deadlocks on a malformed graph.
func (p *Plan) NextTasks(limit int) []*Task {
	if p == nil || limit <= 0 {
		return nil
	}
	var ready []*Task
	for _, t := range p.Tasks {
		if t.Status != TaskPending {
			continue
		}
		if p.dependenciesSatisfied(t) {
			ready = append(ready, t)
		}
	}
	if len(ready) == 0 {
		// No dependency-ready tasks, but some are pending — return the
		// lowest-phase pending ones rather than stalling forever.
		for _, t := range p.Tasks {
			if t.Status == TaskPending {
				ready = append(ready, t)
			}
		}
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].Phase != ready[j].Phase {
			return ready[i].Phase < ready[j].Phase
		}
		return ready[i].ID < ready[j].ID
	})
	if len(ready) > limit {
		ready = ready[:limit]
	}
	return ready
}

// dependenciesSatisfied reports whether all of a task's dependencies are
// completed or skipped (i.e. no longer blocking).
func (p *Plan) dependenciesSatisfied(t *Task) bool {
	for _, depID := range t.DependsOn {
		dep := p.Get(depID)
		if dep == nil {
			continue // unknown dependency — don't block on it
		}
		if dep.Status != TaskCompleted && dep.Status != TaskSkipped {
			return false
		}
	}
	return true
}

// CoverageGap is one (vuln class, endpoint) pair that the discovered surface
// has not yet been tested for. CoverageGaps recomputes these from the live
// ScanState coverage counters, grounded in the endpoints recon surfaced, so the
// model is nudged to the next gap instead of self-declaring a phase "done" after
// one payload.
type CoverageGap struct {
	VulnClass string
	Endpoint  string
	Reason    string
}

// requiredCoverageClasses is the single contract shared by gap detection and
// auto-plan generation. Keeping these lists separate previously made the
// planner demand CRLF/SSTI work for task IDs it had never created, wasting
// model turns and allowing the plan and finish gate to disagree.
func requiredCoverageClasses() []string {
	return []string{
		"sqli",
		"xss",
		"idor",
		"ssrf",
		"ssti",
		"cmdi",
		"path_traversal",
		"crlf",
		"xxe",
		"csrf",
		"parameter_mining",
	}
}

// CoverageGaps returns the structured gap list. discoveredEndpoints is the set
// of endpoints the recon surfaced (from notes / attack-surface seeding);
// state provides what's already been tested. A gap exists for each (class,
// endpoint) pair where the endpoint was discovered but not tested for that
// class.
func CoverageGaps(state *ScanState, discoveredEndpoints []string) []CoverageGap {
	if state == nil {
		return nil
	}
	classes := requiredCoverageClasses()
	// Phase-scope filter: a restricted phase selection must not keep
	// demanding engine obligations for excluded lanes (e.g. SQLi gaps on a
	// file-upload-only scan).
	if len(state.AllowedPhases) > 0 {
		filtered := make([]string, 0, len(classes))
		for _, c := range classes {
			if classAllowedForSelection(state.AllowedPhases, c) {
				filtered = append(filtered, c)
			}
		}
		classes = filtered
	}
	var gaps []CoverageGap
	// Per-endpoint × per-class gap detection. When no endpoints were discovered
	// (pure black-box, no seeded surface), fall back to whole-target gaps for
	// any class not yet tested at all — so the nudge still surfaces missing
	// vuln classes.
	if len(discoveredEndpoints) == 0 {
		for _, class := range classes {
			if !state.VulnClassesTested[class] {
				gaps = append(gaps, CoverageGap{VulnClass: class, Endpoint: "", Reason: fmt.Sprintf("vuln class %q not tested on any endpoint yet", class)})
			}
		}
		return gaps
	}
	sort.Strings(discoveredEndpoints)
	for _, ep := range discoveredEndpoints {
		for _, class := range classes {
			// Applicability filter: only (class, endpoint) pairs the observed
			// surface makes testable are coverage obligations. /robots.txt
			// owes no XXE/SSTI/CSRF probe; an XML route always owes XXE.
			if !classAppliesToEndpoint(state, ep, class) {
				continue
			}
			if !endpointTestedForClass(state, ep, class) {
				gaps = append(gaps, CoverageGap{
					VulnClass: class,
					Endpoint:  ep,
					Reason:    fmt.Sprintf("endpoint %q not tested for %s", ep, class),
				})
			}
		}
	}
	return gaps
}

// applicabilityExtraClasses are the canonical classes outside the fixed
// baseline floor that become REAL plan tasks only when the observed surface
// carries applicable endpoints (workflow routes owe business-logic and
// race-condition work; upload routes owe file-upload testing; GraphQL and
// WebSocket surfaces owe their dedicated lanes). This is how the planner
// stops being a small fixed class floor without exploding into a Cartesian
// endpoint × class matrix.
var applicabilityExtraClasses = []string{
	"business-logic",
	"race-conditions",
	"mass-assignment",
	"file-upload",
	"websocket",
	"graphql",
	"nosqli",
	"deserialization",
	"open-redirect",
	"cors",
	"secret-exposure",
	"dom-xss",
	"privilege-escalation",
	"auth-bypass",
}

// AutoPlanFromState builds the engine plan with BOTH the applicability layer
// and the operator's phase selection applied: the baseline floor plus one
// task per extra class that has at least one applicable endpoint, plus the
// target-level obligations whose surface signals exist (CORS/cookies,
// takeover, mail, cloud, CMS, external references, novel discovery).
// Bounded and deterministic; classes with no applicable endpoint and phases
// outside state.AllowedPhases are NOT scheduled — that is the point.
//
// An EMPTY AllowedPhases means the full methodology is allowed; a non-empty
// selection keeps only its own lanes plus the bounded technical
// prerequisites those lanes need (marked Prerequisite, never counted as the
// prerequisite phase's own methodology work).
func AutoPlanFromState(state *ScanState) *Plan {
	if state == nil {
		return NewPlan()
	}
	return buildEnginePlan(state, state.DiscoveredEndpoints, state.DetectedTechs, phaseScopeFor(state.AllowedPhases))
}

// endpointTestedForClass reports whether this exact endpoint has coverage
// evidence for a vulnerability class. Global class coverage and a generic
// request to the endpoint are deliberately insufficient: either shortcut can
// make the planner silently skip untested class/endpoint pairs.
func endpointTestedForClass(state *ScanState, endpoint, class string) bool {
	if canonical := normalizeCoverageClass(class); canonical != "" {
		class = canonical
	}
	aliases := endpointCoverageLookupAliases(endpoint)
	hasEndpointMatrixEvidence := false
	// Only the agent's OWN per-endpoint matrix satisfies coverage. Coverage
	// executed by a delegated specialist must NOT close the coordinator's
	// plan tasks: a single shallow child probe per endpoint would satisfy
	// taskCoverageComplete and let the whole scan finish in minutes without
	// the coordinator ever exercising the class itself. Specialist work is
	// evidence input for the report, never a substitute for the coordinator's
	// own coverage. The scan-level shared store remains in use for whole-scan
	// markers such as OAST probe completion.
	for _, alias := range aliases {
		if classes, ok := state.EndpointClassCoverage[alias]; ok {
			hasEndpointMatrixEvidence = true
			if classes[class] {
				return true
			}
		}
	}
	// Verifier-attributed scan-level evidence (Part 20): a deterministic
	// verifier that actually executed this (endpoint, class) pair — from ANY
	// agent, root or specialist — is trustworthy coverage. The coordinator
	// is not forced to repeat the probe; at the same time, raw request-level
	// child probes remain invisible here, so one shallow request still
	// cannot close a class.
	if shared := sharedCoverageForState(state); shared != nil {
		for _, alias := range aliases {
			if shared.HasVerified(alias, class) {
				return true
			}
		}
	}
	if hasEndpointMatrixEvidence {
		return false
	}

	// Compatibility fallback for state produced before the pair matrix was
	// introduced. These maps are coarse, so consult them only when the endpoint
	// has no matrix evidence at all.
	switch class {
	case "sqli":
		if endpointSetContains(state.InjectionEndpoints, aliases) {
			return true
		}
	case "idor":
		if endpointSetContains(state.AccessControlEndpoints, aliases) {
			return true
		}
	}
	return false
}

func endpointSetContains(set map[string]bool, aliases []string) bool {
	for _, alias := range aliases {
		if set[alias] {
			return true
		}
	}
	for endpoint := range set {
		for _, storedAlias := range endpointCoverageAliases(endpoint) {
			for _, wanted := range aliases {
				if storedAlias == wanted {
					return true
				}
			}
		}
	}
	return false
}

// planIsEngineAuthored reports whether every task in the plan came from
// AutoPlan (Origin "auto"). Such a plan may be safely rebuilt from a more
// mature endpoint inventory; a plan containing any LLM-authored task must be
// left alone.
func planIsEngineAuthored(p *Plan) bool {
	if p == nil || len(p.Tasks) == 0 {
		return false
	}
	for _, t := range p.Tasks {
		if t.Origin != "auto" {
			return false
		}
	}
	return true
}

// refreshEnginePlan rebuilds the engine-owned plan from the current
// surface. It is called by the PLANNER whenever the surface revision
// changes — never by delegation code — so plan completeness is identical
// with zero specialists: recon expands the surface while it runs (crawl,
// JS analysis, content discovery, OpenAPI, redirects, DNS), and the plan
// absorbs those discoveries whether or not any specialist exists. An
// LLM-authored plan is never touched.
func refreshEnginePlan(state *ScanState) {
	if state == nil || state.Plan == nil || !planIsEngineAuthored(state.Plan) {
		return
	}
	// Preserve settled outcomes the rebuild cannot re-derive: explicit
	// skipped/NA tasks. Completed work is re-derived by reconcilePlan from
	// the coverage matrix; a skip is a judged disposition, so it survives
	// only while the CURRENT surface still supports it.
	prev := make(map[string]Task)
	for _, t := range state.Plan.Tasks {
		if t.Status == TaskSkipped {
			prev[t.ID] = *t
		}
	}
	state.Plan = AutoPlanFromState(state)
	for _, t := range state.Plan.Tasks {
		old, ok := prev[t.ID]
		if !ok || t.Status != TaskPending {
			continue
		}
		if !skipDispositionStillValid(state, &old) {
			continue
		}
		t.Status = old.Status
		t.Disposition = old.Disposition
		t.Notes = old.Notes
	}
	reconcilePlan(state)
	// New surface means new (class x endpoint) obligations: re-seed the
	// ledger. Upsert dedupes, so this only adds hypotheses the previous
	// seed did not know about — no specialist is needed for the ledger to
	// cover the refreshed plan.
	if l := ledgerForState(state); l != nil {
		seedLedgerFromPlan(state, l)
	}
}

// skipDispositionStillValid re-checks a preserved N/A skip against the
// CURRENT surface: the surface change that triggered the refresh may have
// invalidated it (e.g. auth endpoints appeared after auth-session was
// dispositioned not-applicable).
func skipDispositionStillValid(state *ScanState, t *Task) bool {
	if t == nil || t.Disposition != DispositionNotApplicable {
		return true
	}
	switch t.ID {
	case "auth-session":
		return !authSurfaceExists(state) && !state.AuthContextAvailable
	case "dirbust":
		if t.Prerequisite {
			return true // bounded prerequisite: a typed skip is a settled judgment
		}
		return false // content discovery always applies to web targets
	}
	if t.VulnClass != "" {
		return len(ApplicableEndpointsForClass(state, t.VulnClass)) == 0
	}
	return true
}

// planHasEngineTasks reports whether the plan is MIXED: at least one
// engine-owned (Origin "auto") task exists alongside LLM-authored tasks.
// Mixed plans receive incremental engine-task merging on surface change
// instead of a wholesale rebuild; purely LLM-authored plans are never
// rewritten by the engine.
func planHasEngineTasks(p *Plan) bool {
	if p == nil {
		return false
	}
	for _, t := range p.Tasks {
		if t.Origin == "auto" {
			return true
		}
	}
	return false
}

// refreshPlanForSurface is the single plan-freshness entry point, called by
// the planner hook each iteration and by the finish gate before it evaluates
// completeness. When the surface revision changed since the plan was last
// built: an engine-authored plan is rebuilt (settled outcomes preserved), a
// MIXED plan receives missing engine-owned tasks via MergeRequiredEngineTasks,
// and purely LLM-authored plans only record the new revision. The revision
// is always updated so freshness tracking stays consistent.
func refreshPlanForSurface(state *ScanState) {
	if state == nil || state.Plan == nil || !state.PlanBuilt || len(state.DiscoveredEndpoints) == 0 {
		return
	}
	rev := surfaceRevision(state)
	if rev == state.PlanSurfaceRevision {
		return
	}
	switch {
	case planIsEngineAuthored(state.Plan):
		refreshEnginePlan(state)
	case planHasEngineTasks(state.Plan):
		if MergeRequiredEngineTasks(state, state.Plan) > 0 {
			reconcilePlan(state)
			if l := ledgerForState(state); l != nil {
				seedLedgerFromPlan(state, l)
			}
		}
	}
	state.PlanSurfaceRevision = rev
}

// MergeRequiredEngineTasks incrementally adds MISSING engine-owned tasks to
// an existing (possibly LLM-authored) plan. All existing tasks - model-built
// or engine - keep their status, notes, and dependencies; only absent
// engine obligations are appended, so a later upload endpoint can add the
// file-upload lane without touching any custom task, and a later workflow
// route can add business-logic + race-conditions lanes. Recorded N/A skips
// are revalidated against the CURRENT surface: a skip the new evidence
// contradicts is reopened. Returns the number of tasks added.
func MergeRequiredEngineTasks(state *ScanState, plan *Plan) int {
	if state == nil || plan == nil {
		return 0
	}
	required := AutoPlanFromState(state)
	if required == nil {
		return 0
	}
	added := 0
	for _, t := range required.Tasks {
		existing := plan.Get(t.ID)
		if existing != nil || plan.Get(t.ID+"-coverage") != nil {
			// Reevaluate recorded N/A skips: the surface change that
			// triggered this merge may have invalidated them.
			if existing != nil && existing.Status == TaskSkipped && !skipDispositionStillValid(state, existing) {
				existing.Status = TaskPending
				existing.Disposition = ""
			}
			continue
		}
		// Keep custom dependencies intact; only reference deps that exist
		// in THIS plan so a merged task never waits on a phantom task.
		nt := *t
		nt.DependsOn = nil
		for _, d := range t.DependsOn {
			if plan.Get(d) != nil {
				nt.DependsOn = append(nt.DependsOn, d)
			}
		}
		if nt.Notes != "" {
			nt.Notes += " (added by engine surface refresh)"
		}
		plan.add(&nt)
		added++
	}
	return added
}

// newCoverageTask builds the engine-owned per-class coverage task. It is the
// coverage floor for both the auto plan and model-authored plans: a class task
// carries Origin "auto", so update_plan cannot hand-complete it — only the
// endpoint x class coverage matrix can (via reconcilePlan or the update_plan
// evidence guard).
func newCoverageTask(class string, endpoints []string) *Task {
	t := &Task{
		ID:        "test-" + class,
		Title:     fmt.Sprintf("Test for %s across discovered endpoints", class),
		Phase:     classPhase(class),
		VulnClass: class,
		Status:    TaskPending,
		DependsOn: []string{"recon"},
		Origin:    "auto",
	}
	if len(endpoints) > 0 {
		t.Notes = fmt.Sprintf("Discovered endpoints to test for %s: %s", class, truncList(endpoints, 12))
		t.Endpoint = truncList(endpoints, 1)
	}
	return t
}

// taskCoverageComplete grounds plan reconciliation in exact coverage. An
// explicit LLM task targets its endpoint; grouped/auto tasks require coverage
// across every endpoint discovered by recon. Whole-target black-box tasks use
// the aggregate class flag until an endpoint inventory exists.
func taskCoverageComplete(state *ScanState, task *Task) bool {
	if state == nil || task == nil || task.VulnClass == "" {
		return false
	}
	// Whole-target classes (CORS policy, mail posture, CMS posture, ...)
	// complete on scan-level evidence: their methodology is target-scoped,
	// so a per-endpoint matrix would either demand meaningless duplicates
	// or never close at all.
	if task.WholeTarget {
		return state.VulnClassesTested[task.VulnClass]
	}
	if task.Origin != "auto" && strings.TrimSpace(task.Endpoint) != "" {
		return endpointTestedForClass(state, task.Endpoint, task.VulnClass)
	}
	if len(state.DiscoveredEndpoints) == 0 {
		return state.VulnClassesTested[task.VulnClass]
	}
	for _, endpoint := range state.DiscoveredEndpoints {
		// Non-applicable pairs are not obligations: a class completes when
		// every APPLICABLE endpoint is covered, so /robots.txt can never
		// hold an injection lane open and an unrelated signal can never
		// complete a class either.
		if !classAppliesToEndpoint(state, endpoint, task.VulnClass) {
			continue
		}
		if !endpointTestedForClass(state, endpoint, task.VulnClass) {
			return false
		}
	}
	return true
}

// FormatGaps turns a CoverageGap slice into the compact model-facing summary.
func FormatGaps(gaps []CoverageGap) string {
	if len(gaps) == 0 {
		return ""
	}
	// Group by vuln class for a readable nudge.
	byClass := make(map[string][]string)
	for _, g := range gaps {
		ep := g.Endpoint
		if ep == "" {
			ep = "(whole target)"
		}
		byClass[g.VulnClass] = append(byClass[g.VulnClass], ep)
	}
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	var sb strings.Builder
	sb.WriteString("Coverage gaps (discovered surface not yet tested):\n")
	for _, c := range classes {
		eps := byClass[c]
		sort.Strings(eps)
		if len(eps) > 6 {
			eps = append(eps[:6], fmt.Sprintf("… +%d more", len(eps)-6))
		}
		sb.WriteString(fmt.Sprintf("  • %s: %s\n", c, strings.Join(eps, ", ")))
	}
	return sb.String()
}

// AutoPlan builds a coverage-grounded plan from the seeded attack surface and
// the methodology, without needing the LLM to call build_plan. It is the
// fallback when the operator supplied an OpenAPI/HAR/Postman context (so the
// engine already knows the real endpoints) or when recon has surfaced
// endpoints via notes. Tasks are grouped per vuln class across endpoints to
// keep the graph tractable.
//
// endpoints may be empty (pure black-box): the plan then covers the methodology
// phases as whole-target tasks, which the model refines once it discovers
// surface. detectedTechs nudges the tech-specific classes (e.g. java → ssti).
//
// AutoPlan is the FULL-methodology entry (no phase restriction); the
// phase-scoped variant is AutoPlanFromState, which consults
// state.AllowedPhases and derives bounded technical prerequisites.
func AutoPlan(endpoints []string, detectedTechs map[string]bool) *Plan {
	return buildEnginePlan(nil, endpoints, detectedTechs, phaseScopeFor(nil))
}

// buildEnginePlan is the single engine plan constructor. scope carries the
// operator's phase selection (empty = full methodology). state may be nil
// (bare AutoPlan): the applicability layer and target-level obligations then
// contribute nothing, exactly like the historical AutoPlan behavior.
//
// Phase 20 (exploit verification) and Phase 22 (final report) are deliberately
// NOT plan tasks: verification is performed inline by the deterministic
// verifiers and the hypothesis ledger, and reporting is the terminal
// lifecycle itself. They are DERIVED phase states (phase_disposition.go), so
// the plan no longer carries permanently-pending fake tasks that the finish
// gate ignores.
func buildEnginePlan(state *ScanState, endpoints []string, detectedTechs map[string]bool, scope phaseScope) *Plan {
	p := NewPlan()

	// Phase 1: recon is a prerequisite for everything. Even with a seeded
	// surface, live fingerprinting confirms the surface is reachable and
	// extracts the tech stack that steers later tasks. On a restricted
	// selection that EXCLUDES Phase 1, the task stays — as a bounded
	// technical prerequisite, never as Phase 1 methodology.
	recon := &Task{
		ID:        "recon",
		Title:     "Reconnaissance + technology fingerprint + endpoint inventory",
		Phase:     1,
		VulnClass: "",
		Endpoint:  "",
		Status:    TaskPending,
		Origin:    "auto",
	}
	if scope.restricted && !scope.allows(1) {
		recon.Prerequisite = true
		recon.Title = "Bounded prerequisite discovery (technical prerequisite for the selected phases)"
		recon.Notes = prerequisiteProfileNotes(scope.allowed)
	} else if scope.restricted {
		recon.Notes = "Phase 1 is selected: run the comprehensive reconnaissance contract for the selected scope."
	}
	p.add(recon)

	// Phase 3: directory/content discovery — present for the full
	// methodology, for a selected Phase 3, and as a bounded prerequisite when
	// the selected testing phases need routes the inventory does not have
	// yet. NOT present for pure domain-level selections ({1,22},
	// {13,15,16}-only scans owe their own discovery, not a web wordlist).
	dirbustWanted := scope.allows(3)
	if !dirbustWanted && scope.restricted {
		dirbustWanted = selectionNeedsRouteDiscovery(scope.allowed)
	}
	if dirbustWanted {
		dirbustTitle := "Directory & file discovery (ffuf/gobuster) + hidden paths"
		dirbustNotes := ""
		if len(endpoints) > 0 {
			dirbustTitle = "Bounded content discovery — gap-driven wordlist pass for hidden non-API paths"
			dirbustNotes = "A seeded API surface is known; do NOT broad-crawl it. Run ONE bounded wordlist pass (ffuf -w common wordlist, -maxtime, -noninteractive) against the host root for hidden NON-API paths (debug consoles, admin panels, backups, source/config files), save and inspect the output, and fold any new live routes into the endpoint inventory."
		}
		dirbust := &Task{
			ID:        "dirbust",
			Title:     dirbustTitle,
			Phase:     3,
			VulnClass: "dirbusting",
			Status:    TaskPending,
			DependsOn: []string{"recon"},
			Notes:     dirbustNotes,
			Origin:    "auto",
		}
		if scope.restricted && !scope.allows(3) {
			dirbust.Prerequisite = true
			dirbust.Title = "Bounded route/content discovery (technical prerequisite for the selected phases)"
			dirbust.Notes = "Phase 3 is not selected, but the selected phases need route discovery: crawl links/forms and run ONE bounded keyword pass (ffuf/gobuster, -maxtime, common wordlist) for the routes those phases target. This is a technical prerequisite, not Phase 3 methodology — skip full content enumeration."
		}
		p.add(dirbust)
	}

	// Start with the full baseline coverage contract, then add specialized
	// technology lanes such as Node.js prototype pollution or PHP LFI. Every
	// class lane is filtered by the phase selection.
	classes := defaultVulnClasses(detectedTechs)
	for _, class := range classes {
		if !scope.classAllowed(class) {
			continue
		}
		t := newCoverageTask(class, endpoints)
		// Step-by-step execution: testing (phases 5+) waits for recon AND
		// content discovery (phase 3), so the attack surface is mapped before
		// any class lane opens. NextTasks presents dirbust as the only ready
		// task until it completes.
		t.DependsOn = []string{"recon", "dirbust"}
		p.add(t)
	}

	// Phase 5: full authentication & session testing - always a complete lane,
	// regardless of whether operator-supplied credentials exist.
	if scope.allows(5) {
		authTitle := "Authentication & session testing (login bypass, JWT, session fixation)"
		authNotes := "Test all authentication controls thoroughly - login bypass, JWT/session manipulation, weak credentials, registration flows. Include: token identity (two different logins must not mint identical/interchangeable tokens), token expiry enforcement (expired credentials must be rejected), and a bounded failed-login burst to check authentication rate limiting. Never skip or downgrade this task."
		p.add(&Task{
			ID:        "auth-session",
			Title:     authTitle,
			Phase:     5,
			VulnClass: "auth",
			Status:    TaskPending,
			DependsOn: []string{"recon", "dirbust"},
			Notes:     authNotes,
			Origin:    "auto",
		})
	}

	// Phase 8: IDOR / broken access control - always tested (when selected).
	if scope.allows(8) {
		p.add(&Task{
			ID:        "idor",
			Title:     "IDOR / broken access control (horizontal + vertical)",
			Phase:     8,
			VulnClass: "idor",
			Status:    TaskPending,
			DependsOn: []string{"recon", "auth-session"},
			Notes:     "",
			Origin:    "auto",
		})
	}

	// Applicability extras: one task per extra class that has at least one
	// applicable endpoint, with the concrete endpoint list in the task notes.
	// Bounded and deterministic; classes with no applicable endpoint are NOT
	// scheduled (that is the point).
	if state != nil {
		for _, class := range applicabilityExtraClasses {
			if !scope.classAllowed(class) {
				continue
			}
			eps := ApplicableEndpointsForClass(state, class)
			if len(eps) == 0 {
				continue
			}
			t := newCoverageTask(class, eps)
			t.DependsOn = []string{"recon", "dirbust"}
			if p.Get(t.ID) != nil {
				t.ID += "-coverage"
			}
			if skill, ok := VulnClassSkill(class); ok {
				t.Notes += " Load the methodology first: read_skill(name=" + strconv.Quote(skill) + ")."
			}
			p.add(t)
		}
		// Target-level obligations (whole-target classes with observed
		// surface signals): CORS/cookie analysis, subdomain takeover, mail,
		// cloud, CMS, broken-link/content-spoofing, bounded novel
		// discovery. Phases whose surface does not exist never appear —
		// their disposition is not_applicable.
		appendTargetObligations(state, p, scope)
	}

	return p
}

// defaultVulnClasses returns every class required by the coverage contract
// except IDOR, which has its own post-auth task below. Technology detection may
// add specialized lanes, but it must never remove a baseline lane: fingerprints
// can be incomplete or wrong, and that was a direct source of intermittent
// misses.
func defaultVulnClasses(detectedTechs map[string]bool) []string {
	classes := make([]string, 0, len(requiredCoverageClasses())+2)
	// The dedicated Phase-8 idor task always covers this class; keep it out of
	// the test-* loop to avoid a duplicate lane.
	for _, class := range requiredCoverageClasses() {
		if class != "idor" {
			classes = append(classes, class)
		}
	}
	if detectedTechs == nil {
		return classes
	}
	classes = append(classes, "prototype-pollution")
	classes = append(classes, "lfi")
	return classes
}

// isVagueDispositionReason reports whether a skip/disposition note is a
// shortcut rationalization rather than a concrete surface fact. Used by both
// the update_plan transition guard and the finish gate so the model cannot
// clear engine-owned work with prose like "probably not applicable".
func isVagueDispositionReason(note string) bool {
	note = strings.ToLower(strings.TrimSpace(note))
	if note == "" {
		return true
	}
	for _, vague := range vagueDispositionReasons {
		if strings.Contains(note, vague) {
			return true
		}
	}
	return false
}

// classPhase maps a vuln class to its canonical methodology phase by
// resolving the class registry (vuln_classes.go) — the ONLY class→phase
// mapping in the codebase. Unknown classes return 0: they must never
// silently fall back to Phase 6 the way the historical switch did (every
// unknown class became "injection").
func classPhase(class string) int {
	def, ok := LookupVulnClass(class)
	if !ok {
		return 0
	}
	return def.Phase
}

// classAllowedForSelection reports whether a class's canonical phase is part
// of an operator phase selection. An EMPTY selection allows everything (the
// full methodology). Unknown classes are conservatively excluded under a
// restriction: an unclassifiable lane cannot be placed in the selection.
func classAllowedForSelection(selection []int, class string) bool {
	if len(selection) == 0 {
		return true
	}
	def, ok := LookupVulnClass(class)
	if !ok {
		return false
	}
	return methodology.Allows(selection, def.Phase)
}

// classAllowedForState is classAllowedForSelection over the scan's state.
func classAllowedForState(state *ScanState, class string) bool {
	if state == nil {
		return true
	}
	return classAllowedForSelection(state.AllowedPhases, class)
}

// phaseAllowedForState reports whether a phase is inside the scan's
// selection (empty selection = full methodology).
func phaseAllowedForState(state *ScanState, phase int) bool {
	if state == nil {
		return true
	}
	return methodology.Allows(state.AllowedPhases, phase)
}

// truncList joins a slice, truncating to n items with a "+N more" suffix.
func truncList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" … +%d more", len(items)-n)
}

// planBriefSkillsState is the optional state FormatPlan consults to avoid
// recommending an already-loaded skill. agent.go sets it once; nil disables
// the loaded-skill check (recommendations then always show).
var planBriefSkillsState *ScanState

// FormatPlanState is FormatPlan with the ScanState for skill-aware hints.
// While reconnaissance is still owed, it appends the applicability-aware
// dimension checklist so the brief shows exactly WHAT remains ("Recon 73%:
// crawl ✓, JS analysis ✗") instead of an opaque pending task.
func FormatPlanState(state *ScanState, p *Plan, gaps []CoverageGap) string {
	planBriefSkillsState = state
	defer func() { planBriefSkillsState = nil }()
	brief := FormatPlan(p, gaps)
	if state != nil && p != nil {
		if rt := p.Get("recon"); rt != nil &&
			(rt.Status == TaskPending || rt.Status == TaskActive) {
			if lines := ReconDimensionChecklist(state); len(lines) > 0 {
				brief += "\n" + strings.Join(lines, "\n") + "\n"
			}
		}
	}
	return brief
}

// FormatPlan renders the plan as a compact, model-facing brief: progress,
// the next ready tasks, and any coverage gaps. Used as the per-iteration
// "what to work on now" injection.
func FormatPlan(p *Plan, gaps []CoverageGap) string {
	if p == nil || p.IsEmpty() {
		return ""
	}
	pending, active, completed, skipped := p.Counts()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Active Plan — %d%% executed (%d done, %d active, %d pending, %d skipped — skips are not executed coverage)\n",
		p.ProgressPct(), completed, active, pending, skipped))

	next := p.NextTasks(3)
	if len(next) > 0 {
		sb.WriteString("Next tasks ready to run:\n")
		for _, t := range next {
			sb.WriteString(fmt.Sprintf("  ▶ [Phase %d] %s — %s\n", t.Phase, t.ID, t.Title))
			if ep := strings.TrimSpace(t.Endpoint); ep != "" {
				sb.WriteString(fmt.Sprintf("      target: %s\n", ep))
			}
			if t.Notes != "" {
				sb.WriteString(fmt.Sprintf("      %s\n", t.Notes))
			}
			// Task activation loads its methodology (Part 18): when the
			// next ready task's class resolves to a skill that has not been
			// loaded yet, the brief names it — the model no longer has to
			// remember the catalog, and never loads more than the current
			// lane's 1-3 skills.
			if t.VulnClass != "" {
				if skill, ok := VulnClassSkill(t.VulnClass); ok && skill != "" && !skillCovered(planBriefSkillsState, skill) {
					sb.WriteString(fmt.Sprintf("      methodology: read_skill(name=%q) before testing %s\n", skill, t.VulnClass))
				}
			}
		}
	} else if p.RemainingCount() == 0 {
		sb.WriteString("All planned tasks complete — you may call finish.\n")
	}
	if g := FormatGaps(gaps); g != "" {
		sb.WriteString("\n")
		sb.WriteString(g)
	}
	return sb.String()
}
