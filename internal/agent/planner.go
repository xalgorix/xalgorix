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
	"strings"
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

// ProgressPct returns whole-percent completion (completed+skipped over total).
// Returns 0 for an empty plan.
func (p *Plan) ProgressPct() int {
	if p == nil || len(p.Tasks) == 0 {
		return 0
	}
	_, _, completed, skipped := p.Counts()
	return int(float64(completed+skipped) / float64(len(p.Tasks)) * 100)
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
	shared := sharedCoverageForState(state)
	for _, alias := range aliases {
		if classes, ok := state.EndpointClassCoverage[alias]; ok {
			hasEndpointMatrixEvidence = true
			if classes[class] {
				return true
			}
		}
		if shared != nil {
			if shared.Has(alias, class) {
				return true
			}
			if shared.HasEndpoint(alias) {
				hasEndpointMatrixEvidence = true
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

// taskCoverageComplete grounds plan reconciliation in exact coverage. An
// explicit LLM task targets its endpoint; grouped/auto tasks require coverage
// across every endpoint discovered by recon. Whole-target black-box tasks use
// the aggregate class flag until an endpoint inventory exists.
func taskCoverageComplete(state *ScanState, task *Task) bool {
	if state == nil || task == nil || task.VulnClass == "" {
		return false
	}
	if task.Origin != "auto" && strings.TrimSpace(task.Endpoint) != "" {
		return endpointTestedForClass(state, task.Endpoint, task.VulnClass)
	}
	if len(state.DiscoveredEndpoints) == 0 {
		return state.VulnClassesTested[task.VulnClass]
	}
	for _, endpoint := range state.DiscoveredEndpoints {
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
func AutoPlan(endpoints []string, detectedTechs map[string]bool) *Plan {
	p := NewPlan()

	// Phase 1-2: recon is a prerequisite for everything. Even with a seeded
	// surface, live fingerprinting confirms the surface is reachable and
	// extracts the tech stack that steers later tasks.
	recon := &Task{
		ID:        "recon",
		Title:     "Reconnaissance + technology fingerprint + endpoint inventory",
		Phase:     1,
		VulnClass: "",
		Endpoint:  "",
		Status:    TaskPending,
		Origin:    "auto",
	}
	p.add(recon)

	// Phase 3: directory/content discovery (only when no seeded surface — a
	// seeded OpenAPI surface makes broad dirbusting lower-value).
	if len(endpoints) == 0 {
		p.add(&Task{
			ID:        "dirbust",
			Title:     "Directory & file discovery (ffuf/gobuster) + hidden paths",
			Phase:     3,
			VulnClass: "dirbusting",
			Status:    TaskPending,
			DependsOn: []string{"recon"},
			Origin:    "auto",
		})
	}

	// Start with the full baseline coverage contract, then add specialized
	// technology lanes such as Node.js prototype pollution or PHP LFI.
	classes := defaultVulnClasses(detectedTechs)

	// Build per-class tasks. When endpoints are known, each class task lists
	// the endpoint set in its Notes so the model tests them all; when unknown,
	// the task is whole-target and the model refines after discovery.
	for _, class := range classes {
		phase := classPhase(class)
		t := &Task{
			ID:        "test-" + class,
			Title:     fmt.Sprintf("Test for %s across discovered endpoints", class),
			Phase:     phase,
			VulnClass: class,
			Status:    TaskPending,
			DependsOn: []string{"recon"},
			Origin:    "auto",
		}
		if len(endpoints) > 0 {
			t.Notes = fmt.Sprintf("Discovered endpoints to test for %s: %s", class, truncList(endpoints, 12))
			t.Endpoint = truncList(endpoints, 1)
		}
		p.add(t)
	}

	// Phase 5: auth/session testing when auth material exists (the agent knows
	// this from target auth / seeded surface; the plan includes it so it isn't
	// dropped). Depends on recon.
	p.add(&Task{
		ID:        "auth-session",
		Title:     "Authentication & session testing (login bypass, JWT, session fixation)",
		Phase:     5,
		VulnClass: "auth",
		Status:    TaskPending,
		DependsOn: []string{"recon"},
		Origin:    "auto",
	})

	// Phase 8: IDOR / broken access control (the high-value post-auth class).
	p.add(&Task{
		ID:        "idor",
		Title:     "IDOR / broken access control (horizontal + vertical)",
		Phase:     8,
		VulnClass: "idor",
		Status:    TaskPending,
		DependsOn: []string{"recon", "auth-session"},
		Origin:    "auto",
	})

	// Phase 20: exploit verification + Phase 22 report are the tail, depending
	// on the test tasks completing.
	testDeps := make([]string, 0, len(p.Tasks))
	for _, t := range p.Tasks {
		if t.VulnClass != "" && t.VulnClass != "dirbusting" && t.VulnClass != "auth" {
			testDeps = append(testDeps, t.ID)
		}
	}
	p.add(&Task{
		ID:        "verify",
		Title:     "Exploit verification — re-test every candidate finding (Phase 20)",
		Phase:     20,
		VulnClass: "",
		Status:    TaskPending,
		DependsOn: testDeps,
		Origin:    "auto",
	})
	p.add(&Task{
		ID:        "report",
		Title:     "Final report — summarize verified findings + remediation (Phase 22)",
		Phase:     22,
		VulnClass: "",
		Status:    TaskPending,
		DependsOn: []string{"verify"},
		Origin:    "auto",
	})

	return p
}

// defaultVulnClasses returns every class required by the coverage contract
// except IDOR, which has its own post-auth task below. Technology detection may
// add specialized lanes, but it must never remove a baseline lane: fingerprints
// can be incomplete or wrong, and that was a direct source of intermittent
// misses.
func defaultVulnClasses(detectedTechs map[string]bool) []string {
	classes := make([]string, 0, len(requiredCoverageClasses())+2)
	for _, class := range requiredCoverageClasses() {
		if class != "idor" {
			classes = append(classes, class)
		}
	}
	if detectedTechs == nil {
		return classes
	}
	if detectedTechs["nodejs"] {
		classes = append(classes, "prototype-pollution")
	}
	if detectedTechs["php"] {
		classes = append(classes, "lfi")
	}
	return classes
}

// classPhase maps a vuln class to its methodology phase.
func classPhase(class string) int {
	switch class {
	case "sqli", "xss", "ssti", "cmdi", "crlf":
		return 6 // injection testing
	case "ssrf":
		return 7
	case "xxe":
		return 7
	case "idor", "prototype-pollution":
		return 8
	case "csrf":
		return 5
	case "parameter_mining":
		return 4
	case "path_traversal", "lfi":
		return 6
	case "dirbusting":
		return 3
	case "auth":
		return 5
	default:
		return 6
	}
}

// truncList joins a slice, truncating to n items with a "+N more" suffix.
func truncList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" … +%d more", len(items)-n)
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
	sb.WriteString(fmt.Sprintf("## Active Plan — %d%% complete (%d done, %d active, %d pending, %d skipped)\n",
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
