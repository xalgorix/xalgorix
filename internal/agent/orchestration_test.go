package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools/skills"
)

// ── Directive composition (Part 21: hook delivery) ───────────────────────────

// Case 6: delegation nudge + planner brief + skill recommendation in the same
// iteration must ALL reach the model — the old first-non-empty-nudge merge
// delivered only the first registered hook's message while every hook had
// already marked its state delivered.
func TestDirectives_ComposeInsteadOfFirstNudgeWins(t *testing.T) {
	reg := NewHookRegistry()
	state := NewScanState()
	state.Iteration = 20

	delegationDelivered := false
	plannerDelivered := false
	skillDelivered := false

	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityCritical, Category: "delegation", DedupeKey: "delegation-initial",
			Content:     "DELEGATION-CONTENT",
			OnDelivered: func(*ScanState) { delegationDelivered = true },
		}}}
	})
	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityAdvisory, Category: "skill", DedupeKey: "skill-suggestion",
			Content:     "SKILL-CONTENT",
			OnDelivered: func(*ScanState) { skillDelivered = true },
		}}}
	})
	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityPlanner, Category: "planner", DedupeKey: "planner-brief",
			Content:     "PLANNER-CONTENT",
			OnDelivered: func(*ScanState) { plannerDelivered = true },
		}}}
	})

	result := reg.Fire(OnIterationStart, state, nil)
	for _, want := range []string{"DELEGATION-CONTENT", "PLANNER-CONTENT", "SKILL-CONTENT"} {
		if !strings.Contains(result.Nudge, want) {
			t.Fatalf("merged nudge lost %q, got:\n%s", want, result.Nudge)
		}
	}
	if !delegationDelivered || !plannerDelivered || !skillDelivered {
		t.Fatalf("delivered flags: delegation=%v planner=%v skill=%v", delegationDelivered, plannerDelivered, skillDelivered)
	}
	// Critical guidance must precede advisory hints in the composition.
	if strings.Index(result.Nudge, "DELEGATION-CONTENT") > strings.Index(result.Nudge, "SKILL-CONTENT") {
		t.Fatal("critical directive must be composed before advisory ones")
	}
}

// Case 7: a directive dropped by dedupe (or overflow) keeps its OnDelivered
// un-run, so the producing state stays eligible and delivery succeeds later.
func TestDirectives_SuppressedNudgeStaysEligible(t *testing.T) {
	state := NewScanState()
	state.Iteration = 20
	delivered := false
	hook := func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityPlanner, Category: "planner", DedupeKey: "planner-brief",
			Content:     "BRIEF-CONTENT",
			OnDelivered: func(*ScanState) { delivered = true },
		}}}
	}
	dominant := func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityCritical, Category: "delegation", DedupeKey: "planner-brief",
			Content: "CRITICAL-CONTENT",
		}}}
	}

	reg := NewHookRegistry()
	reg.Register(OnIterationStart, dominant)
	reg.Register(OnIterationStart, hook)
	first := reg.Fire(OnIterationStart, state, nil)
	if strings.Contains(first.Nudge, "BRIEF-CONTENT") {
		t.Fatal("dedupe collision should have suppressed the planner brief")
	}
	if delivered {
		t.Fatal("suppressed directive must not be marked delivered")
	}

	// Later iteration, dominant hook quiet: the brief is finally delivered.
	reg2 := NewHookRegistry()
	reg2.Register(OnIterationStart, hook)
	second := reg2.Fire(OnIterationStart, state, nil)
	if !strings.Contains(second.Nudge, "BRIEF-CONTENT") || !delivered {
		t.Fatal("suppressed directive must be deliverable on a later iteration")
	}
}

// Case 8: LastPlanBrief is recorded ONLY when the brief verifiably reached the
// model. The old hookPlanner set it before the merge, so a nudge lost to the
// first-non-empty race suppressed the brief forever.
func TestDirectives_LastPlanBriefRecordsOnlyOnDelivery(t *testing.T) {
	state := NewScanState()
	state.Plan = AutoPlan([]string{"/api/login"}, nil)
	state.ReconDone = true
	state.DiscoveredEndpoints = []string{"/api/login"}
	state.Iteration = 20

	reg := NewHookRegistry()
	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityCritical, Category: "delegation", DedupeKey: "delegation-initial",
			Content: "DOMINANT-DELEGATION",
		}}}
	})
	reg.Register(OnIterationStart, hookPlanner)

	merged := reg.Fire(OnIterationStart, state, nil)
	// Legacy pre-directive semantics would deliver only the delegation nudge;
	// now the brief is composed in too, so LastPlanBrief is set — but if the
	// brief HAD been dropped, LastPlanBrief must stay empty.
	if !strings.Contains(merged.Nudge, "Active Plan") {
		t.Fatal("planner brief should be composed into the merged nudge")
	}
	if state.LastPlanBrief == "" {
		t.Fatal("LastPlanBrief must be recorded when the brief is delivered")
	}

	// The dedupe-drop case: a duplicate planner-brief directive must NOT
	// overwrite delivery bookkeeping (first delivered wins).
	state2 := NewScanState()
	state2.Plan = AutoPlan([]string{"/api/login"}, nil)
	state2.ReconDone = true
	state2.DiscoveredEndpoints = []string{"/api/login"}
	state2.Iteration = 20
	reg3 := NewHookRegistry()
	reg3.Register(OnIterationStart, hookPlanner)
	reg3.Register(OnIterationStart, hookPlanner)
	res := reg3.Fire(OnIterationStart, state2, nil)
	if strings.Count(res.Nudge, "Active Plan") != 1 {
		t.Fatalf("duplicate planner-brief directives must dedupe, got:\n%s", res.Nudge)
	}
}

// Legacy single-nudge hooks keep working and are appended after directives.
func TestDirectives_LegacyNudgeStillComposed(t *testing.T) {
	reg := NewHookRegistry()
	state := NewScanState()
	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Directives: []Directive{{
			Priority: DirectivePriorityPlanner, Category: "planner", DedupeKey: "planner-brief",
			Content: "BRIEF",
		}}}
	})
	reg.Register(OnIterationStart, func(s *ScanState, _ map[string]string) HookResult {
		return HookResult{Nudge: "LEGACY"}
	})
	result := reg.Fire(OnIterationStart, state, nil)
	if !strings.Contains(result.Nudge, "BRIEF") || !strings.Contains(result.Nudge, "LEGACY") {
		t.Fatalf("legacy nudge lost in composition: %q", result.Nudge)
	}
}

func TestComposeDirectives_OverflowDropsLowestPriority(t *testing.T) {
	dirs := []Directive{
		{Priority: DirectivePriorityCritical, Content: "CRITICAL"},
		{Priority: DirectivePriorityAdvisory, Content: strings.Repeat("a", maxDirectiveComposeLen)},
	}
	composed, delivered := composeDirectives(dirs, "")
	if strings.Contains(composed, strings.Repeat("a", 100)) || len(delivered) != 1 {
		t.Fatalf("overflow must drop the low-priority directive, got %d delivered", len(delivered))
	}
	if !strings.Contains(composed, "deferred") {
		t.Fatalf("overflow must leave a visible deferral marker, got: %q", composed)
	}
	if !strings.Contains(composed, "CRITICAL") {
		t.Fatal("highest-priority directive must never be dropped by overflow")
	}
}

// ── Skill tracking (Part 21: skill orchestration) ────────────────────────────

// Case 2: a failed read_skill lookup must not count as a loaded skill.
func TestSkillTracker_FailedLookupDoesNotCount(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	hookSkillLoadTracker(state, map[string]string{
		"tool_name": "read_skill", "name": "nonexistent-skill-xyz",
		"error": "skill not found: nonexistent-skill-xyz — use list_skills",
	})
	if state.SkillsLoaded != 0 || len(state.LoadedSkills) != 0 {
		t.Fatalf("failed lookup counted: SkillsLoaded=%d", state.SkillsLoaded)
	}
	if state.FailedSkillLoads != 1 {
		t.Fatalf("failed lookup must be recorded, got %d", state.FailedSkillLoads)
	}
}

// Case 3: a suppressed duplicate load must not inflate the unique count.
func TestSkillTracker_DuplicateDoesNotInflate(t *testing.T) {
	state := NewScanState()
	hookSkillLoadTracker(state, map[string]string{
		"tool_name": "read_skill", "name": "sqli", "skill_name": "exploiting-sql-injection",
	})
	hookSkillLoadTracker(state, map[string]string{
		"tool_name": "read_skill", "name": "sqli", "skill_name": "exploiting-sql-injection",
		"skill_duplicate": "true",
	})
	if state.SkillsLoaded != 1 {
		t.Fatalf("duplicate load inflated count to %d", state.SkillsLoaded)
	}
	if state.LoadedSkills["exploiting-sql-injection"].Reloads != 1 {
		t.Fatal("suppressed duplicate should be visible in Reloads")
	}
}

// Case 1: loading the SQLi skill must NOT suppress later GraphQL/JWT/etc.
// recommendations — the old SkillsLoaded>0 global off-switch did exactly that.
func TestSkillRecommendations_PerDomainNotGlobal(t *testing.T) {
	state := NewScanState()
	state.Iteration = 15
	state.DetectedTechs["php"] = true
	state.DetectedTechs["nodejs"] = true

	recs := recommendedSkillsForState(state)
	if len(recs) == 0 {
		t.Fatal("expected per-tech recommendations for php+nodejs")
	}
	has := map[string]bool{}
	for _, r := range recs {
		has[r.Skill] = true
	}
	if len(recs) != 2 {
		t.Fatalf("expected exactly 2 distinct recommendations, got %v", recs)
	}

	// Simulate the SQLi skill successfully loaded (php lane satisfied).
	state.LoadedSkills[recsSQLI(t, recs)] = &LoadedSkillInfo{Name: recsSQLI(t, recs), Reason: "model-requested"}
	state.SkillsLoaded = 1
	remaining := recommendedSkillsForState(state)
	if len(remaining) != 1 {
		t.Fatalf("loading one skill must not suppress recommendations for other technologies: %v", remaining)
	}
	if strings.Contains(remaining[0].Skill, "sql") {
		t.Fatalf("already-loaded skill re-recommended: %v", remaining)
	}
}

func recsSQLI(t *testing.T, recs []skillRecommendation) string {
	t.Helper()
	for _, r := range recs {
		if strings.Contains(r.Skill, "sql") {
			return r.Skill
		}
	}
	t.Fatal("expected a SQLi recommendation for php")
	return ""
}

// The suggester hook must keep recommending an unloaded domain even after one
// skill was loaded, and delivered suggestions dedupe per skill.
func TestSkillSuggester_RecommendsUncoveredDomains(t *testing.T) {
	state := NewScanState()
	state.Iteration = 15
	state.DetectedTechs["php"] = true

	// Round 1: php detected, nothing loaded → SQLi methodology recommended.
	result := fireDirectives(t, state, hookAutoSkillSuggester)
	if result.Nudge == "" {
		t.Fatal("expected a skill recommendation with detected techs and no skills loaded")
	}
	if state.SkillsLoaded != 0 {
		t.Fatal("a recommendation is not a load")
	}
	sqli := ""
	for name := range state.SkillSuggestionsSent {
		if strings.Contains(name, "sql") {
			sqli = name
		}
	}
	if sqli == "" {
		t.Fatal("expected a SQLi suggestion for php")
	}

	// The model loads the SQLi skill.
	state.LoadedSkills[sqli] = &LoadedSkillInfo{Name: sqli, Reason: "model-requested"}
	state.SkillsLoaded = 1
	if got := recommendedSkillsForState(state); len(got) != 0 {
		t.Fatalf("satisfied domain must stop recommending, got %v", got)
	}

	// Round 2: GraphQL is discovered LATER in the scan. The old
	// SkillsLoaded>0 off-switch suppressed every later recommendation; the
	// per-domain suggester must still fire for the uncovered domain.
	state.DetectedTechs["graphql"] = true
	result2 := fireDirectives(t, state, hookAutoSkillSuggester)
	if !strings.Contains(result2.Nudge, "graphql") {
		t.Fatalf("a loaded SQLi skill must not suppress the later GraphQL recommendation:\n%s", result2.Nudge)
	}
	if sqli == "" || strings.Contains(result2.Nudge, sqli) {
		t.Fatalf("already-loaded skill re-recommended in:\n%s", result2.Nudge)
	}

	// Delivered recommendations dedupe: no nagging on later iterations.
	if got := recommendedSkillsForState(state); len(got) != 0 {
		t.Fatalf("delivered recommendations must dedupe, got %v", got)
	}
}

// Cases 4+5: the deterministic resolver maps surface signals to methodology.
func TestResolveSkillName_SurfaceSignals(t *testing.T) {
	cases := []struct {
		query   string
		wantSub string
	}{
		{"graphql", "graphql"},
		{"business logic", "business"},
		{"jwt", "jwt"},
		{"race condition", "race"},
		{"file upload", ""},
	}
	for _, tc := range cases {
		name, ok := skills.ResolveSkillName(tc.query)
		if !ok {
			t.Fatalf("ResolveSkillName(%q) failed to resolve", tc.query)
		}
		if tc.wantSub != "" && !strings.Contains(strings.ToLower(name), tc.wantSub) {
			t.Fatalf("ResolveSkillName(%q) = %q, want substring %q", tc.query, name, tc.wantSub)
		}
	}
	// Nonsense must not resolve.
	if _, ok := skills.ResolveSkillName("zzzqqqxyzzy-no-such-concept-12345"); ok {
		t.Fatal("nonsense query must not resolve")
	}
}
