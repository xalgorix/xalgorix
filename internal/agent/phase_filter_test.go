package agent

import (
	"strings"
	"testing"
)

// richTestState builds a state carrying a realistic structured black-box
// surface used across the phase-orchestration tests.
func richTestState() *ScanState {
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.com"}
	state.DiscoveredEndpoints = []string{
		"https://app.example.com/checkout",
		"https://app.example.com/upload",
		"https://app.example.com/graphql",
		"wss://app.example.com/ws",
		"https://app.example.com/search",
		"https://bucket.s3.amazonaws.com/assets/logo.svg",
	}
	state.ObservedEndpointMethods = map[string]map[string]bool{
		"app.example.com/checkout": {"POST": true},
		"app.example.com/upload":   {"POST": true},
		"app.example.com/graphql":  {"POST": true},
		"app.example.com/search":   {"GET": true},
	}
	state.EndpointContentTypes = map[string]string{
		"app.example.com/upload":   "multipart/form-data",
		"app.example.com/graphql":  "application/json",
		"app.example.com/checkout": "application/json",
	}
	state.ObservedEndpointParameters = map[string][]SurfaceParameter{
		"app.example.com/search": {{Name: "url", Location: "query"}},
	}
	state.DetectedTechs = map[string]bool{"wordpress": true}
	state.CookieAuthObserved = true
	return state
}

// taskClasses returns the scheduled tasks keyed by vulnerability class.
func taskClasses(p *Plan) map[string]*Task {
	out := map[string]*Task{}
	if p == nil {
		return out
	}
	for _, t := range p.Tasks {
		if t.VulnClass != "" {
			out[t.VulnClass] = t
		}
	}
	return out
}

func testPlanTaskIDs(p *Plan) []string {
	var ids []string
	if p == nil {
		return ids
	}
	for _, t := range p.Tasks {
		ids = append(ids, t.ID)
	}
	return ids
}

// TestPhaseFilter_EmptySelectionSchedulesAllApplicablePhases: an EMPTY
// AllowedPhases means the full methodology — every applicable lane is
// scheduled.
func TestPhaseFilter_EmptySelectionSchedulesAllApplicablePhases(t *testing.T) {
	state := richTestState()
	p := AutoPlanFromState(state)
	classes := taskClasses(p)
	for _, class := range []string{
		"sqli", "xss", "csrf", "parameter_mining", // baseline
		"auth", "idor", // dedicated lanes
		"business-logic", "race-conditions", "file-upload", "graphql",
		"websocket", "open-redirect", "cors", "cookie-security",
		"cms-security", "cloud-config", "cloud-storage", "novel-testing",
	} {
		if _, ok := classes[class]; !ok {
			t.Errorf("full-methodology scan missing task for class %q (tasks: %v)", class, testPlanTaskIDs(p))
		}
	}
	if p.Get("recon") == nil || p.Get("recon").Prerequisite {
		t.Error("full scan must carry the (non-prerequisite) recon task")
	}
}

// TestPhaseFilter_FileUploadOnlySelection: AllowedPhases=[10] schedules the
// file-upload methodology plus ONLY its bounded technical prerequisites —
// no SQLi/XSS/SSRF/business-logic lanes, no full Phase 1/3 methodology.
func TestPhaseFilter_FileUploadOnlySelection(t *testing.T) {
	state := richTestState()
	state.AllowedPhases = []int{10}
	p := AutoPlanFromState(state)
	classes := taskClasses(p)

	if t10, ok := classes["file-upload"]; !ok || t10.Phase != 10 {
		t.Fatalf("phase-10 selection must schedule the file-upload task (phase 10), got %v", testPlanTaskIDs(p))
	}
	for _, excluded := range []string{
		"sqli", "xss", "ssti", "cmdi", "path_traversal", "crlf", "xxe", "ssrf", // phase 6/7
		"csrf", "auth", "auth-bypass", // phase 5
		"idor", "privilege-escalation", // phase 8
		"business-logic", "race-conditions", // phase 12
		"graphql", "websocket", "open-redirect", // phases 9/17/14
		"cors", "cookie-security", // phase 4
		"cms-security", "cloud-config", "cloud-storage", "novel-testing", // 16/18/21
	} {
		if _, ok := classes[excluded]; ok {
			t.Errorf("phase-10-only scan scheduled EXCLUDED class %q", excluded)
		}
	}
	// Bounded technical prerequisites exist and are marked as such: the
	// restricted scan can still FIND upload routes without Phase 1/3 being
	// selected methodology.
	recon := p.Get("recon")
	if recon == nil {
		t.Fatal("phase-10-only scan must still carry a (prerequisite) recon task to locate upload functionality")
	}
	if !recon.Prerequisite {
		t.Error("recon on a restricted scan that excluded Phase 1 must be marked Prerequisite (not Phase 1 methodology)")
	}
	dirbust := p.Get("dirbust")
	if dirbust == nil {
		t.Fatal("phase-10-only scan must carry a bounded route-discovery prerequisite to locate upload routes")
	}
	if !dirbust.Prerequisite {
		t.Error("dirbust on a phase-10-only scan must be marked Prerequisite (Phase 3 was not selected)")
	}
	// No auth-session / idor lanes.
	if p.Get("auth-session") != nil {
		t.Error("phase-10-only scan must not schedule the phase-5 auth lane")
	}
	if p.Get("idor") != nil {
		t.Error("phase-10-only scan must not schedule the phase-8 idor lane")
	}
}

// TestPhaseFilter_APIAndBusinessLogicSelection: AllowedPhases=[9,12]
// schedules GraphQL/API + business/race lanes only.
func TestPhaseFilter_APIAndBusinessLogicSelection(t *testing.T) {
	state := richTestState()
	state.AllowedPhases = []int{9, 12}
	p := AutoPlanFromState(state)
	classes := taskClasses(p)
	for _, class := range []string{"graphql", "business-logic", "race-conditions"} {
		task, ok := classes[class]
		if !ok {
			t.Errorf("phases [9,12] must schedule %q, got %v", class, testPlanTaskIDs(p))
			continue
		}
		wantPhase := 9
		if class != "graphql" {
			wantPhase = 12
		}
		if task.Phase != wantPhase {
			t.Errorf("task %q phase = %d, want %d", class, task.Phase, wantPhase)
		}
	}
	for _, excluded := range []string{"file-upload", "sqli", "websocket", "auth"} {
		if _, ok := classes[excluded]; ok {
			t.Errorf("phases [9,12] must not schedule %q (phase not selected)", excluded)
		}
	}
	if p.Get("auth-session") != nil {
		t.Error("phases [9,12] must not schedule the phase-5 auth lane")
	}
}

// TestPhaseFilter_ReconOnlySelectionPreserved: AllowedPhases=[1,22] builds
// no testing lanes at all — the recon-only contract.
func TestPhaseFilter_ReconOnlySelectionPreserved(t *testing.T) {
	state := richTestState()
	state.AllowedPhases = []int{1, 22}
	if !isReconReportOnlyPhaseSelection(state.AllowedPhases) {
		t.Fatal("[1,22] must classify as the recon/report-only selection")
	}
	p := AutoPlanFromState(state)
	for class := range taskClasses(p) {
		if class != "dirbusting" {
			t.Errorf("recon-only plan must carry no testing class tasks, got %q (tasks: %v)", class, testPlanTaskIDs(p))
		}
	}
	if p.Get("auth-session") != nil || p.Get("idor") != nil {
		t.Error("recon-only plan must not carry auth/idor lanes")
	}
	// Content discovery stays: it is part of the selected Phase 1
	// comprehensive-recon contract, not excluded-phase methodology.
	if p.Get("dirbust") == nil {
		t.Error("recon-only plan keeps the (Phase-1-contract) content-discovery task")
	}
	if recon := p.Get("recon"); recon == nil || recon.Prerequisite {
		t.Error("recon-only plan keeps the full (selected) Phase 1 recon task")
	}
}

// TestPhaseFilter_CloudOnlySelection: AllowedPhases=[16] schedules ONLY the
// cloud methodology that the observed evidence supports — generic classes
// are excluded, and no cloud class is scheduled without evidence.
func TestPhaseFilter_CloudOnlySelection(t *testing.T) {
	state := richTestState()
	state.AllowedPhases = []int{16}
	p := AutoPlanFromState(state)
	classes := taskClasses(p)
	for _, class := range []string{"cloud-config", "cloud-storage"} {
		task, ok := classes[class]
		if !ok {
			t.Errorf("phase-16 selection with observed cloud evidence must schedule %q, got %v", class, testPlanTaskIDs(p))
			continue
		}
		if task.Phase != 16 || !task.WholeTarget {
			t.Errorf("cloud task %q: phase=%d wholeTarget=%v, want phase 16 wholeTarget true", class, task.Phase, task.WholeTarget)
		}
	}
	for _, excluded := range []string{"sqli", "xss", "auth", "idor", "business-logic", "websocket", "graphql"} {
		if _, ok := classes[excluded]; ok {
			t.Errorf("phase-16-only scan scheduled EXCLUDED class %q", excluded)
		}
	}

	// No cloud evidence at all: a clean single-host target without cloud
	// signals schedules nothing for phase 16 (N/A disposition later).
	plain := NewScanState()
	plain.ScanTargets = []string{"https://app.example.com"}
	plain.AllowedPhases = []int{16}
	plain.DiscoveredEndpoints = []string{"https://app.example.com/"}
	classesPlain := taskClasses(AutoPlanFromState(plain))
	if _, ok := classesPlain["cloud-config"]; ok {
		t.Error("cloud-config must NOT be scheduled without cloud evidence (applicability first)")
	}
}

// TestPhaseFilter_FirstClassToolsRespectExcludedPhases: the deterministic
// verifier backstop refuses classes whose phase is excluded.
func TestPhaseFilter_FirstClassToolsRespectExcludedPhases(t *testing.T) {
	a := &Agent{allowedPhases: []int{10}}
	// Phase 6/7/8/12 excluded → their first-class tools are blocked.
	if blocked, _ := a.shouldBlockForPhaseRestriction("verify_sqli", map[string]string{"url": "https://app.example.com/x"}); !blocked {
		t.Error("verify_sqli must be blocked when Phase 6 is not selected")
	}
	if blocked, _ := a.shouldBlockForPhaseRestriction("verify_xxe", nil); !blocked {
		t.Error("verify_xxe must be blocked when Phase 7 is not selected")
	}
	if blocked, _ := a.shouldBlockForPhaseRestriction("authz_matrix", nil); !blocked {
		t.Error("authz_matrix must be blocked when Phase 8 is not selected")
	}
	if blocked, _ := a.shouldBlockForPhaseRestriction("verify_timing", map[string]string{"vuln_class": "business-logic"}); !blocked {
		t.Error("verify_timing(business-logic) must be blocked when Phase 12 is not selected")
	}
	if blocked, _ := a.shouldBlockForPhaseRestriction("verify_oob", map[string]string{"vuln_class": "business-logic"}); !blocked {
		t.Error("verify_oob(business-logic) must be blocked when Phase 12 is not selected")
	}

	// Selected-phase tools run.
	a2 := &Agent{allowedPhases: []int{6, 7}}
	if blocked, reason := a2.shouldBlockForPhaseRestriction("verify_sqli", nil); blocked {
		t.Errorf("verify_sqli with Phase 6 selected must run, got %q", reason)
	}
	if blocked, reason := a2.shouldBlockForPhaseRestriction("verify_oob", map[string]string{"vuln_class": "xxe"}); blocked {
		t.Errorf("verify_oob(xxe) with Phase 7 selected must run, got %q", reason)
	}
	if blocked, reason := a2.shouldBlockForPhaseRestriction("verify_oob", map[string]string{"vuln_class": "business-logic"}); !blocked {
		t.Errorf("verify_oob(business-logic) must be blocked while Phase 12 is excluded, got %q", reason)
	}
	// Unclassified tools are never wall-blocked (the plan is the authority).
	if blocked, _ := a2.shouldBlockForPhaseRestriction("terminal_execute", map[string]string{"command": "curl https://app.example.com"}); blocked {
		t.Error("terminal commands must not be phase-wall-blocked (brittle regex walls are explicitly not the design)")
	}
	// Unrestricted scans never hit the backstop.
	a3 := &Agent{}
	if blocked, _ := a3.shouldBlockForPhaseRestriction("verify_sqli", nil); blocked {
		t.Error("full-methodology scans must never hit the phase backstop")
	}
}

// TestPhaseFilter_LedgerSeedingRespectsPhases: hypothesis seeding for
// observed parameters must not create work in excluded lanes —
// AllowedPhases=[10] seeds NO SQLi/XSS/SSRF/IDOR/business-logic hypotheses
// merely because those classes are applicable.
func TestPhaseFilter_LedgerSeedingRespectsPhases(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.AllowedPhases = []int{10}
	state.DiscoveredEndpoints = []string{"https://app.example.com/search"}
	state.ObservedEndpointParameters = map[string][]SurfaceParameter{
		"app.example.com/search": {
			{Name: "url", Location: "query"},
			{Name: "file", Location: "query"},
			{Name: "role", Location: "query"},
			{Name: "id", Location: "query"},
		},
	}
	if seeded := seedParamHypotheses(state, ctx.Ledger); seeded != 0 {
		t.Fatalf("phase-10-only scan seeded %d parameter hypotheses from url/file/role/id params — no upload parameter exists and every candidate lane is excluded", seeded)
	}
	for _, h := range ctx.Ledger.All() {
		switch h.VulnClass {
		case "ssrf", "open-redirect", "path_traversal", "mass-assignment", "privilege-escalation", "idor":
			t.Errorf("phase-10-only scan seeded EXCLUDED-lane hypothesis %q (%s)", h.ID, h.VulnClass)
		}
	}

	// With the phases selected, the same surface seeds the url-param lanes.
	ctx2, state2 := newTestCtxState(t)
	state2.AllowedPhases = []int{7, 8, 14}
	state2.DiscoveredEndpoints = []string{"https://app.example.com/search"}
	state2.ObservedEndpointParameters = map[string][]SurfaceParameter{
		"app.example.com/search": {{Name: "url", Location: "query"}},
	}
	if seeded := seedParamHypotheses(state2, ctx2.Ledger); seeded == 0 {
		t.Fatal("phases [7,8,14] must seed ssrf/open-redirect hypotheses for the url parameter")
	}
	seen := map[string]bool{}
	for _, h := range ctx2.Ledger.All() {
		seen[h.VulnClass] = true
	}
	for _, want := range []string{"ssrf", "open-redirect"} {
		if !seen[want] {
			t.Errorf("expected %q hypothesis from the url parameter, ledger has %v", want, seen)
		}
	}
}

// TestPhaseFilter_SkillSuggestionsRespectPhases: technology-driven skill
// recommendations never cross into excluded lanes (GraphQL skill without
// Phase 9, injection without 6).
func TestPhaseFilter_SkillSuggestionsRespectPhases(t *testing.T) {
	state := richTestState()
	state.DetectedTechs = map[string]bool{"graphql": true, "firebase": true, "php": true}
	state.AllowedPhases = []int{16}
	for _, rec := range recommendedSkillsForState(state) {
		if strings.Contains(rec.Reason, "detected graphql stack") {
			t.Errorf("phase-16-only scan recommended GraphQL methodology (%q) — Phase 9 excluded", rec.Skill)
		}
		if strings.Contains(rec.Reason, "detected php stack") {
			t.Errorf("phase-16-only scan recommended injection methodology (%q) — Phase 6 excluded", rec.Skill)
		}
	}

	// With phase 9 selected, the graphql skill is recommendable again.
	state9 := richTestState()
	state9.DetectedTechs = map[string]bool{"graphql": true}
	state9.AllowedPhases = []int{9}
	found := false
	for _, rec := range recommendedSkillsForState(state9) {
		if strings.Contains(rec.Reason, "detected graphql stack") {
			found = true
		}
	}
	if !found {
		t.Error("phase-9 selection with detected graphql must recommend the GraphQL methodology")
	}
}
