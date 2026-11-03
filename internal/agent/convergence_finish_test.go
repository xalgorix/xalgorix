package agent

import "testing"

func TestTaskBlocksPrincipledFinish(t *testing.T) {
	cases := []struct {
		name  string
		state *ScanState
		task  *Task
		want  bool
	}{
		{"recon blocks when recon not done", &ScanState{ReconDone: false}, &Task{ID: "recon"}, true},
		{"recon does NOT block once ReconDone (stale task status)", &ScanState{ReconDone: true}, &Task{ID: "recon"}, false},
		{"dirbust blocks when not done", &ScanState{}, &Task{ID: "dirbust"}, true},
		{"dirbust does NOT block once DirBustingDone", &ScanState{DirBustingDone: true}, &Task{ID: "dirbust"}, false},
		{"auth-session does NOT block (closes as residual)", &ScanState{}, &Task{ID: "auth-session", VulnClass: "auth"}, false},
		{"specific-endpoint llm hypothesis is soft (closes as residual)", &ScanState{}, &Task{ID: "x", VulnClass: "sqli", Origin: "llm", Endpoint: "/login"}, false},
		{"generic auto per-endpoint class task is soft", &ScanState{}, &Task{ID: "x", VulnClass: "sqli", Origin: "auto"}, false},
		{"whole-target class task is soft", &ScanState{}, &Task{ID: "x", VulnClass: "redos", WholeTarget: true, Origin: "auto"}, false},
		{"class-less exploratory is soft", &ScanState{}, &Task{ID: "x", VulnClass: ""}, false},
	}
	for _, tc := range cases {
		if got := taskBlocksPrincipledFinish(tc.state, tc.task); got != tc.want {
			t.Errorf("%s: taskBlocksPrincipledFinish = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// breadthState builds a state whose VulnClassesTested covers n of the required
// injection classes, with a plan of one pending generic sqli per-endpoint task.
func breadthState(n int, conv bool, iter int) *ScanState {
	req := requiredCoverageClasses()
	vct := map[string]bool{}
	for i := 0; i < n && i < len(req); i++ {
		vct[req[i]] = true
	}
	return &ScanState{
		ConvergeFinish:    conv,
		Iteration:         iter,
		MinIterations:     50,
		VulnClassesTested: vct,
		Plan: &Plan{Tasks: []*Task{
			{ID: "t-sqli", VulnClass: "sqli", Origin: "auto", Status: TaskPending},
		}},
	}
}

func TestSaturatedForFinish(t *testing.T) {
	// Flag off: never saturates.
	if saturatedForFinish(breadthState(11, false, 500)) {
		t.Error("flag off must not saturate")
	}
	// Before MinIterations: not yet.
	if saturatedForFinish(breadthState(11, true, 10)) {
		t.Error("below MinIterations must not saturate")
	}
	// Low class breadth (3/11 ≈ 27% < 60%): not saturated.
	if saturatedForFinish(breadthState(3, true, 500)) {
		t.Error("low class breadth must not saturate")
	}
	// Breadth ok (8/11 ≈ 73%), only soft tasks, past min-iter: saturated.
	if !saturatedForFinish(breadthState(8, true, 500)) {
		t.Error("broad coverage with only soft tasks should saturate")
	}
	// A pending recon task blocks even with full breadth.
	st := breadthState(11, true, 500)
	st.Plan.Tasks = append(st.Plan.Tasks, &Task{ID: "recon", Status: TaskPending})
	if saturatedForFinish(st) {
		t.Error("pending recon must block saturation")
	}
	// A pending specific-endpoint hypothesis is soft: it must NOT block saturation
	// (it closes as logged residual at the finish — the model over-plans these and
	// never drains them, so blocking on them prevents convergence).
	st2 := breadthState(11, true, 500)
	st2.Plan.Tasks = append(st2.Plan.Tasks, &Task{ID: "h", VulnClass: "idor", Origin: "llm", Endpoint: "/x", Status: TaskPending})
	if !saturatedForFinish(st2) {
		t.Error("pending specific-endpoint hypothesis must NOT block saturation (soft, closes as residual)")
	}
	// No soft task at all (only completed): nothing to close → not saturated.
	st3 := breadthState(11, true, 500)
	st3.Plan.Tasks = []*Task{{ID: "t", VulnClass: "sqli", Origin: "auto", Status: TaskCompleted}}
	if saturatedForFinish(st3) {
		t.Error("no open soft task must not saturate (plan-exhausted path handles that)")
	}
}

func TestCloseSoftTasksForFinish(t *testing.T) {
	st := &ScanState{
		Plan: &Plan{Tasks: []*Task{
			{ID: "recon", Status: TaskPending},                                                          // foundational blocker: untouched
			{ID: "h", VulnClass: "sqli", Origin: "llm", Endpoint: "/login", Status: TaskPending},        // specific-endpoint hypothesis → untested residual
			{ID: "t-sqli", VulnClass: "sqli", Origin: "auto", Status: TaskPending},                      // soft class → untested_at_finish
			{ID: "t-redos", VulnClass: "redos", WholeTarget: true, Origin: "auto", Status: TaskPending}, // soft class
			{ID: "auth-session", VulnClass: "auth", Status: TaskActive},                                 // soft auth → blocked_missing_auth
			{ID: "explore", VulnClass: "", Status: TaskPending},                                         // class-less → untested_at_finish
			{ID: "done", VulnClass: "xss", Origin: "auto", Status: TaskCompleted},                       // already terminal: untouched
		}},
	}
	closed := closeSoftTasksForFinish(st)
	if closed != 5 {
		t.Fatalf("closed = %d, want 5", closed)
	}
	by := map[string]*Task{}
	for _, tk := range st.Plan.Tasks {
		by[tk.ID] = tk
	}
	if by["recon"].Status != TaskPending {
		t.Error("recon (foundational blocker) must be left pending")
	}
	for _, id := range []string{"h", "t-sqli", "t-redos", "explore"} {
		if by[id].Status != TaskSkipped || by[id].Disposition != DispositionUntestedAtFinish {
			t.Errorf("%s = %v/%q, want skipped/untested_at_finish (closed without execution)", id, by[id].Status, by[id].Disposition)
		}
	}
	if by["auth-session"].Disposition != DispositionBlockedMissingAuth {
		t.Errorf("auth-session disposition = %q, want blocked_missing_auth", by["auth-session"].Disposition)
	}
	if n := untestedAtFinishCount(st); n != 4 {
		t.Errorf("untestedAtFinishCount = %d, want 4 (auth-session stays typed blocked work)", n)
	}
	// auth-session WITH an auth context closes as exhausted, not blocked.
	st2 := &ScanState{AuthContextAvailable: true, Plan: &Plan{Tasks: []*Task{
		{ID: "auth-session", VulnClass: "auth", Status: TaskPending},
	}}}
	closeSoftTasksForFinish(st2)
	if st2.Plan.Tasks[0].Disposition != DispositionExhausted {
		t.Errorf("auth-session (with auth ctx) disposition = %q, want exhausted", st2.Plan.Tasks[0].Disposition)
	}
}

// Lever A: a content-discovery artifact owes information-exposure only — and
// ONLY when the flag is on (legacy applicability is byte-identical when off).
func TestContentDiscoveryArtifactApplicability(t *testing.T) {
	const ep = "/.htaccess"

	off := buildSurfaceEndpoint(&ScanState{ConvergeFinish: false}, ep)
	offClasses := off.ApplicableClasses()
	sawInjection := false
	for _, c := range offClasses {
		if CanonicalVulnClassID(c) != "" {
			sawInjection = true
		}
	}
	if !sawInjection {
		t.Errorf("flag OFF: %s should still get the legacy injection floor, got %v", ep, offClasses)
	}

	on := buildSurfaceEndpoint(&ScanState{ConvergeFinish: true}, ep)
	onClasses := on.ApplicableClasses()
	if len(onClasses) != 1 || onClasses[0] != "information-exposure" {
		t.Errorf("flag ON: %s should owe only information-exposure, got %v", ep, onClasses)
	}
}

func TestIsContentDiscoveryArtifact(t *testing.T) {
	artifacts := []string{
		"/.git/config", "/.svn/entries", "/.htaccess", "/.htpasswd", "/Thumbs.db",
		"/.DS_Store", "/access.log", "/error_log", "/backup.sql", "/site.zip",
		"/db.bak", "/__xalgorix_nonexistent_control_71ab9", "/web.config",
	}
	for _, a := range artifacts {
		if !isContentDiscoveryArtifact(a) {
			t.Errorf("%q should be a content-discovery artifact", a)
		}
	}
	realRoutes := []string{
		"/account/login", "/cart/add", "/api/graphql", "/actuator/env",
		"/products", "/search", "/digit", "/login",
	}
	for _, r := range realRoutes {
		if isContentDiscoveryArtifact(r) {
			t.Errorf("%q is a real route, must NOT be flagged as an artifact", r)
		}
	}
}
