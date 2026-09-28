package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

func TestCoordinatorFinishGateRequiresDelegatedResultCollection(t *testing.T) {
	release := make(chan struct{})
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		<-release
		return "specialist evidence", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)

	spawned, err := registry.Execute("spawn_agent", map[string]string{
		"name": "authorization specialist",
		"task": "test account boundaries with baseline controls",
	})
	if err != nil {
		t.Fatal(err)
	}
	agentID, _ := spawned.Metadata["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("spawn result missing agent ID: %#v", spawned)
	}

	coordinator := &Agent{agentGraph: graph}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); !gate.Block || !strings.Contains(gate.BlockReason, "still running") {
		t.Fatalf("running delegation did not block finish: %+v", gate)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for graph.RunningCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); !gate.Block || !strings.Contains(gate.BlockReason, "not been collected") {
		t.Fatalf("uncollected delegation did not block finish: %+v", gate)
	}

	if _, err := registry.Execute("check_agent", map[string]string{"agent_id": agentID}); err != nil {
		t.Fatal(err)
	}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); gate.Block {
		t.Fatalf("collected delegation still blocked finish: %+v", gate)
	}
}

func TestDelegatedAgentHasNoNestedGraphTools(t *testing.T) {
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(sctx.Close)
	cfg := &config.Config{MaxIterations: 1, SkillsDir: t.TempDir()}
	child := NewAgent(
		cfg,
		"delegated",
		make(chan Event, 8),
		scopeguard.Config{BindAddr: "127.0.0.1"},
		sctx,
		withAgentGraph(graph, newScanBudget(), "sub_test"),
	)
	t.Cleanup(child.Stop)

	for _, name := range []string{"create_agent", "spawn_agent", "check_agent", "wait_agent"} {
		if _, ok := child.registry.Get(name); ok {
			t.Fatalf("delegated child unexpectedly exposes %q", name)
		}
	}
}

func TestDelegatedOptionsPropagateBenchmarkIsolation(t *testing.T) {
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	child := &Agent{}
	for _, opt := range delegatedAgentOptions(context.Background(), graph, newScanBudget(), "sub_bench", true) {
		opt(child)
	}
	if !child.benchmarkIsolated {
		t.Fatal("delegated child did not inherit benchmark isolation")
	}
	if child.agentGraph != graph || child.delegatedAgentID != "sub_bench" {
		t.Fatalf("delegated options did not preserve graph identity: graph=%p id=%q", child.agentGraph, child.delegatedAgentID)
	}
}

func TestMaybeAutoDelegateLaunchesOneDeterministicWave(t *testing.T) {
	tasks := make(chan struct {
		name string
		task string
	}, len(defaultSpecialistProfiles)+1)
	// Match the production lifetime cap: every engine lane (discovery +
	// testing wave) plus one manual spawn.
	graph := agentsgraph.NewWithLimit(context.Background(), len(defaultSpecialistProfiles)+1, func(_ context.Context, _ string, name string, _ []string, task string) (string, error) {
		tasks <- struct {
			name string
			task string
		}{name: name, task: task}
		return "lane exhausted", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)
	state := NewScanState()
	state.Iteration = 5
	state.ReconDone = true
	state.DelegationEnabled = true
	// Coverage-model evidence: the recon completion gate requires
	// HTTP probing, tech fingerprinting, and crawling/JS analysis.
	state.ReconCoverage.HTTPProbed = true
	state.ReconCoverage.TechFingerprinted = true
	state.ReconCoverage.Crawled = true
	state.ReconCoverage.ContentDiscoveredHosts["example.test"] = true
	// Applicability-informed dimension: the /api/ inventory means the wave
	// waits for API-surface discovery evidence (or a typed N/A disposition).
	state.ReconCoverage.APISurfaceDiscovered = true
	state.Plan = AutoPlan([]string{"/api/users"}, nil) // stale: built from the seeded surface only
	state.DiscoveredEndpoints = []string{"/api/users", "/admin/export", "/search"}
	state.PlanBuilt = true
	state.LedgerSeeded = true

	a := &Agent{
		registry:   registry,
		agentGraph: graph,
		state:      state,
		events:     make(chan Event, 16),
		targetAuth: "Authorization: Bearer operator-test-token",
	}
	if got := a.maybeAutoDelegate([]string{"https://example.test"}); got != "" || graph.DelegationCount() != 0 {
		t.Fatalf("delegation launched before an endpoint inventory: message=%q count=%d", got, graph.DelegationCount())
	}
	state.EndpointInventorySaved = true

	// ── Stage E: the discovery lane launches right after the inventory +
	// plan + ledger exist, in parallel with the root's remaining baseline
	// recon (dirbust + tech detection are still outstanding here).
	discoveryMsg := a.maybeAutoDelegate([]string{"https://example.test"})
	if graph.DelegationCount() != 1 {
		t.Fatalf("discovery lane: delegated %d agents, want 1", graph.DelegationCount())
	}
	if !strings.Contains(discoveryMsg, "ENGINE DISCOVERY LANE STARTED") {
		t.Fatalf("discovery lane message missing: %q", discoveryMsg)
	}
	if !state.ReconLaneLaunched || state.DelegationAttempted {
		t.Fatalf("discovery lane flags wrong: reconLane=%v waveAttempted=%v", state.ReconLaneLaunched, state.DelegationAttempted)
	}
	select {
	case got := <-tasks:
		if got.name != "recon-discovery" {
			t.Fatalf("first launch should be the discovery lane, got %q", got.name)
		}
		if !strings.Contains(got.task, "Discovery Manifest") {
			t.Fatalf("discovery lane task lacks the manifest contract: %s", got.task)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovery-lane task")
	}

	// The testing wave still waits for comprehensive recon.
	if got := a.maybeAutoDelegate([]string{"https://example.test"}); got != "" || graph.DelegationCount() != 1 {
		t.Fatalf("testing wave launched before comprehensive recon: message=%q count=%d", got, graph.DelegationCount())
	}
	state.DirBustingDone = true
	state.DirBustingUsedWordlist = true
	state.DetectedTechs["flask"] = true
	// Plan refresh now lives in the PLANNER (surface-revision based), not
	// in delegation code: simulate hookPlanner's refresh step so the wave
	// launches from the rebuilt plan exactly as production does. With zero
	// specialists the same refresh keeps the plan equally complete.
	if rev := surfaceRevision(state); rev != state.PlanSurfaceRevision {
		refreshEnginePlan(state)
		state.PlanSurfaceRevision = rev
	}

	// ── Stage W: the testing wave launches the non-overlapping lanes
	// (authz-logic included: operator token supplies both identities).
	message := a.maybeAutoDelegate([]string{"https://example.test"})
	if graph.DelegationCount() != len(defaultSpecialistProfiles) {
		t.Fatalf("delegated %d agents total, want %d (1 discovery + testing lanes)", graph.DelegationCount(), len(defaultSpecialistProfiles))
	}
	waveNames := map[string]bool{}
	for range a.eligibleSpecialistProfiles() {
		select {
		case got := <-tasks:
			if got.name == "recon-discovery" {
				t.Fatal("discovery lane must not relaunch with the testing wave")
			}
			waveNames[got.name] = true
			if want := "tmp/" + got.name + "/"; !strings.Contains(got.task, want) {
				t.Errorf("specialist %q lacks an isolated scratch directory %q in task: %s", got.name, want, got.task)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for delegated task")
		}
	}
	if !state.DelegationAttempted || !state.WaveLaunched || !strings.Contains(message, "ENGINE DELEGATION STARTED") {
		t.Fatalf("wave not recorded: attempted=%v wave=%v message=%q", state.DelegationAttempted, state.WaveLaunched, message)
	}
	// The stale one-endpoint plan must have been rebuilt from the full
	// discovered surface by the PLANNER refresh before wave launch, so
	// specialists partition every endpoint instead of the seeded subset.
	fresh := false
	for _, task := range state.Plan.Tasks {
		if strings.Contains(task.Notes, "/admin/export") {
			fresh = true
			break
		}
	}
	if !fresh {
		t.Fatal("wave launched from a stale plan: no task references the post-recon endpoint /admin/export")
	}
	if again := a.maybeAutoDelegate([]string{"https://example.test"}); again != "" {
		t.Fatalf("a second wave must never launch: %q", again)
	}
	if graph.DelegationCount() != len(defaultSpecialistProfiles) {
		t.Fatalf("second call changed lifetime delegation count to %d", graph.DelegationCount())
	}
}

func TestEligibleSpecialistProfilesRequireAuthenticatedIdentityForAuthz(t *testing.T) {
	// The recon-discovery lane launches EARLY and is excluded from the
	// testing wave; authz is filtered without identities.
	unauthenticated := (&Agent{}).eligibleSpecialistProfiles()
	if len(unauthenticated) != len(defaultSpecialistProfiles)-2 {
		t.Fatalf("anonymous-only scan got %d profiles, want %d", len(unauthenticated), len(defaultSpecialistProfiles)-2)
	}
	for _, profile := range unauthenticated {
		if profile.Role == "authz-logic" {
			t.Fatal("anonymous-only scan must not auto-launch the authz specialist")
		}
		if profile.Role == "recon-discovery" {
			t.Fatal("recon-discovery launches early, never with the testing wave")
		}
	}

	authenticated := (&Agent{targetAuth: "Authorization: Bearer operator-test-token"}).eligibleSpecialistProfiles()
	if len(authenticated) != len(defaultSpecialistProfiles)-1 {
		t.Fatalf("authenticated scan got %d profiles, want %d", len(authenticated), len(defaultSpecialistProfiles)-1)
	}
	for _, profile := range authenticated {
		if profile.Role == "recon-discovery" {
			t.Fatal("recon-discovery launches early, never with the testing wave")
		}
	}
}

func TestMaybeAutoDelegateSkipsNarrowModes(t *testing.T) {
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)
	readyState := func() *ScanState {
		state := NewScanState()
		state.Iteration = 5
		state.ReconDone = true
		state.EndpointInventorySaved = true
		state.DirBustingDone = true
		state.DetectedTechs["flask"] = true
		state.ReconCoverage.HTTPProbed = true
		state.ReconCoverage.TechFingerprinted = true
		state.ReconCoverage.Crawled = true
		state.ReconCoverage.ContentDiscoveredHosts["example.test"] = true
		state.Plan = AutoPlan([]string{"/"}, nil)
		state.PlanBuilt = true
		state.LedgerSeeded = true
		return state
	}

	for _, tc := range []struct {
		name      string
		configure func(*Agent)
	}{
		{name: "ctf", configure: func(a *Agent) { a.ctfMission = true }},
		{name: "discovery", configure: func(a *Agent) { a.state.DiscoveryMode = true }},
		{name: "delegated-child", configure: func(a *Agent) { a.delegatedAgentID = "sub-1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{registry: registry, agentGraph: graph, state: readyState()}
			tc.configure(a)
			if got := a.maybeAutoDelegate([]string{"https://example.test"}); got != "" {
				t.Fatalf("narrow mode unexpectedly delegated: %q", got)
			}
		})
	}
	if graph.DelegationCount() != 0 {
		t.Fatalf("narrow modes consumed delegation budget: %d", graph.DelegationCount())
	}
}

func TestDelegatedSubagentInheritsRootLLMClient(t *testing.T) {
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(sctx.Close)
	cfg := &config.Config{
		MaxIterations: 1,
		SkillsDir:     t.TempDir(),
		LLM:           "zai-org/GLM-5.3",
		APIBase:       "https://api.crusoecloud.com/v1",
	}

	endpoint := llm.Endpoint{
		URL:         "https://api.crusoecloud.com/v1/chat/completions",
		Model:       "zai-org/GLM-5.3",
		HeaderStyle: "openai",
		Auth:        llm.AuthAPIKey,
		APIKey:      "secret-key",
	}
	rootClient := llm.NewClient(cfg, llm.WithResolver(llm.NewFixedResolver(endpoint)))
	events := make(chan Event, 16)
	root := NewAgent(
		cfg,
		"root",
		events,
		scopeguard.Config{BindAddr: "127.0.0.1"},
		sctx,
		WithLLMClient(rootClient),
	)
	t.Cleanup(root.Stop)

	if root.client != rootClient {
		t.Fatalf("root.client = %p, want %p", root.client, rootClient)
	}

	opts := delegatedAgentOptions(context.Background(), root.agentGraph, root.scanBudget, "sub-test", false)
	subArgs := []any{sctx}
	for _, opt := range opts {
		subArgs = append(subArgs, opt)
	}
	if root.client != nil {
		subArgs = append(subArgs, WithLLMClient(root.client.Clone()))
	}
	subAgent := NewAgent(cfg, "sub", make(chan Event, 16), root.localGuard, subArgs...)
	t.Cleanup(subAgent.Stop)

	if subAgent.client == nil {
		t.Fatal("subAgent.client is nil")
	}
	if subAgent.client == rootClient {
		t.Fatal("subAgent.client is identical to rootClient pointer, want independent clone")
	}

	ep, err := subAgent.client.ResolveEndpoint(context.Background())
	if err != nil {
		t.Fatalf("subAgent.client.ResolveEndpoint: %v", err)
	}
	if ep.Model != "zai-org/GLM-5.3" {
		t.Fatalf("subAgent model = %q, want %q", ep.Model, "zai-org/GLM-5.3")
	}
	if ep.URL != "https://api.crusoecloud.com/v1/chat/completions" {
		t.Fatalf("subAgent url = %q, want %q", ep.URL, "https://api.crusoecloud.com/v1/chat/completions")
	}
}

// XALGORIX_DISABLED_SPECIALISTS excludes named lanes from both the early
// discovery stage and the testing wave, without touching the binary version.
func TestSpecialistDisabled(t *testing.T) {
	a := &Agent{}
	if a.specialistDisabled("recon-discovery") {
		t.Fatal("recon-discovery should be enabled with no config")
	}

	a = &Agent{cfg: &config.Config{
		DisabledSpecialists: []string{"recon-discovery"},
	}}
	if !a.specialistDisabled("recon-discovery") {
		t.Fatal("recon-discovery should be disabled")
	}
	if !a.specialistDisabled("RECON-DISCOVERY") {
		t.Fatal("case-insensitive match failed")
	}
	if a.specialistDisabled("injection-serverside") {
		t.Fatal("injection-serverside should still be enabled")
	}

	a = &Agent{cfg: &config.Config{
		DisabledSpecialists: []string{"recon-discovery", "authz-logic"},
	}}
	if !a.specialistDisabled("recon-discovery") || !a.specialistDisabled("authz-logic") {
		t.Fatal("both lanes should be disabled")
	}
	if a.specialistDisabled("client-source") {
		t.Fatal("client-source should still be enabled")
	}

	authenticated := &Agent{
		cfg:        &config.Config{DisabledSpecialists: []string{"injection-serverside"}},
		targetAuth: "Authorization: Bearer x",
	}
	for _, p := range authenticated.eligibleSpecialistProfiles() {
		if p.Role == "injection-serverside" {
			t.Fatal("disabled lane appeared in the testing wave")
		}
	}
}
