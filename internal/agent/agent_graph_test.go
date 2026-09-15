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
	}, len(defaultSpecialistProfiles))
	graph := agentsgraph.New(context.Background(), func(_ context.Context, _ string, name string, _ []string, task string) (string, error) {
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
	state.Plan = AutoPlan([]string{"/api/users"}, nil)
	state.PlanBuilt = true
	state.LedgerSeeded = true

	a := &Agent{
		registry:   registry,
		agentGraph: graph,
		state:      state,
		events:     make(chan Event, 16),
	}
	message := a.maybeAutoDelegate([]string{"https://example.test"})
	if graph.DelegationCount() != len(defaultSpecialistProfiles) {
		t.Fatalf("delegated %d agents, want one %d-agent wave", graph.DelegationCount(), len(defaultSpecialistProfiles))
	}
	for range defaultSpecialistProfiles {
		select {
		case got := <-tasks:
			if want := "tmp/" + got.name + "/"; !strings.Contains(got.task, want) {
				t.Errorf("specialist %q lacks an isolated scratch directory %q in task: %s", got.name, want, got.task)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for delegated task")
		}
	}
	if !state.DelegationAttempted || !strings.Contains(message, "ENGINE DELEGATION STARTED") {
		t.Fatalf("automatic delegation was not recorded: attempted=%v message=%q", state.DelegationAttempted, message)
	}
	if again := a.maybeAutoDelegate([]string{"https://example.test"}); again != "" {
		t.Fatalf("a second wave must never launch: %q", again)
	}
	if graph.DelegationCount() != len(defaultSpecialistProfiles) {
		t.Fatalf("second call changed lifetime delegation count to %d", graph.DelegationCount())
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
