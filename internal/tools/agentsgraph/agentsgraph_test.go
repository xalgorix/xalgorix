package agentsgraph

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func agentIDFromResult(t *testing.T, metadata map[string]any) string {
	t.Helper()
	agentID, ok := metadata["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("missing agent_id in metadata: %#v", metadata)
	}
	return agentID
}

func TestRegisterAlwaysExposesAsyncTools(t *testing.T) {
	graph := New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)

	for _, name := range []string{"create_agent", "spawn_agent", "check_agent", "wait_agent"} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("tool %q was not registered", name)
		}
	}
}

func TestSpawnPartialWaitAndCollection(t *testing.T) {
	release := make(chan struct{})
	graph := New(context.Background(), func(_ context.Context, agentID, name string, targets []string, task string) (string, error) {
		graphPartial := "runner=" + agentID
		_ = graphPartial
		<-release
		return "completed " + name + " on " + strings.Join(targets, ","), nil
	})
	t.Cleanup(graph.Stop)

	result, err := graph.spawnAgent(map[string]string{
		"name":   "authorization specialist",
		"task":   "test horizontal access controls",
		"target": "https://example.test/api",
	})
	if err != nil {
		t.Fatalf("spawnAgent: %v", err)
	}
	agentID := agentIDFromResult(t, result.Metadata)
	graph.AddPartialResult(agentID, "baseline 403; cross-account request pending")

	checked, err := graph.checkAgent(map[string]string{"agent_id": agentID})
	if err != nil {
		t.Fatalf("checkAgent: %v", err)
	}
	if !strings.Contains(checked.Output, "RUNNING") || !strings.Contains(checked.Output, "baseline 403") {
		t.Fatalf("unexpected running output:\n%s", checked.Output)
	}

	close(release)
	waited, err := graph.waitAgent(map[string]string{"agent_id": agentID, "timeout": "5"})
	if err != nil {
		t.Fatalf("waitAgent: %v", err)
	}
	if !strings.Contains(waited.Output, "COMPLETED") || !strings.Contains(waited.Output, "completed authorization specialist") {
		t.Fatalf("unexpected wait output:\n%s", waited.Output)
	}
	if got := graph.UncollectedCount(); got != 0 {
		t.Fatalf("uncollected count = %d, want 0 after wait", got)
	}
}

func TestGraphsAreIsolatedAcrossConcurrentScans(t *testing.T) {
	graphA := New(context.Background(), func(_ context.Context, _ string, _ string, _ []string, _ string) (string, error) {
		return "result from scan A", nil
	})
	graphB := New(context.Background(), func(_ context.Context, _ string, _ string, _ []string, _ string) (string, error) {
		return "result from scan B", nil
	})
	t.Cleanup(graphA.Stop)
	t.Cleanup(graphB.Stop)

	resultA, err := graphA.spawnAgent(map[string]string{"name": "A", "task": "scan A"})
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := graphB.spawnAgent(map[string]string{"name": "B", "task": "scan B"})
	if err != nil {
		t.Fatal(err)
	}

	waitA, err := graphA.waitAgent(map[string]string{"agent_id": agentIDFromResult(t, resultA.Metadata), "timeout": "5"})
	if err != nil {
		t.Fatal(err)
	}
	waitB, err := graphB.waitAgent(map[string]string{"agent_id": agentIDFromResult(t, resultB.Metadata), "timeout": "5"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(waitA.Output, "result from scan A") || strings.Contains(waitA.Output, "scan B") {
		t.Fatalf("scan A cross-wired result:\n%s", waitA.Output)
	}
	if !strings.Contains(waitB.Output, "result from scan B") || strings.Contains(waitB.Output, "scan A") {
		t.Fatalf("scan B cross-wired result:\n%s", waitB.Output)
	}
}

func TestConcurrencyLimitIsPerGraph(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	graph := NewWithLimit(context.Background(), 2, func(_ context.Context, _ string, _ string, _ []string, _ string) (string, error) {
		started <- struct{}{}
		<-release
		return "done", nil
	})
	t.Cleanup(graph.Stop)

	for i := 0; i < 2; i++ {
		result, err := graph.spawnAgent(map[string]string{"name": "worker", "task": "hold slot"})
		if err != nil || result.Metadata == nil {
			t.Fatalf("spawn %d: result=%#v err=%v", i, result, err)
		}
	}
	<-started
	<-started
	blocked, err := graph.spawnAgent(map[string]string{"name": "overflow", "task": "must not run"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(blocked.Output, "2/2") || blocked.Metadata != nil {
		t.Fatalf("unexpected capacity result: %#v", blocked)
	}
	close(release)
	if !graph.WaitStopped(2 * time.Second) {
		t.Fatal("workers did not stop")
	}
}

func TestDelegationLimitIsLifetimeBudgetNotOnlyConcurrency(t *testing.T) {
	graph := NewWithLimit(context.Background(), 2, func(_ context.Context, _ string, name string, _ []string, _ string) (string, error) {
		return "done " + name, nil
	})
	t.Cleanup(graph.Stop)

	for _, name := range []string{"first", "second"} {
		spawned, err := graph.spawnAgent(map[string]string{"name": name, "task": "bounded lane"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graph.waitAgent(map[string]string{
			"agent_id": agentIDFromResult(t, spawned.Metadata),
			"timeout":  "5",
		}); err != nil {
			t.Fatal(err)
		}
	}

	blocked, err := graph.spawnAgent(map[string]string{"name": "third", "task": "replacement wave"})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Metadata != nil || !strings.Contains(blocked.Output, "delegation budget exhausted (2/2") {
		t.Fatalf("unexpected lifetime-budget result: %#v", blocked)
	}
	if got := graph.DelegationCount(); got != 2 {
		t.Fatalf("delegation count = %d, want 2", got)
	}
}

func TestSynchronousDelegationAlsoConsumesLifetimeBudget(t *testing.T) {
	graph := NewWithLimit(context.Background(), 1, func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)

	created, err := graph.createAgent(map[string]string{"name": "sync", "task": "bounded lane"})
	if err != nil || !strings.Contains(created.Output, "completed") {
		t.Fatalf("create result=%#v err=%v", created, err)
	}
	blocked, err := graph.spawnAgent(map[string]string{"name": "async", "task": "must not run"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(blocked.Output, "delegation budget exhausted (1/1") {
		t.Fatalf("synchronous delegation did not consume budget: %#v", blocked)
	}
}

func TestStopCancelsRunnersAndUnblocksWaiters(t *testing.T) {
	started := make(chan struct{})
	graph := New(context.Background(), func(ctx context.Context, _ string, _ string, _ []string, _ string) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	})

	result, err := graph.spawnAgent(map[string]string{"name": "slow", "task": "wait for cancellation"})
	if err != nil {
		t.Fatal(err)
	}
	agentID := agentIDFromResult(t, result.Metadata)
	<-started

	var wg sync.WaitGroup
	wg.Add(1)
	waited := make(chan tools.Result, 1)
	go func() {
		defer wg.Done()
		res, _ := graph.waitAgent(map[string]string{"agent_id": agentID, "timeout": "30"})
		waited <- res
	}()

	graph.Stop()
	if !graph.WaitStopped(2 * time.Second) {
		t.Fatal("canceled runner did not unwind")
	}
	wg.Wait()
	res := <-waited
	if !strings.Contains(res.Output, "FAILED") || !strings.Contains(res.Output, "parent scan stopped") {
		t.Fatalf("unexpected stopped result:\n%s", res.Output)
	}
	if got := graph.RunningCount(); got != 0 {
		t.Fatalf("running count after stop = %d, want 0", got)
	}
}

func TestCompletedResultMustBeCollected(t *testing.T) {
	graph := New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "evidence", nil
	})
	t.Cleanup(graph.Stop)
	result, err := graph.spawnAgent(map[string]string{"name": "specialist", "task": "produce evidence"})
	if err != nil {
		t.Fatal(err)
	}
	agentID := agentIDFromResult(t, result.Metadata)

	deadline := time.Now().Add(2 * time.Second)
	for graph.RunningCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := graph.UncollectedCount(); got != 1 {
		t.Fatalf("uncollected count = %d, want 1", got)
	}
	if summary := graph.PendingSummary(); !strings.Contains(summary, agentID) || !strings.Contains(summary, "not collected") {
		t.Fatalf("unexpected pending summary: %q", summary)
	}
	if _, err := graph.checkAgent(map[string]string{"agent_id": agentID}); err != nil {
		t.Fatal(err)
	}
	if got := graph.UncollectedCount(); got != 0 {
		t.Fatalf("uncollected count after check = %d, want 0", got)
	}
}
