package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

func TestReDoSPlanRunsAfterOtherTasks(t *testing.T) {
	plan := NewPlan()
	for _, task := range []*Task{
		{ID: "recon", Title: "Map the surface", Phase: 1, Status: TaskCompleted},
		{ID: "redos", Title: "Test regex denial-of-service", Phase: 6, VulnClass: "redos", Status: TaskPending, DependsOn: []string{"recon"}},
		{ID: "auth", Title: "Test authentication", Phase: 8, Status: TaskPending, DependsOn: []string{"recon"}},
	} {
		if !plan.add(task) {
			t.Fatalf("could not add %q", task.ID)
		}
	}

	if next := plan.NextTasks(3); len(next) != 1 || next[0].ID != "auth" {
		t.Fatalf("ReDoS became ready while other work remained: %+v", next)
	}
	plan.Get("auth").Status = TaskSkipped
	if next := plan.NextTasks(3); len(next) != 1 || next[0].ID != "redos" {
		t.Fatalf("ReDoS was not scheduled after other work settled: %+v", next)
	}
}

func TestReDoSWaitsForDelegatedResults(t *testing.T) {
	release := make(chan struct{})
	graph := agentsgraph.NewWithLimit(context.Background(), 1,
		func(ctx context.Context, _, _ string, _ []string, _ string) (string, error) {
			select {
			case <-release:
				return "lane complete", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		})
	t.Cleanup(func() {
		graph.Stop()
		graph.WaitStopped(time.Second)
	})
	registry := tools.NewRegistry()
	graph.Register(registry)
	spawned, err := registry.Execute("spawn_agent", map[string]string{
		"name": "other-lane", "task": "Test another class", "target": "https://target.test",
	})
	if err != nil || spawned.Metadata["spawned"] != true {
		t.Fatalf("could not start specialist: %v %+v", err, spawned)
	}
	identifier, _ := spawned.Metadata["agent_id"].(string)
	a := &Agent{agentGraph: graph}
	probe := map[string]string{"tool_name": "http_request", "url": "https://target.test/widget", "body": `{"name":"` + strings.Repeat("a", 30) + `"}`}
	if result := a.delegatedWorkReDoSGuard(nil, probe); !result.ForceSkip {
		t.Fatalf("running specialist did not defer ReDoS: %+v", result)
	}
	close(release)
	collected, err := registry.Execute("wait_agent", map[string]string{"agent_id": identifier})
	if err != nil || collected.Metadata["status"] != "completed" {
		t.Fatalf("specialist result was not collected: %v %+v", err, collected)
	}
	if result := a.delegatedWorkReDoSGuard(nil, probe); result.ForceSkip {
		t.Fatalf("final ReDoS stage remained blocked: %+v", result)
	}
}

func TestReDoSRequestGuardDefersActualEarlyProbes(t *testing.T) {
	state := NewScanState()
	state.PlanBuilt = true
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "redos", Title: "Test ReDoS", VulnClass: "redos", Status: TaskPending})
	state.Plan.add(&Task{ID: "sqli", Title: "Test SQL injection", VulnClass: "sqli", Status: TaskPending})
	registry := NewHookRegistry()
	RegisterDefaultHooks(registry)

	for _, args := range []map[string]string{
		{"tool_name": "terminal_execute", "command": `curl -sk https://target.test/widget -X POST -d '{"name":"` + strings.Repeat("a", 30) + `"}'`},
		{"tool_name": "http_request", "url": "https://target.test/widget", "body": `{"name":"` + strings.Repeat("a", 30) + `"}`},
		{"tool_name": "python_action", "code": `requests.post("https://target.test/widget", json={"name":"a"*30})`},
		{"tool_name": "spawn_agent", "name": "regex-lane", "task": "Test ReDoS on the widget input"},
	} {
		result := registry.Fire(OnToolCall, state, args)
		if !result.ForceSkip || !strings.Contains(result.Nudge, "final availability stage") {
			t.Fatalf("early ReDoS action was allowed: %q %+v", args["tool_name"], result)
		}
	}
	if state.MeaningfulTestCalls != 0 {
		t.Fatalf("blocked probes counted as executed work: %d", state.MeaningfulTestCalls)
	}

	benign := map[string]string{"tool_name": "terminal_execute", "command": `curl -sk https://target.test/widget -d '{"name":"widget1"}'`}
	if result := registry.Fire(OnToolCall, state, benign); result.ForceSkip {
		t.Fatalf("ordinary testing was blocked: %+v", result)
	}

	state.Plan.Get("sqli").Status = TaskCompleted
	probe := map[string]string{"tool_name": "http_request", "url": "https://target.test/widget", "body": `{"name":"` + strings.Repeat("a", 30) + `"}`}
	if result := registry.Fire(OnToolCall, state, probe); result.ForceSkip {
		t.Fatalf("final-stage ReDoS probe was blocked: %+v", result)
	}
}
