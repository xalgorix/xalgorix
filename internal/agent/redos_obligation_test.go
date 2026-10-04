package agent

import (
	"strings"
	"testing"
)

func TestAutoPlanRequiresReDoSLast(t *testing.T) {
	plan := AutoPlan([]string{"/widget"}, nil)
	redos := plan.Get("test-redos")
	if redos == nil || redos.VulnClass != "redos" || !redos.WholeTarget || redos.Status != TaskPending {
		t.Fatalf("automatic plan lacks a pending final ReDoS obligation: %+v", redos)
	}
	plan.Get("recon").Status = TaskCompleted
	plan.Get("dirbust").Status = TaskCompleted
	for _, task := range plan.Tasks {
		if task.ID != "test-redos" && task.ID != "recon" && task.ID != "dirbust" {
			task.Status = TaskSkipped
		}
	}
	if next := plan.NextTasks(1); len(next) != 1 || next[0].ID != "test-redos" {
		t.Fatalf("final task was not ReDoS: %+v", next)
	}
}

func TestBuiltPlanRetainsOneFinalReDoSObligation(t *testing.T) {
	state := NewScanState()
	agent := &Agent{state: state}
	for _, input := range []string{
		`[{"id":"recon","title":"Map routes","phase":1},{"id":"sqli","title":"Test SQL injection","phase":6,"vuln_class":"sqli"}]`,
		`[{"id":"recon","title":"Map routes","phase":1},{"id":"regex-check","title":"Check regex denial of service","phase":6}]`,
	} {
		if result, err := agent.buildPlanTool(map[string]string{"tasks": input}); err != nil || result.Error != "" {
			t.Fatalf("plan build failed: %v %+v", err, result)
		}
		count := 0
		for _, task := range state.Plan.Tasks {
			if isReDoSTask(task) {
				count++
				if task.VulnClass != "redos" || !task.WholeTarget {
					t.Fatalf("ReDoS task lost its coverage contract: %+v", task)
				}
			}
		}
		if count != 1 {
			t.Fatalf("expected exactly one final ReDoS task, got %d", count)
		}
	}
	if result, err := agent.updatePlanTool(map[string]string{"task_id": "regex-check", "status": "completed"}); err != nil || !strings.Contains(result.Error, "bounded probe") {
		t.Fatalf("plan update completed ReDoS without a probe: %v %+v", err, result)
	}
}

func TestReDoSCoverageRequiresExecutedAuthorizedProbe(t *testing.T) {
	state := NewScanState()
	state.Plan = NewPlan()
	state.Plan.add(newReDoSTask())
	probe := `curl -sk https://target.test/widget -X POST -d '{"name":"` + strings.Repeat("a", 30) + `"}'`
	for _, args := range []map[string]string{
		{"tool_name": "terminal_execute", "command": `curl -sk https://target.test/widget`, "output": strings.Repeat("a", 30)},
		{"tool_name": "terminal_execute", "command": probe, "output": `{"error":"must provide valid admin token"}`},
		{"tool_name": "terminal_execute", "command": probe, "error": "command failed", "output": "attempted"},
	} {
		hookReDoSResultTracker(state, args)
		if state.VulnClassesTested["redos"] {
			t.Fatalf("non-probe or rejected probe counted as ReDoS coverage: %+v", args)
		}
	}
	hookReDoSResultTracker(state, map[string]string{"tool_name": "terminal_execute", "command": probe,
		"output": "HTTP/1.1 504 Gateway Timeout; benign control was accepted"})
	if !state.VulnClassesTested["redos"] {
		t.Fatal("authorized completed probe did not count as ReDoS coverage")
	}
	reconcilePlan(state)
	if state.Plan.Get("test-redos").Status != TaskCompleted {
		t.Fatal("final ReDoS task stayed pending after a returned probe")
	}
}

func TestReDoSDispositionWaitsForFinalStage(t *testing.T) {
	state := NewScanState()
	state.PlanBuilt = true
	state.Plan = NewPlan()
	state.Plan.add(newReDoSTask())
	state.Plan.add(&Task{ID: "sqli", Title: "Test SQL injection", Status: TaskPending})
	args := map[string]string{"tool_name": "update_plan", "task_id": "test-redos", "status": "not_applicable"}
	if result := hookReDoSLast(state, args); !result.ForceSkip {
		t.Fatalf("ReDoS was dispositioned before the final stage: %+v", result)
	}
	state.Plan.Get("test-redos").Status = TaskActive
	if result := hookReDoSLast(state, map[string]string{"tool_name": "update_plan", "status": "completed"}); !result.ForceSkip {
		t.Fatalf("inferred ReDoS update bypassed the final-stage guard: %+v", result)
	}
	state.Plan.Get("test-redos").Status = TaskPending
	state.Plan.Get("sqli").Status = TaskCompleted
	if result := hookReDoSLast(state, args); result.ForceSkip {
		t.Fatalf("final ReDoS disposition remained blocked: %+v", result)
	}
}

func TestReDoSWaitsForProfessionalFinishReconPrerequisites(t *testing.T) {
	state := NewScanState()
	state.ProfessionalAssessment = true
	state.PlanBuilt = true
	state.Plan = NewPlan()
	state.Plan.add(&Task{ID: "recon", Title: "Map routes", Status: TaskCompleted})
	state.Plan.add(newReDoSTask())
	probe := map[string]string{"tool_name": "terminal_execute", "command": "curl -sk https://target.test/widget?name=" + strings.Repeat("a", 30)}
	result := hookReDoSLast(state, probe)
	if !result.ForceSkip || !strings.Contains(result.Nudge, "reconnaissance requirements") {
		t.Fatalf("ReDoS ran before the finish recon predicate was settled: %+v", result)
	}
}
