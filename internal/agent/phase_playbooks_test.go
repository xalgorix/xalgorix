package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
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

var playbookTestPolicy = scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"}

func playbookTestAgent(t *testing.T, cfg *config.Config) *Agent {
	t.Helper()
	registry := tools.NewRegistry()
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	graph.Register(registry)
	return &Agent{cfg: cfg, registry: registry}
}

// startPlaybookAgent builds the system prompt and seeds the conversation the
// way Run does.
func startPlaybookAgent(t *testing.T, cfg *config.Config) *Agent {
	t.Helper()
	a := playbookTestAgent(t, cfg)
	prompt := a.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
	a.messages = []llm.Message{{Role: "system", Content: prompt}, {Role: "user", Content: "Begin the assessment."}}
	return a
}

func phaseHeading(t *testing.T, checklist string, phase int) string {
	t.Helper()
	for _, m := range phaseHeadingRE.FindAllStringSubmatch(checklist, -1) {
		if m[1] == strconv.Itoa(phase) {
			return m[0]
		}
	}
	t.Fatalf("checklist has no Phase %d heading", phase)
	return ""
}

// TestDeferPhasePlaybooksPreservesEveryWord verifies that deferral moves text
// and never changes it: putting each deferred body back in place of its note
// reproduces the original checklist byte for byte.
func TestDeferPhasePlaybooksPreservesEveryWord(t *testing.T) {
	full := rateLimitedChecklist(defaultChecklist, playbookTestPolicy)
	deferred, playbooks := deferPhasePlaybooks(full)

	var phases []int
	for p := range playbooks {
		phases = append(phases, p)
	}
	sort.Ints(phases)
	for _, must := range []int{1, 3, 4, 6, 8} {
		if _, ok := playbooks[must]; !ok {
			t.Errorf("large Phase %d was not deferred (deferred: %v)", must, phases)
		}
	}
	for p, pb := range playbooks {
		if p > maxDeferredPhase {
			t.Errorf("Phase %d has no task trigger but was deferred", p)
		}
		if len(pb.Body) < minDeferredPhaseBytes {
			t.Errorf("Phase %d body is only %d bytes but was deferred", p, len(pb.Body))
		}
	}
	for _, keep := range []int{20, 21, 22} {
		if _, ok := playbooks[keep]; ok {
			t.Errorf("Phase %d must stay in the prompt", keep)
		}
	}

	rebuilt := deferred
	for p, pb := range playbooks {
		withNote := pb.Heading + phasePlaybookNote(p)
		if strings.Count(rebuilt, withNote) != 1 {
			t.Fatalf("Phase %d note not found exactly once", p)
		}
		rebuilt = strings.Replace(rebuilt, withNote, pb.Heading+pb.Body, 1)
	}
	if rebuilt != full {
		t.Fatal("re-inserting the deferred playbooks does not reproduce the original checklist")
	}
	if saved := len(full) - len(deferred); saved < 40000 {
		t.Fatalf("deferral saved only %d bytes", saved)
	}
}

// TestPhasePlaybooksOnlyWhenEnabledForTheRootChecklist verifies that the
// prompt is unchanged with the setting off, and that only the root agent's
// full checklist is ever deferred.
func TestPhasePlaybooksOnlyWhenEnabledForTheRootChecklist(t *testing.T) {
	full := rateLimitedChecklist(defaultChecklist, playbookTestPolicy)
	_, playbooks := deferPhasePlaybooks(full)
	injectionBody := playbooks[6].Body

	off := playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full"})
	offPrompt := off.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
	if !strings.Contains(offPrompt, full) || off.phasePlaybooks != nil {
		t.Fatal("with the setting off the prompt must carry the full checklist and nothing is deferred")
	}

	on := playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full", PhasePlaybooks: true})
	onPrompt := on.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
	if strings.Contains(onPrompt, injectionBody) {
		t.Fatal("with the setting on the Phase 6 body must not be in the system prompt")
	}
	if !strings.Contains(onPrompt, phaseHeading(t, full, 6)) || !strings.Contains(onPrompt, phasePlaybookNote(6)) {
		t.Fatal("the Phase 6 heading and its note must stay in the system prompt")
	}
	for _, keep := range []int{20, 22} {
		if !strings.Contains(onPrompt, phaseHeading(t, full, keep)) {
			t.Fatalf("Phase %d must stay in the system prompt", keep)
		}
	}
	if len(offPrompt)-len(onPrompt) < 40000 {
		t.Fatalf("system prompt shrank by only %d bytes", len(offPrompt)-len(onPrompt))
	}

	for name, a := range map[string]*Agent{
		"delegated agent":        playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full", PhasePlaybooks: true}),
		"discovery agent":        playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full", PhasePlaybooks: true}),
		"professional checklist": playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "professional", PhasePlaybooks: true}),
	} {
		switch name {
		case "delegated agent":
			a.delegatedAgentID = "child-1"
		case "discovery agent":
			a.discoveryMode = true
		}
		a.buildSystemPrompt([]string{"https://example.test"}, "Work one lane.", playbookTestPolicy)
		if a.phasePlaybooks != nil {
			t.Errorf("%s: nothing may be deferred", name)
		}
	}
}

func playbookMessages(a *Agent) map[int]int {
	out := map[int]int{}
	for _, m := range a.messages {
		for p := 1; p <= 22; p++ {
			if strings.HasPrefix(m.Content, phasePlaybookMarker(p)) {
				out[p]++
			}
		}
	}
	return out
}

// TestInjectPhasePlaybooksFollowsThePlan verifies delivery: phase 1 before a
// plan exists, then the phases of active and next-ready tasks, each once, in
// their original words, and again after compaction drops them.
func TestInjectPhasePlaybooksFollowsThePlan(t *testing.T) {
	full := rateLimitedChecklist(defaultChecklist, playbookTestPolicy)
	a := startPlaybookAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full", PhasePlaybooks: true})

	// No plan yet: recon.
	if added := a.injectPhasePlaybooks(); len(added) != 1 || added[0] != 1 {
		t.Fatalf("before a plan exists, added %v, want [1]", added)
	}
	last := a.messages[len(a.messages)-1].Content
	if want := phasePlaybookMarker(1) + "\n" + phaseHeading(t, full, 1); !strings.HasPrefix(last, want) {
		t.Fatalf("Phase 1 playbook starts %q, want %q", last[:min(len(last), 80)], want)
	}
	if !strings.Contains(full, strings.TrimPrefix(last, phasePlaybookMarker(1)+"\n")) {
		t.Fatal("the delivered Phase 1 playbook is not the original checklist text")
	}
	if added := a.injectPhasePlaybooks(); len(added) != 0 {
		t.Fatalf("a playbook already in the conversation was added again: %v", added)
	}

	// Recon done; IDOR active; injection next.
	plan := NewPlan()
	plan.add(&Task{ID: "recon", Phase: 1, Status: TaskCompleted})
	plan.add(&Task{ID: "test-sqli", Phase: 6, VulnClass: "sqli", Status: TaskPending, DependsOn: []string{"recon"}})
	plan.add(&Task{ID: "idor", Phase: 8, VulnClass: "idor", Status: TaskActive, DependsOn: []string{"recon"}})
	plan.add(&Task{ID: "report", Phase: 22, Status: TaskPending, DependsOn: []string{"test-sqli", "idor"}})
	a.state = &ScanState{Plan: plan}
	added := a.injectPhasePlaybooks()
	sort.Ints(added)
	if len(added) != 2 || added[0] != 6 || added[1] != 8 {
		t.Fatalf("with IDOR active and injection next, added %v, want [6 8]", added)
	}
	if got := playbookMessages(a); got[1] != 1 || got[6] != 1 || got[8] != 1 {
		t.Fatalf("playbook messages = %v, want one each for phases 1, 6 and 8", got)
	}

	// Compaction drops the older messages, including the Phase 6 playbook.
	kept := []llm.Message{a.messages[0], {Role: "user", Content: "[CONTEXT PRUNED: 4 older messages were compacted.]\n... " + phasePlaybookMarker(6) + " ..."}}
	a.messages = kept
	added = a.injectPhasePlaybooks()
	sort.Ints(added)
	if len(added) != 2 || added[0] != 6 || added[1] != 8 {
		t.Fatalf("after compaction, added %v, want [6 8]", added)
	}
}

// TestInjectPhasePlaybooksSkipsPromptsThatDoNotDefer verifies that nothing is
// delivered when the live system prompt still carries the full checklist, as
// in a scan resumed from a checkpoint saved without the setting, or when the
// setting is off.
func TestInjectPhasePlaybooksSkipsPromptsThatDoNotDefer(t *testing.T) {
	resumed := startPlaybookAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full", PhasePlaybooks: true})
	old := playbookTestAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full"})
	resumed.messages[0].Content = old.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
	if added := resumed.injectPhasePlaybooks(); len(added) != 0 {
		t.Fatalf("a prompt with the full checklist got playbooks %v", added)
	}

	off := startPlaybookAgent(t, &config.Config{RateLimitRPS: 2, Checklist: "full"})
	if added := off.injectPhasePlaybooks(); len(added) != 0 {
		t.Fatalf("with the setting off, added %v", added)
	}
}

// TestRunSendsPhaseOnePlaybookOnTheFirstCall runs the real agent loop against
// a chat-completions stub with the setting on. The first request must carry a
// system prompt that defers the large phases and, in the same request, the
// Phase 1 playbook. This fails if Run stops calling injectPhasePlaybooks
// before the model call.
func TestRunSendsPhaseOnePlaybookOnTheFirstCall(t *testing.T) {
	first := make(chan capturedChatRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var req capturedChatRequest
		_ = json.Unmarshal(body, &req)
		select {
		case first <- req:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Mapping the target first."}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	}))
	t.Cleanup(srv.Close)

	sctx := scanctx.New("phase-playbooks-run", t.TempDir())
	t.Cleanup(sctx.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := &config.Config{LLM: "test-model", APIBase: srv.URL, APIKey: "test-key", Checklist: "full", PhasePlaybooks: true, RateLimitRPS: 2}
	events := make(chan Event, 1024)
	a := NewAgent(cfg, "phase-playbooks-test", events, scopeguard.Config{BindAddr: "127.0.0.1"}, sctx, withParentContext(ctx))
	done := make(chan struct{})
	go func() {
		a.Run([]string{"https://example.invalid"}, "")
		close(done)
	}()
	go func() {
		for range events {
		}
	}()
	t.Cleanup(func() {
		a.Stop()
		cancel()
		select {
		case <-done:
			close(events)
		case <-time.After(30 * time.Second):
			t.Error("agent did not stop during test cleanup")
		}
	})

	var req capturedChatRequest
	select {
	case req = <-first:
	case <-time.After(90 * time.Second):
		t.Fatal("the agent never called the model")
	}
	var system string
	playbook := false
	for _, m := range req.Messages {
		var s string
		if err := json.Unmarshal(m.Content, &s); err != nil {
			s = string(m.Content)
		}
		if m.Role == "system" {
			system = s
		}
		if m.Role == "user" && strings.HasPrefix(s, phasePlaybookMarker(1)) {
			playbook = true
		}
	}
	if !strings.Contains(system, phasePlaybookNote(6)) {
		t.Fatal("the first request's system prompt does not defer Phase 6")
	}
	if !playbook {
		t.Fatal("the first request does not carry the Phase 1 playbook")
	}
}
