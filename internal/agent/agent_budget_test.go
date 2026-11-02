package agent

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
)

func TestScanBudgetAtomicallyCapsParallelToolReservations(t *testing.T) {
	budget := newScanBudget()
	const cap = 5

	var wg sync.WaitGroup
	allowed := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- budget.reserveToolCalls(1, cap)
		}()
	}
	wg.Wait()
	close(allowed)

	total := 0
	for count := range allowed {
		total += count
	}
	if total != cap {
		t.Fatalf("parallel reservations allowed %d calls, want exactly %d", total, cap)
	}
	if got := budget.toolCallCount(); got != cap {
		t.Fatalf("recorded tool calls = %d, want %d", got, cap)
	}
}

func TestScanBudgetAtomicallyCapsParallelAgentIterations(t *testing.T) {
	budget := newScanBudget()
	const cap = 7

	var wg sync.WaitGroup
	allowed := make(chan bool, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- budget.reserveIteration(cap)
		}()
	}
	wg.Wait()
	close(allowed)

	granted := 0
	for ok := range allowed {
		if ok {
			granted++
		}
	}
	if granted != cap || budget.iterationCount() != cap {
		t.Fatalf("parallel iterations granted=%d recorded=%d, want %d", granted, budget.iterationCount(), cap)
	}
}

func TestOverBudgetUsesGraphWideToolAndTokenLedger(t *testing.T) {
	budget := newScanBudget()
	if allowed := budget.reserveToolCalls(5, 5); allowed != 5 {
		t.Fatalf("initial reservation = %d, want 5", allowed)
	}
	agent := &Agent{
		cfg:        &config.Config{MaxToolCalls: 5},
		scanBudget: budget,
	}
	if over, reason := agent.overBudget(0); !over || reason == "" {
		t.Fatalf("shared tool budget was not enforced: over=%v reason=%q", over, reason)
	}
}

func TestScanBudgetStartIsSharedAndStable(t *testing.T) {
	budget := newScanBudget()
	budget.start()
	budget.startedMu.RLock()
	first := budget.startedAt
	budget.startedMu.RUnlock()
	time.Sleep(time.Millisecond)
	budget.start()
	budget.startedMu.RLock()
	second := budget.startedAt
	budget.startedMu.RUnlock()
	if !first.Equal(second) {
		t.Fatalf("delegated start reset root budget clock: first=%v second=%v", first, second)
	}
}

func TestDelegatedAgentInheritsRootScanBudget(t *testing.T) {
	budget := newScanBudget()
	child := &Agent{}
	withAgentGraph(nil, budget, "sub_test")(child)
	if child.scanBudget != budget {
		t.Fatal("delegated agent did not inherit root scan budget")
	}
	if child.delegatedAgentID != "sub_test" {
		t.Fatalf("delegated id = %q, want sub_test", child.delegatedAgentID)
	}
}

func TestScanCostSumsEveryAgentsReportedCost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],` +
			`"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"cost":0.5}}`))
	}))
	defer srv.Close()

	budget := newScanBudget()
	root := &Agent{client: llm.NewClient(&config.Config{LLM: "openai/gpt-test", APIBase: srv.URL, APIKey: "test"}), scanBudget: budget}
	child := &Agent{client: root.client.Clone(), scanBudget: budget}
	for _, a := range []*Agent{root, child, child} {
		if _, err := a.client.Chat([]llm.Message{{Role: "user", Content: "ping"}}); err != nil {
			t.Fatalf("Chat: %v", err)
		}
		a.syncBudgetTokens()
	}
	// Syncing again must not count the same spend twice.
	child.syncBudgetTokens()
	if got := root.ScanCostUSD(); got != 1.5 {
		t.Fatalf("scan cost = %v, want 1.5 (root 0.5 + subagent 1.0)", got)
	}
}
