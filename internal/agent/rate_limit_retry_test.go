package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestRateLimitRetry_ProgressiveBackoffPolicy(t *testing.T) {
	a := &Agent{}
	if got := a.rateLimitBackoff(0); got != 15*time.Second {
		t.Fatalf("expected 15s for attempt 0, got %s", got)
	}
	if got := a.rateLimitBackoff(1); got != 15*time.Second {
		t.Fatalf("expected 15s for attempt 1, got %s", got)
	}
	if got := a.rateLimitBackoff(2); got != 30*time.Second {
		t.Fatalf("expected 30s for attempt 2, got %s", got)
	}
	if got := a.rateLimitBackoff(3); got != 60*time.Second {
		t.Fatalf("expected 60s for attempt 3, got %s", got)
	}
	if got := a.rateLimitBackoff(10); got != 60*time.Second {
		t.Fatalf("expected 60s for attempt 10, got %s", got)
	}
}

func TestRateLimitRetry_RecoversAfter429(t *testing.T) {
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "Rate limit exceeded. Please retry later.",
					"type":    "tokens",
				},
			})
			return
		}

		// On retry, succeed with finish tool call
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"role":    "assistant",
						"content": `<function=finish><parameter=summary>Scan completed after rate limit recovery</parameter></function>`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cfg := &config.Config{
		LLM:                 "openai/gpt-test",
		APIBase:             srv.URL,
		APIKey:              "sk-test",
		MaxRateLimitWaitSec: 30,
	}

	events := make(chan Event, 64)
	client := llm.NewClient(cfg)
	guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0}

	ag := NewAgent(
		cfg,
		"rate-limit-test-agent",
		events,
		guard,
		WithLLMClient(client),
		withRateLimitBackoff(func(consecutive int) time.Duration {
			return 10 * time.Millisecond // fast backoff for test
		}),
	)

	done := make(chan struct{})
	var eventList []Event
	go func() {
		defer close(done)
		for ev := range events {
			eventList = append(eventList, ev)
		}
	}()

	ag.Run([]string{"example.com"}, "Run security assessment")
	close(events)
	<-done

	if atomic.LoadInt32(&requestCount) < 2 {
		t.Fatalf("expected at least 2 requests (initial 429 + retry), got %d", atomic.LoadInt32(&requestCount))
	}

	var sawRateLimitNotice bool
	var finishedNormally bool
	for _, ev := range eventList {
		if ev.Type == "error" && ev.Content != "" && (ev.Content[0:3] == "⏳" || ev.Content[0:2] == "⏳") {
			sawRateLimitNotice = true
		}
		if ev.Type == "finished" && !ev.Aborted {
			finishedNormally = true
		}
	}

	if !sawRateLimitNotice {
		t.Error("expected to see rate limit retry notification event")
	}
	if !finishedNormally {
		t.Error("expected agent to finish normally after recovering from rate limit")
	}
	if ag.state.ConsecutiveRateLimits != 0 {
		t.Errorf("expected ConsecutiveRateLimits to be reset to 0 after healthy response, got %d", ag.state.ConsecutiveRateLimits)
	}
}

func TestRateLimitRetry_CumulativeBudgetExhausted(t *testing.T) {
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Quota exceeded permanently.",
				"type":    "tokens",
			},
		})
	}))
	defer srv.Close()

	// 1 second max budget
	cfg := &config.Config{
		LLM:                 "openai/gpt-test",
		APIBase:             srv.URL,
		APIKey:              "sk-test",
		MaxRateLimitWaitSec: 1,
	}

	events := make(chan Event, 64)
	client := llm.NewClient(cfg)
	guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0}

	ag := NewAgent(
		cfg,
		"rate-limit-budget-test",
		events,
		guard,
		WithLLMClient(client),
		withRateLimitBackoff(func(consecutive int) time.Duration {
			return 250 * time.Millisecond
		}),
	)

	done := make(chan struct{})
	var eventList []Event
	go func() {
		defer close(done)
		for ev := range events {
			eventList = append(eventList, ev)
		}
	}()

	ag.Run([]string{"example.com"}, "Run security assessment")
	close(events)
	<-done

	// Should have retried several times before exhausting the 1s budget
	reqs := atomic.LoadInt32(&requestCount)
	if reqs < 2 {
		t.Fatalf("expected multiple retry attempts before budget exhaustion, got %d", reqs)
	}

	var sawAbort bool
	for _, ev := range eventList {
		if ev.Type == "finished" && ev.Aborted && ev.AbortReason == "llm_rate_limited" {
			sawAbort = true
			break
		}
	}
	if !sawAbort {
		t.Errorf("expected finished event with AbortReason=llm_rate_limited")
	}
}

func TestRateLimitRetry_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Too Many Requests",
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		LLM:                 "openai/gpt-test",
		APIBase:             srv.URL,
		APIKey:              "sk-test",
		MaxRateLimitWaitSec: 30,
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 64)
	client := llm.NewClient(cfg)
	guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0}

	ag := NewAgent(
		cfg,
		"rate-limit-cancel-test",
		events,
		guard,
		WithLLMClient(client),
		withParentContext(ctx),
		withRateLimitBackoff(func(consecutive int) time.Duration {
			return 10 * time.Second // large backoff
		}),
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range events {
		}
	}()

	start := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel() // cancel during backoff
	}()

	ag.Run([]string{"example.com"}, "Run security assessment")
	close(events)
	<-done
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("expected immediate cancellation during backoff, but took %s", elapsed)
	}
}
