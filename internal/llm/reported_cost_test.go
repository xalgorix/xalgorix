package llm

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func costServer(t *testing.T, body string, stream bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func costClient(srvURL string) *Client {
	return NewClient(&config.Config{LLM: "openai/gpt-test", APIBase: srvURL, APIKey: "test"})
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestReportedCostIsSummedAcrossResponses(t *testing.T) {
	srv := costServer(t, `{"choices":[{"message":{"role":"assistant","content":"pong"}}],`+
		`"usage":{"prompt_tokens":100,"completion_tokens":40,"total_tokens":140,"cost":0.00125}}`, false)
	c := costClient(srv.URL)
	for i := 0; i < 2; i++ {
		if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
			t.Fatalf("Chat: %v", err)
		}
	}
	if got := c.GetReportedCostUSD(); !near(got, 0.0025) {
		t.Fatalf("reported cost = %v, want 0.0025", got)
	}
}

func TestReportedCostFromTheFinalStreamChunk(t *testing.T) {
	srv := costServer(t,
		"data: {\"choices\":[{\"delta\":{\"content\":\"po\"}}]}\n\n"+
			"data: {\"choices\":[{\"delta\":{\"content\":\"ng\"}}]}\n\n"+
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":40,\"total_tokens\":140,\"cost\":0.000021}}\n\n"+
			"data: [DONE]\n\n", true)
	c := costClient(srv.URL)
	for chunk := range c.ChatStream([]Message{{Role: "user", Content: "ping"}}) {
		if chunk.Err != nil {
			t.Fatalf("stream: %v", chunk.Err)
		}
	}
	if got := c.GetReportedCostUSD(); !near(got, 0.000021) {
		t.Fatalf("reported cost = %v, want 0.000021", got)
	}
}

func TestBYOKCostAddsTheUpstreamCharge(t *testing.T) {
	srv := costServer(t, `{"choices":[{"message":{"role":"assistant","content":"pong"}}],`+
		`"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14,"cost":0.0001,`+
		`"is_byok":true,"cost_details":{"upstream_inference_cost":0.002}}}`, false)
	c := costClient(srv.URL)
	if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if got := c.GetReportedCostUSD(); !near(got, 0.0021) {
		t.Fatalf("BYOK cost = %v, want 0.0021", got)
	}
}

func TestNoReportedCostStaysZero(t *testing.T) {
	srv := costServer(t, `{"choices":[{"message":{"role":"assistant","content":"pong"}}],`+
		`"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14}}`, false)
	c := costClient(srv.URL)
	if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if got := c.GetReportedCostUSD(); got != 0 {
		t.Fatalf("cost without a provider report = %v, want 0", got)
	}
	if clone := c.Clone(); clone.GetReportedCostUSD() != 0 {
		t.Fatal("a cloned client must start with its own cost counter")
	}
}
