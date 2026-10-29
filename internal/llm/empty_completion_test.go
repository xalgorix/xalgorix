package llm

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func newEmptyCompletionClient(t *testing.T, body string) *Client {
	t.Helper()
	c := NewClient(&config.Config{
		LLM:           "custom/vendor/some-model",
		APIBase:       "https://gateway.example/api/v1",
		APIKey:        "test-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, body), nil
	})}
	return c
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// TestDoChat_ChoiceErrorSurfacesAsError covers gateways that commit HTTP 200
// and then report the upstream failure inside the choice. Returning "" there
// made the agent count it as an empty response instead of showing the cause.
func TestDoChat_ChoiceErrorSurfacesAsError(t *testing.T) {
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"finish_reason":"error","message":{"role":"assistant","content":""},"error":{"code":502,"message":"upstream provider failed"}}]}`)

	_, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err == nil {
		t.Fatal("doChat returned nil error for a completion carrying a choice error")
	}
	if !strings.Contains(err.Error(), "upstream provider failed") || !strings.Contains(err.Error(), "finish_reason: error") {
		t.Fatalf("error %q does not carry the gateway message and finish_reason", err)
	}
}

func TestDoChat_ChoiceErrorAsString(t *testing.T) {
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"message":{"content":null},"error":"model overloaded"}]}`)

	_, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err == nil || !strings.Contains(err.Error(), "model overloaded") {
		t.Fatalf("doChat error = %v, want it to contain the string error", err)
	}
}

// TestDoChat_EmptyCompletionLogsDiagnostics checks that an empty completion
// with no error still returns "" (the agent's empty-response budget handles
// it) but logs finish_reason / reasoning presence for troubleshooting.
func TestDoChat_EmptyCompletionLogsDiagnostics(t *testing.T) {
	buf := captureLog(t)
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"finish_reason":"length","native_finish_reason":"max_tokens","message":{"role":"assistant","content":"","reasoning":[{"type":"text","text":"thinking"}]}}],"usage":{"prompt_tokens":10,"completion_tokens":8192,"total_tokens":8202}}`)

	got, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("doChat = %q, want empty", got)
	}
	logged := buf.String()
	for _, want := range []string{"Empty completion", `finish_reason="length"`, `native_finish_reason="max_tokens"`, "reasoning=true", "completion_tokens=8192"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q:\n%s", want, logged)
		}
	}
}

// A refusal sent as an object must not break decoding of the response.
func TestDoChat_RefusalObjectStillParses(t *testing.T) {
	buf := captureLog(t)
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":null,"refusal":{"reason":"policy"}}}]}`)

	got, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err != nil || got != "" {
		t.Fatalf("doChat = %q, %v; want \"\", nil", got, err)
	}
	if !strings.Contains(buf.String(), "refusal=true") {
		t.Fatalf("log missing refusal=true:\n%s", buf.String())
	}
}

func TestDoChat_NonEmptyCompletionDoesNotLogDiagnostics(t *testing.T) {
	buf := captureLog(t)
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello","reasoning_content":"thought"}}]}`)

	got, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err != nil || got != "hello" {
		t.Fatalf("doChat = %q, %v; want hello, nil", got, err)
	}
	if strings.Contains(buf.String(), "Empty completion") {
		t.Fatalf("unexpected empty-completion log for a non-empty reply:\n%s", buf.String())
	}
}

// Native tool calls legitimately arrive with empty content and must not be
// reported as empty completions.
func TestDoChat_ToolCallOnlyCompletionIsNotEmpty(t *testing.T) {
	buf := captureLog(t)
	c := newEmptyCompletionClient(t, `{"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"terminal","arguments":"{\"command\":\"id\"}"}}]}}]}`)

	var calls []ToolCall
	got, _, err := c.chatWithRetry([]Message{{Role: "user", Content: "hi"}}, nil, &calls)
	if err != nil || got != "" || len(calls) != 1 {
		t.Fatalf("chatWithRetry = %q, %d calls, %v; want \"\", 1 call, nil", got, len(calls), err)
	}
	if strings.Contains(buf.String(), "Empty completion") {
		t.Fatalf("tool-call-only reply logged as empty:\n%s", buf.String())
	}
}
