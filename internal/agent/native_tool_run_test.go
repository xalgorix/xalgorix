package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

type capturedChatRequest struct {
	Messages []struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCallID string          `json:"tool_call_id"`
	} `json:"messages"`
	Tools []json.RawMessage `json:"tools"`
}

func (r capturedChatRequest) lastMessage() (role, content string) {
	if len(r.Messages) == 0 {
		return "", ""
	}
	m := r.Messages[len(r.Messages)-1]
	var s string
	if err := json.Unmarshal(m.Content, &s); err != nil {
		s = string(m.Content)
	}
	return m.Role, s
}

// TestRunNativeChannelSendsNativeRecoveryText runs the agent loop against an
// chat-completions stub with native tool calls on. The stub answers the first
// turn with prose only, then with a call that leaves out a required argument.
// What the model gets back must be worded for the native channel: this is what
// fails if Run stops recording the resolved channel in the scan state, or the
// missing-parameter error stops being switched to its native wording.
func TestRunNativeChannelSendsNativeRecoveryText(t *testing.T) {
	nudgeSeen := make(chan capturedChatRequest, 1)
	toolResultSeen := make(chan capturedChatRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var req capturedChatRequest
		_ = json.Unmarshal(body, &req)
		role, content := req.lastMessage()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case role == "tool":
			select {
			case toolResultSeen <- req:
			default:
			}
			<-r.Context().Done()
		case role == "user" && strings.Contains(content, "You MUST use tools to interact with the target"):
			select {
			case nudgeSeen <- req:
			default:
			}
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"add_note","arguments":"{\"key\":\"probe\"}"}}
			]}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`)
		default:
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Let me look at the target before choosing a test."}}],"usage":{"prompt_tokens":10,"completion_tokens":8,"total_tokens":18}}`)
		}
	}))
	t.Cleanup(srv.Close)

	sctx := scanctx.New("native-channel-run", t.TempDir())
	t.Cleanup(sctx.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := &config.Config{LLM: "test-model", APIBase: srv.URL, APIKey: "test-key", NativeToolCalls: true}
	events := make(chan Event, 1024)
	a := NewAgent(cfg, "native-channel-test", events, scopeguard.Config{BindAddr: "127.0.0.1"}, sctx, withParentContext(ctx))
	a.discoveryMode = true
	done := make(chan struct{})
	go func() {
		a.Run([]string{"https://example.invalid"}, "authorized assessment")
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

	select {
	case req := <-nudgeSeen:
		if len(req.Tools) == 0 {
			t.Fatal("the request carried no native tool definitions; the native channel was not selected")
		}
		_, nudge := req.lastMessage()
		assertNoXMLCallInstruction(t, "no-tool nudge sent by Run", nudge)
		if !strings.Contains(nudge, "native tool interface") {
			t.Errorf("Run sent the XML-channel nudge on the native channel:\n%s", nudge)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the agent never sent a no-tool nudge")
	}

	select {
	case req := <-toolResultSeen:
		_, result := req.lastMessage()
		if !strings.Contains(result, "missing required parameter") {
			t.Fatalf("expected the missing-parameter error as the tool result, got:\n%s", result)
		}
		assertNoXMLCallInstruction(t, "missing-parameter tool result", result)
	case <-time.After(90 * time.Second):
		t.Fatal("the agent never returned the tool result")
	}
}
