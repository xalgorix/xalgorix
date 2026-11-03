package tui

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestHumanizeTokens(t *testing.T) {
	cases := map[int]string{
		0:         "0",
		640:       "640",
		5000:      "5k",
		812_000:   "812k",
		2_000_000: "2.00M",
		2_340_000: "2.34M",
	}
	for in, want := range cases {
		if got := humanizeTokens(in); got != want {
			t.Errorf("humanizeTokens(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLocalProvider(t *testing.T) {
	local := []*config.Config{
		{LLMProvider: "ollama"},
		{OllamaCompatible: true},
		{APIBase: "http://localhost:11434"},
		{APIBase: "http://127.0.0.1:11434/v1"},
		{LLM: "ollama/llama3.3"},
	}
	for _, c := range local {
		if !isLocalProvider(c) {
			t.Errorf("isLocalProvider(%+v) = false, want true", c)
		}
	}
	remote := []*config.Config{
		{LLMProvider: "openai", LLM: "openai/gpt-5.4"},
		{LLMProvider: "minimax", APIBase: "https://api.minimax.io/v1"},
		nil,
	}
	for _, c := range remote {
		if isLocalProvider(c) {
			t.Errorf("isLocalProvider(%+v) = true, want false", c)
		}
	}
}

func TestFormatCostNote(t *testing.T) {
	// No tokens → stays silent.
	if got := FormatCostNote(&config.Config{}, 0, 0); got != "" {
		t.Errorf("FormatCostNote(_, 0) = %q, want empty", got)
	}

	// Remote provider: names the provider bill, the hosted nudge, and the URL.
	remote := FormatCostNote(&config.Config{LLMProvider: "openai"}, 2_000_000, 0)
	for _, want := range []string{
		"2.00M tokens",
		"billed to your own LLM provider",
		"1 credit per",
		"xalgorix.com/hosted-vs-self-hosted",
	} {
		if !strings.Contains(remote, want) {
			t.Errorf("remote cost note missing %q:\n%s", want, remote)
		}
	}

	// A provider-reported charge is printed as the scan's cost.
	charged := FormatCostNote(&config.Config{LLMProvider: "openrouter"}, 2_000_000, 1.23456)
	if !strings.Contains(charged, "reported a charge of $1.2346") {
		t.Errorf("cost note missing the reported charge:\n%s", charged)
	}

	// Local provider: must NOT claim a provider bill.
	local := FormatCostNote(&config.Config{LLMProvider: "ollama"}, 500_000, 0)
	if strings.Contains(local, "billed to your own LLM provider") {
		t.Errorf("local cost note wrongly claims a provider bill:\n%s", local)
	}
	if !strings.Contains(local, "local model") {
		t.Errorf("local cost note should mention the local model:\n%s", local)
	}
}

func TestOnlyTheRootAgentsFinishEndsTheCLIRun(t *testing.T) {
	const root = "agent_1"
	if rootFinished(agent.Event{Type: "finished", AgentID: "agent_2"}, root) {
		t.Error("a subagent's finished event must not end the run")
	}
	if !rootFinished(agent.Event{Type: "finished", AgentID: root}, root) {
		t.Error("the root agent's finished event must end the run")
	}
	if !rootFinished(agent.Event{Type: "finished"}, root) {
		t.Error("an unattributed finished event must still end the run")
	}
	if rootFinished(agent.Event{Type: "message", AgentID: root}, root) {
		t.Error("only finished events end the run")
	}
}
