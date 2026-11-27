package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestShouldSendCoreSystemPrompt exercises the pure per-iteration decision: the
// full prompt during the establishment window and on a re-injection turn, the
// compact core otherwise.
func TestShouldSendCoreSystemPrompt(t *testing.T) {
	const est = 12
	cases := []struct {
		name              string
		enabled, haveCore bool
		iter              int
		reinjectFull      bool
		want              bool
	}{
		{"disabled sends full", false, true, 50, false, false},
		{"no core built sends full", true, false, 50, false, false},
		{"inside establishment sends full", true, true, 5, false, false},
		{"one before boundary sends full", true, true, est - 1, false, false},
		{"at boundary sends core", true, true, est, false, true},
		{"after establishment sends core", true, true, 500, false, true},
		{"re-injection forces full", true, true, 500, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldSendCoreSystemPrompt(c.enabled, c.haveCore, c.iter, est, c.reinjectFull); got != c.want {
				t.Fatalf("shouldSendCoreSystemPrompt = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSendCoreConsumesReinjectOneShot verifies the re-inject flag is a one-shot:
// the trigger turn sends the full prompt, and the very next turn returns to the
// core.
func TestSendCoreConsumesReinjectOneShot(t *testing.T) {
	a := &Agent{systemPromptCoreOnly: true, coreSystemPrompt: "core", reinjectFullSystemPrompt: true}
	if a.sendCoreSystemPromptThisIter(500) {
		t.Fatal("expected the full prompt on the re-injection turn (sendCore=false)")
	}
	if a.reinjectFullSystemPrompt {
		t.Fatal("re-inject flag should have been consumed")
	}
	if !a.sendCoreSystemPromptThisIter(500) {
		t.Fatal("expected the core on the turn after re-injection (sendCore=true)")
	}
}

// TestSendCoreDisabledNeverRewrites guards the default: with the flag off, the
// decision is always false regardless of iteration or a stray re-inject flag.
func TestSendCoreDisabledNeverRewrites(t *testing.T) {
	a := &Agent{systemPromptCoreOnly: false, coreSystemPrompt: "core", reinjectFullSystemPrompt: true}
	if a.sendCoreSystemPromptThisIter(500) {
		t.Fatal("disabled agent must never send the core")
	}
}

// TestCoreSystemPromptKeepsLoadBearingSections is the safety net: the core must
// never drop the sections that prevent a refusal (authorization), keep the scan
// in scope, keep it read-only, or hold the proof bar — and it must still carry
// the targets, the tool schema and a pointer back to the full methodology.
func TestCoreSystemPromptKeepsLoadBearingSections(t *testing.T) {
	a := playbookTestAgent(t, &config.Config{SystemPromptCoreOnly: true})
	target := "https://app.example.test"
	core := a.buildCoreSystemPrompt([]string{target}, "", playbookTestPolicy)

	for _, must := range []string{
		"SANCTIONED, AUTHORIZED", // authorization framing (suppresses refusals)
		"Refusing or deflecting", // explicit anti-refusal instruction
		"TARGET SCOPE",           // hard scope rule
		"READ-ONLY",              // safety
		"drop tables",            // safety (never modify/delete prod data)
		"Proof is:",              // proof standard
		"read_skill",             // pointer to the deferred methodology
		target,                   // the authorized target
		"<tools>",                // the tool schema (XML registry here)
	} {
		if !strings.Contains(core, must) {
			t.Errorf("core system prompt is missing load-bearing section %q", must)
		}
	}
}

// TestCoreSystemPromptIsMateriallySmaller confirms the core actually saves the
// bulk of the per-call prompt versus the full methodology body.
func TestCoreSystemPromptIsMateriallySmaller(t *testing.T) {
	a := playbookTestAgent(t, &config.Config{SystemPromptCoreOnly: true})
	target := "https://app.example.test"
	core := a.buildCoreSystemPrompt([]string{target}, "", playbookTestPolicy)
	full := a.buildSystemPrompt([]string{target}, "", playbookTestPolicy)
	if len(core) >= len(full)/2 {
		t.Fatalf("core (%d bytes) is not materially smaller than full (%d bytes); expected < half", len(core), len(full))
	}
}

// TestCoreSystemPromptCarriesOperatorInstruction ensures a custom operator
// instruction survives into the core.
func TestCoreSystemPromptCarriesOperatorInstruction(t *testing.T) {
	a := playbookTestAgent(t, &config.Config{SystemPromptCoreOnly: true})
	core := a.buildCoreSystemPrompt([]string{"https://app.example.test"}, "Focus on the authentication flows.", playbookTestPolicy)
	if !strings.Contains(core, "OPERATOR INSTRUCTION") || !strings.Contains(core, "Focus on the authentication flows.") {
		t.Fatal("core system prompt dropped the operator instruction")
	}
}
