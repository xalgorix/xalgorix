package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

func TestSystemPromptIncludesCollectableMultiAgentWorkflow(t *testing.T) {
	registry := tools.NewRegistry()
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	graph.Register(registry)

	agent := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2},
		registry: registry,
	}
	prompt := agent.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)

	for _, expected := range []string{
		"## Multi-Agent Coordinator",
		"ONE wave",
		"3 delegated agents total for the entire scan",
		"NON-OVERLAPPING specialists",
		"Authorization & business logic",
		"call wait_agent/check_agent for EVERY delegation",
		`<tool name="spawn_agent">`,
		`<tool name="wait_agent">`,
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("prompt missing %q", expected)
		}
	}
	if strings.Contains(prompt, "%!") {
		t.Fatalf("prompt contains fmt diagnostic, likely a placeholder/argument mismatch")
	}
}

func TestBuildDelegatedTaskInstructionEnforcesProfessionalLaneExhaustion(t *testing.T) {
	got := buildDelegatedTaskInstruction(
		"Test the assigned injection hypotheses.",
		"sub-injection",
		false,
	)
	for _, want := range []string{
		"Test the assigned injection hypotheses.",
		"owner sub-injection",
		"Do not spawn or delegate additional agents",
		"Do not stop after the first finding",
		"claim_next_hypothesis",
		"report every distinct proven vulnerability",
		"read_ledger again",
		"full assigned lane is exhausted",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("delegated contract missing %q\n---\n%s", want, got)
		}
	}
}

func TestBuildDelegatedTaskInstructionPreservesExplicitCTFMission(t *testing.T) {
	const task = "Solve this CTF and retrieve FLAG{...}."
	if got := buildDelegatedTaskInstruction(task, "sub-ctf", true); got != task {
		t.Fatalf("explicit CTF task should remain unchanged, got:\n%s", got)
	}
	if !isExplicitCTFMission(task) {
		t.Fatal("expected explicit flag objective to classify as CTF")
	}
	if isExplicitCTFMission("Perform a professional assessment; this is not a CTF.") {
		t.Fatal("a professional not-a-CTF instruction must not enable single-flag stopping")
	}
}

func TestDelegatedSystemPromptRemovesRootWorkflowContradictions(t *testing.T) {
	agent := &Agent{
		cfg:              &config.Config{RateLimitRPS: 2},
		registry:         tools.NewRegistry(),
		delegatedAgentID: "sub-injection",
	}
	prompt := agent.buildSystemPrompt(
		[]string{"https://example.test"},
		buildDelegatedTaskInstruction("Test assigned SQL injection hypotheses.", "sub-injection", false),
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	for _, forbidden := range []string{
		"Minimum 50 iterations",
		"act as a coordinator and use spawn_agent",
		"### PHASE 22: Final Report",
		"fully exploiting ONE real weakness wins the bounty",
	} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("delegated prompt retained contradictory root instruction %q", forbidden)
		}
	}
	for _, want := range []string{
		"## Delegated Specialist — bounded lane",
		"Do not call spawn_agent",
		"no fixed iteration minimum",
		"The stopping condition is lane exhaustion",
		"Test assigned SQL injection hypotheses.",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("delegated prompt missing %q", want)
		}
	}
}

func TestProfessionalPromptRequiresDepthAndCompleteCoverage(t *testing.T) {
	agent := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2},
		registry: tools.NewRegistry(),
	}
	prompt := agent.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full professional assessment; this is not a CTF.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	for _, want := range []string{
		"uncovered attack surface is a miss",
		"endpoint × vulnerability-class ledger",
		"continue after every finding",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("professional prompt missing %q", want)
		}
	}
	if strings.Contains(prompt, "fully exploiting ONE real weakness wins the bounty") {
		t.Fatal("professional prompt retained the single-finding objective")
	}
}

func TestProfessionalPromptKeepsLocalScratchInsideWorkspaceTmp(t *testing.T) {
	agent := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2},
		registry: tools.NewRegistry(),
	}
	prompt := agent.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full professional assessment; this is not a CTF.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	for _, want := range []string{
		"put local scratch files under relative",
		"mkdir -p tmp",
		"NEVER store scanner artifacts",
		"tmp/main_page.html",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("professional prompt missing workspace-local scratch rule %q", want)
		}
	}
	for _, forbidden := range []string{
		"-o /tmp/main_page.html",
		"-o /tmp/bundle.js",
		"-o /tmp/baseline.txt",
		"-o /tmp/special.txt",
		"> /tmp/js_chunks.txt",
	} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("professional prompt still writes local scratch outside the workspace: %q", forbidden)
		}
	}
}

func TestBenchmarkPromptForbidsHostAssistedEvidence(t *testing.T) {
	agent := &Agent{
		cfg:               &config.Config{RateLimitRPS: 2},
		registry:          tools.NewRegistry(),
		benchmarkIsolated: true,
	}
	prompt := agent.buildSystemPrompt(
		[]string{"http://127.0.0.1:3300"},
		"Perform a full professional assessment; this is not a CTF.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
	for _, want := range []string{
		"BENCHMARK ISOLATION — NETWORK EVIDENCE ONLY",
		"Never inspect or enter the host/container runtime",
		"Host-assisted evidence invalidates the score",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("benchmark prompt missing isolation rule %q", want)
		}
	}
}

// TestWhiteboxGuidanceText verifies the live-target whitebox modes teach the
// source-to-runtime bridge (work the auto-seeded ledger first, then confirm
// deterministically), while the source-review mode — which has no live target —
// does not push live-only tools.
func TestWhiteboxGuidanceText(t *testing.T) {
	const root = "/tmp/src"

	bridge := []string{"claim_next_hypothesis", "probe_hypothesis", "verify_sqli", "verify_ssti", "verify_xss", "verify_oob", "seeded"}
	for _, mode := range []CodeScanMode{CodeScanNone, CodeScanProvision} {
		g := whiteboxGuidanceText(mode, root, "127.0.0.1:8080")
		if !strings.Contains(g, root) {
			t.Errorf("mode %d: guidance should mention the source root %q", mode, root)
		}
		for _, want := range bridge {
			if !strings.Contains(g, want) {
				t.Errorf("mode %d: guidance must mention %q", mode, want)
			}
		}
	}

	// Provision mode must embed the loopback bind host:port for build-and-run.
	if prov := whiteboxGuidanceText(CodeScanProvision, root, "127.0.0.1:8080"); !strings.Contains(prov, "127.0.0.1:8080") {
		t.Errorf("provision guidance must embed the bind host:port")
	}

	// Source-review mode has NO live target: it must NOT push live-only tools,
	// but should retain the static code_search methodology.
	rev := whiteboxGuidanceText(CodeScanReview, root, "")
	for _, unwanted := range []string{"probe_hypothesis", "verify_sqli", "verify_ssti", "verify_xss", "verify_oob"} {
		if strings.Contains(rev, unwanted) {
			t.Errorf("source-review guidance must NOT mention live-only tool %q", unwanted)
		}
	}
	if !strings.Contains(rev, "code_search") {
		t.Errorf("source-review guidance should retain the code_search methodology")
	}
}
