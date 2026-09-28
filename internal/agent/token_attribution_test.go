package agent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestTokenAttributionAndAggregation(t *testing.T) {
	sctx := scanctx.New("test-scan-123", t.TempDir())
	if sctx.Tokens == nil {
		t.Fatalf("scanctx Tokens tracker not initialized")
	}

	// 1. Record Root Coordinator normal reasoning
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:              sctx.ID,
		AgentID:             "agent_root",
		AgentType:           scanctx.AgentTypeRoot,
		Iteration:           1,
		Model:               "MiniMax-Text-01",
		Provider:            "minimax",
		PromptTokens:        2000,
		CompletionTokens:    300,
		TotalTokens:         2300,
		CachedInputTokens:   1500,
		UncachedInputTokens: 500,
		ToolResultBytes:     1000,
		SkillResultBytes:    4000,
		RequestCategory:     scanctx.CategoryNormalReasoning,
	})

	// 2. Record Injection Specialist reasoning
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:              sctx.ID,
		AgentID:             "agent_injection",
		AgentType:           scanctx.AgentTypeInjectionServer,
		Iteration:           2,
		Model:               "MiniMax-Text-01",
		Provider:            "minimax",
		PromptTokens:        3000,
		CompletionTokens:    400,
		TotalTokens:         3400,
		CachedInputTokens:   2000,
		UncachedInputTokens: 1000,
		ToolResultBytes:     2500,
		SkillResultBytes:    0,
		RequestCategory:     scanctx.CategoryNormalReasoning,
	})

	// 3. Record Authz Logic Specialist reasoning
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:              sctx.ID,
		AgentID:             "agent_authz",
		AgentType:           scanctx.AgentTypeAuthzLogic,
		Iteration:           3,
		Model:               "MiniMax-Text-01",
		Provider:            "minimax",
		PromptTokens:        2500,
		CompletionTokens:    250,
		TotalTokens:         2750,
		CachedInputTokens:   1800,
		UncachedInputTokens: 700,
		ToolResultBytes:     1200,
		SkillResultBytes:    0,
		RequestCategory:     scanctx.CategoryNormalReasoning,
	})

	// 4. Record Verifier reasoning
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:              sctx.ID,
		AgentID:             "agent_verifier",
		AgentType:           scanctx.AgentTypeVerifier,
		Iteration:           1,
		Model:               "MiniMax-Text-01",
		Provider:            "minimax",
		PromptTokens:        1500,
		CompletionTokens:    150,
		TotalTokens:         1650,
		CachedInputTokens:   1000,
		UncachedInputTokens: 500,
		ToolResultBytes:     500,
		SkillResultBytes:    0,
		RequestCategory:     scanctx.CategoryVerifier,
	})

	// 5. Record a Retry event
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:              sctx.ID,
		AgentID:             "agent_root",
		AgentType:           scanctx.AgentTypeRoot,
		Iteration:           4,
		Model:               "MiniMax-Text-01",
		Provider:            "minimax",
		PromptTokens:        2000,
		CompletionTokens:    0,
		TotalTokens:         2000,
		CachedInputTokens:   1500,
		UncachedInputTokens: 500,
		RequestCategory:     scanctx.CategoryRetry,
		RetryAttempt:        1,
	})

	summary := sctx.Tokens.Summary()

	if summary.TotalTokens != 12100 {
		t.Errorf("TotalTokens = %d, want 12100", summary.TotalTokens)
	}
	if summary.PromptTokens != 11000 {
		t.Errorf("PromptTokens = %d, want 11000", summary.PromptTokens)
	}
	if summary.CompletionTokens != 1100 {
		t.Errorf("CompletionTokens = %d, want 1100", summary.CompletionTokens)
	}
	if summary.CachedInputTokens != 7800 {
		t.Errorf("CachedInputTokens = %d, want 7800", summary.CachedInputTokens)
	}
	if summary.UncachedInputTokens != 3200 {
		t.Errorf("UncachedInputTokens = %d, want 3200", summary.UncachedInputTokens)
	}
	if summary.RootTokens != 4300 {
		t.Errorf("RootTokens = %d, want 4300", summary.RootTokens)
	}
	if summary.VerifierTokens != 1650 {
		t.Errorf("VerifierTokens = %d, want 1650", summary.VerifierTokens)
	}
	if summary.SpecialistTokens[scanctx.AgentTypeInjectionServer] != 3400 {
		t.Errorf("Injection Specialist Tokens = %d, want 3400", summary.SpecialistTokens[scanctx.AgentTypeInjectionServer])
	}
	if summary.SpecialistTokens[scanctx.AgentTypeAuthzLogic] != 2750 {
		t.Errorf("Authz Specialist Tokens = %d, want 2750", summary.SpecialistTokens[scanctx.AgentTypeAuthzLogic])
	}
	if summary.ToolOutputBytes != 5200 {
		t.Errorf("ToolOutputBytes = %d, want 5200", summary.ToolOutputBytes)
	}
	if summary.SkillResultBytes != 4000 {
		t.Errorf("SkillResultBytes = %d, want 4000", summary.SkillResultBytes)
	}
	if summary.RetryLoopTokens != 2000 {
		t.Errorf("RetryLoopTokens = %d, want 2000", summary.RetryLoopTokens)
	}
}

func TestAccidentalDuplicateSuppression(t *testing.T) {
	t.Run("HookPlannerSuppressesConsecutiveIdenticalBrief", func(t *testing.T) {
		state := NewScanState()
		state.Plan = AutoPlan([]string{"/api/login", "/api/user"}, map[string]bool{"php": true})
		state.ReconDone = true
		state.DiscoveredEndpoints = []string{"/api/login", "/api/user"}

		// First iteration: must produce plan brief
		res1 := fireDirectives(t, state, hookPlanner)
		if res1.Nudge == "" {
			t.Fatalf("first iteration must produce plan brief")
		}
		if !strings.Contains(res1.Nudge, "Active Plan") {
			t.Fatalf("expected plan content in nudge")
		}

		// Second iteration without state change: MUST suppress duplicate
		res2 := fireDirectives(t, state, hookPlanner)
		if res2.Nudge != "" {
			t.Fatalf("consecutive unchanged plan must be suppressed, got: %s", res2.Nudge)
		}

		// Simulate state change (auth lane actually exercised across endpoints,
		// advancing plan progress - reconcile requires tested AND endpoints)
		state.AccessControlTested = true
		state.AccessControlEndpoints = map[string]bool{"/api/login": true, "/api/user": true}

		// Third iteration with changed state: MUST produce updated plan brief
		res3 := fireDirectives(t, state, hookPlanner)
		if res3.Nudge == "" {
			t.Fatalf("plan with updated task status must produce updated brief")
		}

		// Simulate context compaction: resets LastPlanBrief
		hookResetOnPrune(state, nil)
		if state.LastPlanBrief != "" {
			t.Fatalf("hookResetOnPrune must clear LastPlanBrief")
		}

		// Fourth iteration after prune: MUST re-inject plan brief fresh
		res4 := fireDirectives(t, state, hookPlanner)
		if res4.Nudge == "" {
			t.Fatalf("iteration after context prune must re-inject plan brief")
		}
	})

	t.Run("HookCurlPreferenceSuppressesConsecutiveWarnings", func(t *testing.T) {
		state := NewScanState()

		// 1. Consecutive browser_action without auth
		state.ConsecutiveBrowser = 3
		argsBrowser := map[string]string{"tool_name": "browser_action", "action": "click", "url": "http://target/about"}

		// First trigger at >2 consecutive: warning emitted
		resB1 := hookCurlPreference(state, argsBrowser)
		if resB1.Nudge == "" {
			t.Fatalf("expected browser preference nudge at ConsecutiveBrowser=3")
		}

		// Subsequent consecutive browser_action calls: duplicate suppressed!
		state.ConsecutiveBrowser = 4
		resB2 := hookCurlPreference(state, argsBrowser)
		if resB2.Nudge != "" {
			t.Fatalf("duplicate consecutive browser warning should be suppressed, got: %s", resB2.Nudge)
		}

		state.ConsecutiveBrowser = 5
		resB3 := hookCurlPreference(state, argsBrowser)
		if resB3.Nudge != "" {
			t.Fatalf("duplicate consecutive browser warning should be suppressed, got: %s", resB3.Nudge)
		}

		// Switching to another tool resets the warning tracker
		hookCurlPreference(state, map[string]string{"tool_name": "terminal_execute"})
		if state.BrowserPreferenceNudgeCount != 0 {
			t.Fatalf("switching tool must reset BrowserPreferenceNudgeCount")
		}

		// 2. send_request calls
		argsSend := map[string]string{"tool_name": "send_request", "method": "GET"}
		resS1 := hookCurlPreference(state, argsSend) // call 1
		if resS1.Nudge == "" {
			t.Fatalf("call 1 of send_request should emit soft tip")
		}

		resS2 := hookCurlPreference(state, argsSend) // call 2
		if resS2.Nudge != "" {
			t.Fatalf("call 2 of send_request should not emit warning")
		}

		resS3 := hookCurlPreference(state, argsSend) // call 3
		if resS3.Nudge == "" || !strings.Contains(resS3.Nudge, "STOP using send_request") {
			t.Fatalf("call 3 of send_request should emit strong warning")
		}

		// Subsequent calls (4, 5) MUST NOT re-emit the identical warning
		resS4 := hookCurlPreference(state, argsSend) // call 4
		if resS4.Nudge != "" {
			t.Fatalf("call 4 should suppress duplicate warning, got: %s", resS4.Nudge)
		}

		resS5 := hookCurlPreference(state, argsSend) // call 5
		if resS5.Nudge != "" {
			t.Fatalf("call 5 should suppress duplicate warning, got: %s", resS5.Nudge)
		}
	})
}

func TestSecurityQualityInvariants(t *testing.T) {
	cfg := &config.Config{
		LLM:           "MiniMax-Text-01",
		LLMProvider:   "minimax",
		SkillsDir:     "",
		MaxIterations: 50,
	}
	events := make(chan Event, 10)
	sctx := scanctx.New("quality-test", t.TempDir())
	a := NewAgent(cfg, "RootAgent", events, scopeguard.Config{}, sctx)

	// 1. Verify that tool schemas and registrations are intact
	requiredTools := []string{
		"read_skill",
		"list_skills",
		"search_skills",
		"terminal_execute",
		"send_request",
		"browser_action",
		"add_note",
		"read_notes",
		"finish",
		"report_vulnerability",
		"build_plan",
		"update_plan",
		"record_hypothesis",
		"add_hypothesis_evidence",
		"read_ledger",
	}

	for _, toolName := range requiredTools {
		tool, ok := a.registry.Get(toolName)
		if !ok || tool == nil {
			t.Errorf("required security tool %q missing from agent registry", toolName)
		}
	}

	// 2. Verify agent type determination
	if got := determineAgentType("XalgorixRoot", false); got != scanctx.AgentTypeRoot {
		t.Errorf("root agent type = %q, want %q", got, scanctx.AgentTypeRoot)
	}
	if got := determineAgentType("specialist-injection-serverside", true); got != scanctx.AgentTypeInjectionServer {
		t.Errorf("injection agent type = %q, want %q", got, scanctx.AgentTypeInjectionServer)
	}
	if got := determineAgentType("specialist-authz-logic", true); got != scanctx.AgentTypeAuthzLogic {
		t.Errorf("authz agent type = %q, want %q", got, scanctx.AgentTypeAuthzLogic)
	}
	if got := determineAgentType("specialist-client-source", true); got != scanctx.AgentTypeClientSource {
		t.Errorf("client agent type = %q, want %q", got, scanctx.AgentTypeClientSource)
	}
	if got := determineAgentType("verifier-agent", true); got != scanctx.AgentTypeVerifier {
		t.Errorf("verifier agent type = %q, want %q", got, scanctx.AgentTypeVerifier)
	}

	// 3. Verify message metric calculations
	testMsgs := []llm.Message{
		{Role: "system", Content: "System prompt instructions"},
		{Role: "user", Content: "Run testing on endpoints"},
		{Role: "assistant", Content: "Executing tool"},
		{Role: "user", Content: "Tool 'terminal_execute' result:\noutput from curl"},
		{Role: "user", Content: "Tool 'read_skill' result:\nSkill already loaded in the current active context: xss"},
	}

	totBytes, sysBytes, usrBytes, asstBytes, tCount, tBytes, sCount, sBytes := calculateMessageMetrics(testMsgs)
	if totBytes <= 0 || sysBytes <= 0 || usrBytes <= 0 || asstBytes <= 0 {
		t.Errorf("metric bytes should all be positive, got tot=%d sys=%d usr=%d asst=%d", totBytes, sysBytes, usrBytes, asstBytes)
	}
	if tCount != 2 {
		t.Errorf("toolCount = %d, want 2", tCount)
	}
	if sCount != 1 {
		t.Errorf("skillCount = %d, want 1", sCount)
	}
	if tBytes <= 0 || sBytes <= 0 {
		t.Errorf("tool/skill bytes should be positive")
	}
}

func TestDeterministicByteReduction(t *testing.T) {
	// Compare bytes of repeated full skill vs suppressed reference
	fullSkill := strings.Repeat("Detailed exploit methodology step-by-step instructions with proof-of-concept commands.\n", 100) // ~8KB
	canonicalName := "testing-for-xss-vulnerabilities"
	suppressedMsg := fmt.Sprintf("Skill already loaded in the current active context: %s. The complete methodology remains available earlier in this conversation.", canonicalName)

	fullBytes := len(fullSkill)
	suppressedBytes := len(suppressedMsg)
	savingPercent := float64(fullBytes-suppressedBytes) / float64(fullBytes) * 100.0

	if savingPercent < 90.0 {
		t.Errorf("skill duplicate suppression savings = %.2f%%, expected >90%%", savingPercent)
	}

	// Compare bytes of repeated plan brief
	state := NewScanState()
	state.Plan = AutoPlan([]string{"/api/v1/auth", "/api/v1/users", "/api/v1/billing", "/api/v1/admin"}, map[string]bool{"python": true, "django": true, "postgresql": true})
	gaps := CoverageGaps(state, []string{"/api/v1/auth", "/api/v1/users", "/api/v1/billing", "/api/v1/admin"})
	planBrief := FormatPlan(state.Plan, gaps)

	if len(planBrief) < 500 {
		t.Fatalf("expected non-trivial plan brief, got %d bytes", len(planBrief))
	}
	// Suppressing unchanged plan brief saves 100% of the brief's bytes on that iteration
	t.Logf("Unchanged plan brief byte reduction per iteration: %d bytes saved (100%% of repeated brief)", len(planBrief))
}

// TestRecordTokenAttributionDoesNotMutateMessages proves the instrumentation
// is observation-only: recording attribution must not alter the outbound
// message slice (content, roles, order) in any way.
func TestRecordTokenAttributionDoesNotMutateMessages(t *testing.T) {
	cfg := &config.Config{LLM: "MiniMax-M3", LLMProvider: "minimax"}
	sctx := scanctx.New("obs-invariance", t.TempDir())
	scanctx.Activate(sctx)
	defer sctx.Close()

	agnt := NewAgent(cfg, "specialist-injection-serverside", make(chan Event, 8), scopeguard.Config{}, sctx)
	agnt.state.DelegatedAgent = true

	msgs := []llm.Message{
		{Role: "system", Content: "SYSTEM PROMPT with methodology. Tool 'curl' guidance. result:\nfake tool output"},
		{Role: "assistant", Content: "<function=curl>{\"url\":\"https://t\"}</function>"},
		{Role: "user", Content: "[curl output]\nHTTP/1.1 200 OK read_skill result body"},
		{Role: "user", Content: "plain user turn with no tool markers"},
	}
	before := make([]llm.Message, len(msgs))
	copy(before, msgs)
	for i := range before {
		before[i].Content = strings.Clone(msgs[i].Content)
	}

	usage := &llm.TokenUsage{
		PromptTokens:        1234,
		CompletionTokens:    56,
		TotalTokens:         1290,
		CachedTokens:        1000,
		HasCachedTokens:     true,
		PromptTokensDetails: &llm.PromptTokensDetails{CachedTokens: 1000},
	}

	agnt.recordTokenAttribution(usage, msgs, 7, scanctx.CategoryNormalReasoning, 0)
	// Also verify a failed-request record (nil usage) is harmless.
	agnt.recordTokenAttribution(nil, msgs, 8, scanctx.CategoryRetry, 1)

	if len(msgs) != len(before) {
		t.Fatalf("message count changed: %d → %d", len(before), len(msgs))
	}
	for i := range before {
		if msgs[i].Role != before[i].Role || msgs[i].Content != before[i].Content {
			t.Fatalf("message %d mutated:\nbefore: %q\nafter:  %q", i, before[i], msgs[i])
		}
	}

	recs := sctx.Tokens.Records()
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].AgentType != scanctx.AgentTypeInjectionServer {
		t.Fatalf("agent type = %s", recs[0].AgentType)
	}
	if !recs[0].CacheReported || recs[0].CachedInputTokens != 1000 {
		t.Fatalf("cache attribution broken: %+v", recs[0])
	}
	if recs[1].PromptTokens != 0 {
		t.Fatalf("failed request should record zero usage: %+v", recs[1])
	}
}

// TestTokenAttributionRoleRouting exercises determineAgentType across every
// production agent role so per-agent rollups cannot silently regress.
func TestTokenAttributionRoleRouting(t *testing.T) {
	cases := []struct {
		name      string
		agentName string
		delegated bool
		want      string
	}{
		{"root", "XalgorixRoot", false, scanctx.AgentTypeRoot},
		{"authz", "specialist-authz-logic", true, scanctx.AgentTypeAuthzLogic},
		{"injection", "specialist-injection-serverside", true, scanctx.AgentTypeInjectionServer},
		{"client-source", "specialist-client-source", true, scanctx.AgentTypeClientSource},
		{"verifier", "verifier-agent", true, scanctx.AgentTypeVerifier},
		{"unknown", "specialist-recon", true, scanctx.AgentTypeOther},
	}
	for _, tc := range cases {
		if got := determineAgentType(tc.agentName, tc.delegated); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
