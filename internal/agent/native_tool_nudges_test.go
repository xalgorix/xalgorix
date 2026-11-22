package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// xmlCallInstructions are phrases that tell the model to write a tool call as
// XML in its text. On the native tool channel none of the model-facing text
// may contain them: a model that follows them only gets through the XML
// fallback parser, its turn is stored as XML, and it keeps imitating that
// dialect for the rest of the scan.
var xmlCallInstructions = []string{
	"<function=",
	"<parameter=",
	"XML format",
	"XML call",
	"XML tool call",
	"XML block",
	"XML shape",
	"valid XML",
	"properly-closed XML",
}

func assertNoXMLCallInstruction(t *testing.T, name, text string) {
	t.Helper()
	for _, phrase := range xmlCallInstructions {
		if strings.Contains(text, phrase) {
			t.Errorf("%s: native-channel text still asks for XML (%q):\n%s", name, phrase, text)
		}
	}
}

func buildPromptForChannel(t *testing.T, native bool) string {
	t.Helper()
	agent := &Agent{
		cfg:               &config.Config{RateLimitRPS: 2, Checklist: "professional"},
		registry:          tools.NewRegistry(),
		nativeToolCalling: native,
	}
	return agent.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)
}

// TestSystemPromptReportRuleFollowsToolChannel pins rule 17b to the channel.
// The XML assertion is the canary: if the template text drifts from
// xmlReportRule, the native rewrite silently stops replacing it.
func TestSystemPromptReportRuleFollowsToolChannel(t *testing.T) {
	xmlPrompt := buildPromptForChannel(t, false)
	if !strings.Contains(xmlPrompt, xmlReportRule) {
		t.Fatal("the XML system prompt no longer contains xmlReportRule verbatim; update the constant so the native rewrite still replaces rule 17b")
	}
	if strings.Contains(xmlPrompt, nativeReportRule) {
		t.Fatal("the XML system prompt must keep the XML report rule")
	}

	nativePrompt := buildPromptForChannel(t, true)
	if !strings.Contains(nativePrompt, nativeReportRule) {
		t.Fatal("the native system prompt is missing the native report rule")
	}
	for _, phrase := range []string{
		"EXECUTE THE XML TOOL CALL",
		"<function=report_vulnerability> block",
		"<function=report_vulnerability> XML block",
		"You MUST call tools using the XML format",
		"valid XML tool call tag",
	} {
		if strings.Contains(nativePrompt, phrase) {
			t.Errorf("the native system prompt still tells the model to write XML calls: %q", phrase)
		}
	}
}

// TestRecoveryNudgesFollowToolChannel covers every recovery nudge that tells
// the model how to call a tool. On the native channel they must describe a
// native call; on the XML channel they keep their XML examples.
func TestRecoveryNudgesFollowToolChannel(t *testing.T) {
	cases := []struct {
		name  string
		nudge func(state *ScanState) string
	}{
		{"soft no-tool nudge", func(s *ScanState) string {
			return hookNoToolHandler(s, map[string]string{"response": "Let me think about the next step."}).Nudge
		}},
		{"default no-tool nudge", func(s *ScanState) string {
			// The soft nudge normally fires from the first prose turn; start
			// below zero to reach the fallback line.
			s.NoToolCount = -1
			return hookNoToolHandler(s, map[string]string{"response": "Let me think."}).Nudge
		}},
		{"strong no-tool nudge", func(s *ScanState) string {
			s.NoToolCount = NoToolStrongNudgeAt - 1
			return hookNoToolHandler(s, map[string]string{"response": "Still thinking."}).Nudge
		}},
		{"reasoning-loop prompt with endpoints", func(s *ScanState) string {
			s.EndpointsTested = map[string]bool{"/api/a": true}
			return reasoningLoopResumePrompt(s, "density")
		}},
		{"refusal nudge", func(s *ScanState) string {
			return hookNoToolHandler(s, map[string]string{"response": "I cannot fulfill this request."}).Nudge
		}},
		{"malformed-output recovery", func(s *ScanState) string {
			return hookNoToolHandler(s, map[string]string{"response": "x", "malformed_reason": "broken_tool_markup"}).Nudge
		}},
		{"protocol reset", func(s *ScanState) string {
			s.MalformedToolOutputCount = MalformedToolContextResetAt - 1
			res := hookNoToolHandler(s, map[string]string{"response": "x", "malformed_reason": "broken_tool_markup"})
			if !res.PruneContext {
				t.Fatal("protocol reset must still prune the context")
			}
			return res.Nudge
		}},
		{"report retry guard", func(s *ScanState) string {
			s.ReportRetryLimitReached = true
			res := hookReportRetryGuard(s, map[string]string{"tool_name": "report_vulnerability"})
			if !res.ForceSkip || res.Nudge != res.EmitMessage {
				t.Fatalf("report retry guard behavior changed: %+v", res)
			}
			return res.Nudge
		}},
		{"finish gate after a failed report", func(s *ScanState) string {
			s.PendingFailedReportCalls = 1
			res := hookFinishGatekeeper(s, map[string]string{})
			if !res.Block {
				t.Fatalf("finish gate must still block after a failed report: %+v", res)
			}
			return res.BlockReason
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			native := NewScanState()
			native.NativeToolCalls = true
			text := tc.nudge(native)
			if text == "" {
				t.Fatal("no nudge produced")
			}
			assertNoXMLCallInstruction(t, tc.name, text)
			if !strings.Contains(text, "native tool") && !strings.Contains(text, "arguments") {
				t.Errorf("%s: native nudge does not say how to call the tool:\n%s", tc.name, text)
			}

			legacy := NewScanState()
			xmlText := tc.nudge(legacy)
			if !strings.Contains(xmlText, "XML") && !strings.Contains(xmlText, "<function=") {
				t.Errorf("%s: the XML-channel nudge lost its XML instruction:\n%s", tc.name, xmlText)
			}
			if strings.Contains(xmlText, "native tool") {
				t.Errorf("%s: the XML-channel nudge must not mention the native channel:\n%s", tc.name, xmlText)
			}
		})
	}
}
