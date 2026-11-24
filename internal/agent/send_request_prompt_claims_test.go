package agent

import (
	"fmt"
	"strings"
	"testing"
)

// send_request is not routed through Caido (pinned by
// TestSendRequestDoesNotRouteThroughCaido in internal/tools/proxy), and
// list_requests only reads Caido's own captures. The prompts and nudges must
// not tell the model otherwise (#917), or it calls list_requests to review
// requests that were never captured there.
var caidoRoutingClaims = []string{
	"routed through the caido",
	"caido proxy log",
	"logged in the caido",
	"list_requests shows it",
	"list_requests to see all captured",
}

func assertNoCaidoRoutingClaims(t *testing.T, where, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, claim := range caidoRoutingClaims {
		if strings.Contains(lower, claim) {
			t.Errorf("%s still says send_request traffic goes through Caido (%q)", where, claim)
		}
	}
}

func TestSendRequestPromptDoesNotClaimCaidoRouting(t *testing.T) {
	for name, checklist := range map[string]string{
		"full":         defaultChecklist,
		"compact":      compactChecklist,
		"professional": professionalChecklist,
	} {
		assertNoCaidoRoutingClaims(t, name+" checklist", checklist)
	}

	for _, mode := range []string{"", "compact", "professional"} {
		a := scopeClaimsAgent(t, []string{"https://app.acme.com"}, false)
		a.cfg.Checklist = mode
		prompt := scopeClaimsPrompt(a)
		where := fmt.Sprintf("system prompt (checklist %q)", mode)
		assertNoCaidoRoutingClaims(t, where, prompt)
		// Wherever the prompt talks about Caido it must say send_request is
		// not routed through it.
		if strings.Contains(strings.ToLower(prompt), "caido") && !strings.Contains(prompt, "NOT routed through Caido") {
			t.Errorf("%s mentions Caido without saying send_request is NOT routed through it", where)
		}
	}
	for _, checklist := range []string{defaultChecklist, compactChecklist} {
		if !strings.Contains(checklist, "NOT routed through Caido") {
			t.Errorf("checklist describing send_request lost the routing statement")
		}
	}

	state := NewScanState()
	for call := 1; call <= 3; call++ {
		res := hookCurlPreference(state, map[string]string{"tool_name": "send_request", "method": "GET"})
		if call != 2 && res.Nudge == "" {
			t.Fatalf("send_request call %d: expected a curl-preference nudge", call)
		}
		if strings.Contains(strings.ToLower(res.Nudge), "caido") {
			t.Errorf("send_request nudge %d mentions Caido: %s", call, res.Nudge)
		}
	}
}
