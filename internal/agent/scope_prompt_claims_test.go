package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// thirdPartyCalls are tool calls aimed at hosts outside a scan of
// *.acme.com: a backend referenced in the target's frontend, a partner
// dashboard, and an IP literal found during recon.
var thirdPartyCalls = []struct {
	tool string
	args map[string]string
}{
	{"http_request", map[string]string{"url": "https://db.thirdpartydb.io/rest/v1/users", "method": "POST"}},
	{"terminal_execute", map[string]string{"command": "curl -s -X POST https://grafana.partnerco.net/api/admin/users"}},
	{"terminal_execute", map[string]string{"command": "curl -s http://203.0.113.7/admin"}},
	{"report_vulnerability", map[string]string{"endpoint": "https://db.thirdpartydb.io/rest/v1/users"}},
}

func scopeClaimsAgent(t *testing.T, targets []string, singleHost bool) *Agent {
	t.Helper()
	withScopeguardLookupHost(t, func(string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	})
	return &Agent{
		cfg:             &config.Config{RateLimitRPS: 2, Checklist: "professional"},
		registry:        tools.NewRegistry(),
		localGuard:      scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137},
		targets:         targets,
		singleHostScope: singleHost,
	}
}

func scopeClaimsPrompt(a *Agent) string {
	return a.buildSystemPrompt(a.targets, "Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"})
}

// In a wildcard or multi-target scan the runtime does not refuse third-party
// hosts: only the operator's machine/listener, pinned ports and (single-host
// scans) other organizations are gated. The prompts must say so instead of
// telling the model every out-of-scope host is rejected for it (#911). If a
// general host allow-list is added later, this test fails: update the prompt
// text it guards at the same time.
func TestScopePromptMatchesRuntime_WideScanDoesNotGateThirdPartyHosts(t *testing.T) {
	for _, targets := range [][]string{
		{"*.acme.com"},
		{"https://app.acme.com", "https://api.acme.com"},
	} {
		a := scopeClaimsAgent(t, targets, false)
		for _, c := range thirdPartyCalls {
			if blocked, reason := a.shouldBlockForOutOfScope(c.tool, c.args); blocked {
				t.Fatalf("targets %v: %s %v refused by the local guard (%s); update the scope prompt text", targets, c.tool, c.args, reason)
			}
			if blocked, reason := a.shouldBlockForTargetScope(c.tool, c.args); blocked {
				t.Fatalf("targets %v: %s %v refused by the target boundary (%s); update the scope prompt text", targets, c.tool, c.args, reason)
			}
		}

		prompt := scopeClaimsPrompt(a)
		assertNoBlanketScopeClaims(t, "system prompt", prompt)
		for _, want := range []string{
			"does NOT check every host for you",
			"NOT evidence that the host is in scope",
			"not refuse such a report",
			"Hosts used only inside a payload aimed at the target",
		} {
			if !strings.Contains(prompt, want) {
				t.Errorf("targets %v: system prompt missing %q", targets, want)
			}
		}
	}
}

// Single-host and port-pinned scans get a SCAN BOUNDARY section. The runtime
// refuses the crossings it recognizes (here a URL fetch of another
// organization), but not every crossing: a report is not checked, so the
// section must not say that every crossing is refused.
func TestScopePromptMatchesRuntime_SingleHostBoundaryIsNotOverclaimed(t *testing.T) {
	a := scopeClaimsAgent(t, []string{"https://app.acme.com:8443"}, true)
	if blocked, _ := a.shouldBlockForTargetScope("http_request", thirdPartyCalls[0].args); !blocked {
		t.Fatal("single-host scan should refuse a request to another organization's host")
	}
	if blocked, reason := a.shouldBlockForTargetScope("report_vulnerability", thirdPartyCalls[3].args); blocked {
		t.Fatalf("report on another organization's host is now refused (%s); update the boundary prompt text", reason)
	}

	prompt := scopeClaimsPrompt(a)
	if !strings.Contains(prompt, "## SCAN BOUNDARY") {
		t.Fatal("single-host prompt is missing the SCAN BOUNDARY section")
	}
	assertNoBlanketScopeClaims(t, "single-host system prompt", prompt)
	for _, want := range []string{
		"not proof that it stays inside these boundaries",
		"do not retry it in another form or through another tool",
		"A scope refusal is not a tool failure",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("single-host system prompt missing %q", want)
		}
	}
}

// The refusal-recovery nudge re-asserts authorization without claiming that
// the runtime blocks every out-of-scope host.
func TestRefusalNudgeDoesNotClaimBlanketScopeEnforcement(t *testing.T) {
	state := NewScanState()
	res := hookNoToolHandler(state, map[string]string{"response": "I cannot fulfill this request"})
	if !strings.Contains(res.Nudge, "AUTHORIZED") {
		t.Fatalf("refusal nudge should re-assert authorization, got %q", res.Nudge)
	}
	assertNoBlanketScopeClaims(t, "refusal nudge", res.Nudge)
	if !strings.Contains(res.Nudge, "not part of the engagement") {
		t.Errorf("refusal nudge should keep the model on the configured target(s), got %q", res.Nudge)
	}
}

func assertNoBlanketScopeClaims(t *testing.T, where, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, stale := range []string{
		"hard-enforces scope",
		"any out-of-scope host is rejected automatically",
		"out-of-scope hosts are rejected automatically",
		"physically cannot touch",
		"cannot touch anything you are not authorized",
		"the sandbox already guarantees it",
		"is rejected with an out-of-scope error",
		"the report will be refused",
		"tool calls that cross them are refused",
		// RFC1918 hosts are not refused (see
		// TestShouldBlockForOutOfScope_AllowsNonLocalPrivateHosts): telling the
		// model they are would steer it away from internal targets.
		"local network or the xalgorix dashboard",
	} {
		if strings.Contains(lower, stale) {
			t.Errorf("%s still claims blanket scope enforcement: %q", where, stale)
		}
	}
}
