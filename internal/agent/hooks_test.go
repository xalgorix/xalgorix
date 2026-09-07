package agent

import (
	"fmt"
	"strings"
	"testing"
)

// ── extractEndpointFromCmd tests ─────────────────────────────────────────────

func TestExtractEndpointFromCmd(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"curl with https", `curl -sk https://example.com/api/users`, "example.com/api/users"},
		{"curl with http", `curl http://example.com/login`, "example.com/login"},
		{"curl root path", `curl https://example.com/`, "example.com/"},
		{"curl no path", `curl https://example.com`, "example.com/"},
		{"curl with quotes", `curl https://example.com/v1/token`, "example.com/v1/token"},
		{"curl with flags", `curl -si -H "Host: evil" https://target.com/admin/panel`, "target.com/admin/panel"},
		{"httpx command", `httpx -u https://target.com/api/v2/health`, "target.com/api/v2/health"},
		{"wget command", `wget https://cdn.example.com/bundle.js`, "cdn.example.com/bundle.js"},
		{"no url", `nmap -sV target.com`, ""},
		{"sqlmap no url prefix", `sqlmap -r request.txt`, ""},
		{"strips query params", `curl https://api.example.com/search?q=test`, "api.example.com/search"},
		// New: piped commands (audit fix #1)
		{"piped curl", `echo '{"id":1}' | curl -d @- https://target.com/api/users`, "target.com/api/users"},
		{"piped with grep", `curl -sk https://target.com/api/v2/config | grep secret`, "target.com/api/v2/config"},
		// New: tools the old extractor missed (audit fix #1)
		{"sqlmap with url", `sqlmap -u https://target.com/api/search?q=test --batch`, "target.com/api/search"},
		{"nuclei with url", `nuclei -u https://target.com/api/health -t cves/`, "target.com/api/health"},
		{"dalfox", `dalfox url https://target.com/search?q=xss`, "target.com/search"},
		// Edge cases
		{"url in quotes", `curl "https://target.com/api/v1/data"`, "target.com/api/v1/data"},
		{"ncat no url", `echo "GET / HTTP/1.1" | ncat target.com 80`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEndpointFromCmd(tt.cmd)
			if got != tt.want {
				t.Errorf("extractEndpointFromCmd(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ── extractHostFromCmd tests ─────────────────────────────────────────────────

func TestExtractHostFromCmd(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{`ffuf -u https://target.com/FUZZ -w wordlist.txt`, "target.com"},
		{`gobuster dir -u https://sub.target.com/ -w list.txt`, "sub.target.com"},
		{`dirsearch -u http://10.0.0.1:8080/api`, "10.0.0.1:8080"},
		{`nmap target.com`, ""},
	}

	for _, tt := range tests {
		name := tt.cmd
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(name, func(t *testing.T) {
			got := extractHostFromCmd(tt.cmd)
			if got != tt.want {
				t.Errorf("extractHostFromCmd(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ── hookWorkTracker tests ────────────────────────────────────────────────────

func TestWorkTracker_TracksUniqueEndpoints(t *testing.T) {
	state := NewScanState()

	// First curl — should track endpoint
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -sk https://example.com/api/users`,
	})
	if len(state.EndpointsTested) != 1 {
		t.Errorf("Expected 1 endpoint tracked, got %d", len(state.EndpointsTested))
	}

	// Same endpoint again — no duplicate
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -sk https://example.com/api/users -H "X-Test: 1"`,
	})
	if len(state.EndpointsTested) != 1 {
		t.Errorf("Expected still 1 endpoint (deduped), got %d", len(state.EndpointsTested))
	}

	// Different endpoint
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl https://example.com/api/login`,
	})
	if len(state.EndpointsTested) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(state.EndpointsTested))
	}
}

func TestWorkTracker_InjectionEndpoints(t *testing.T) {
	state := NewScanState()

	// SQLi on /api/users — realistic curl with injection in data flag
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "id=1' or 1=1--" https://target.com/api/users`,
	})
	if len(state.InjectionEndpoints) != 1 {
		t.Errorf("Expected 1 injection endpoint, got %d", len(state.InjectionEndpoints))
	}
	if !state.InjectionTested {
		t.Error("InjectionTested should be true")
	}

	// XSS on /search — realistic curl with script in parameter
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "q=<script>alert(1)</script>" https://target.com/search`,
	})
	if len(state.InjectionEndpoints) != 2 {
		t.Errorf("Expected 2 injection endpoints, got %d", len(state.InjectionEndpoints))
	}
}

func TestWorkTracker_AccessControlEndpoints(t *testing.T) {
	state := NewScanState()

	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl https://target.com/api/user/1`,
	})
	if len(state.AccessControlEndpoints) != 1 {
		t.Errorf("Expected 1 access control endpoint, got %d", len(state.AccessControlEndpoints))
	}

	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -H "x-forwarded-for: 127.0.0.1" https://target.com/admin/dashboard`,
	})
	if len(state.AccessControlEndpoints) != 2 {
		t.Errorf("Expected 2 access control endpoints, got %d", len(state.AccessControlEndpoints))
	}
}

func TestWorkTracker_VulnClassTracking(t *testing.T) {
	state := NewScanState()

	// SSTI
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/search?q={{7*7}}"`,
	})
	if !state.VulnClassesTested["ssti"] {
		t.Error("SSTI should be detected from {{7*7}}")
	}

	// CRLF
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/redirect?url=%0d%0aInjected-Header:true"`,
	})
	if !state.VulnClassesTested["crlf"] {
		t.Error("CRLF should be detected from CRLF payload")
	}

	// Command injection
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/ping?host=127.0.0.1; id"`,
	})
	if !state.VulnClassesTested["cmdi"] {
		t.Error("CmdI should be detected from ; id")
	}

	// Path traversal
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/file?path=../../../etc/passwd"`,
	})
	if !state.VulnClassesTested["path_traversal"] {
		t.Error("Path traversal should be detected from ../../../etc/passwd")
	}

	// SSRF
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/proxy?url=http://169.254.169.254/latest"`,
	})
	if !state.VulnClassesTested["ssrf"] {
		t.Error("SSRF should be detected from 169.254")
	}

	// Verify SQLi and XSS not set (we didn't send those)
	if state.VulnClassesTested["sqli"] {
		t.Error("SQLi should not be detected without SQL payloads")
	}
	if state.VulnClassesTested["xss"] {
		t.Error("XSS should not be detected without XSS payloads")
	}
}

func TestWorkTracker_PythonActionVulnTracking(t *testing.T) {
	state := NewScanState()

	// Python code with SSTI and CRLF payloads
	hookWorkTracker(state, map[string]string{
		"tool_name": "python_action",
		"code":      `import requests; r = requests.get("https://target.com/search?q={{7*7}}")`,
	})
	if !state.VulnClassesTested["ssti"] {
		t.Error("SSTI should be detected from python_action code")
	}

	hookWorkTracker(state, map[string]string{
		"tool_name": "python_action",
		"code":      `r = requests.get("https://target.com/r?url=%0d%0aX-Injected:true")`,
	})
	if !state.VulnClassesTested["crlf"] {
		t.Error("CRLF should be detected from python_action code")
	}
}

func TestWorkTracker_KeepsEndpointClassPairsSeparate(t *testing.T) {
	state := NewScanState()
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "id=1' or 1=1--" https://target.com/api/users`,
	})
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl https://target.com/api/leads`,
	})

	if !endpointTestedForClass(state, "/api/users", "sqli") {
		t.Error("SQLi payload should cover its exact endpoint")
	}
	if endpointTestedForClass(state, "/api/leads", "sqli") {
		t.Error("generic request must not inherit SQLi coverage from another endpoint")
	}
	if endpointTestedForClass(state, "/api/users", "xss") {
		t.Error("SQLi coverage must not imply XSS coverage on the same endpoint")
	}
}

func TestWorkTracker_LocalTargetIsNotAutomaticallySSRF(t *testing.T) {
	state := NewScanState()
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl http://127.0.0.1:5001/api/users`,
	})
	if state.VulnClassesTested["ssrf"] {
		t.Error("a loopback benchmark target by itself must not count as an SSRF probe")
	}

	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "http://127.0.0.1:5001/proxy?url=http://localhost/admin"`,
	})
	if !endpointTestedForClass(state, "/proxy", "ssrf") {
		t.Error("loopback supplied as a URL parameter should count as an SSRF probe")
	}
}

func TestWorkTracker_TracksNativeHTTPAndVerifierTools(t *testing.T) {
	state := NewScanState()
	hookWorkTracker(state, map[string]string{
		"tool_name": "http_request",
		"url":       "https://target.com/login",
		"method":    "POST",
		"body":      "username=admin' or 1=1--",
	})
	hookWorkTracker(state, map[string]string{
		"tool_name": "verify_ssti",
		"url":       "https://target.com/render?name=test",
	})
	hookWorkTracker(state, map[string]string{
		"tool_name": "authz_matrix",
		"url":       "https://target.com/api/orders/42",
	})
	hookWorkTracker(state, map[string]string{
		"tool_name": "browser_action",
		"command":   "verify_xss",
		"url":       "https://target.com/search?q=test",
	})

	for _, tc := range []struct {
		endpoint string
		class    string
	}{
		{endpoint: "/login", class: "sqli"},
		{endpoint: "/render", class: "ssti"},
		{endpoint: "/api/orders/42", class: "idor"},
		{endpoint: "/search", class: "xss"},
	} {
		if !endpointTestedForClass(state, tc.endpoint, tc.class) {
			t.Errorf("expected %s coverage on %s", tc.class, tc.endpoint)
		}
	}
}

func TestWorkTracker_CountsMeaningfulSecurityActions(t *testing.T) {
	state := NewScanState()
	hookWorkTracker(state, map[string]string{"tool_name": "terminal_execute", "command": "echo done"})
	hookWorkTracker(state, map[string]string{"tool_name": "browser_action", "command": "snapshot"})
	if state.MeaningfulTestCalls != 0 {
		t.Fatalf("no-op and observation-only calls should not satisfy specialist work, got %d", state.MeaningfulTestCalls)
	}
	hookWorkTracker(state, map[string]string{
		"tool_name": "verify_sqli",
		"url":       "https://target.com/login",
	})
	if state.MeaningfulTestCalls != 1 {
		t.Fatalf("deterministic verifier should count as one meaningful action, got %d", state.MeaningfulTestCalls)
	}
}

func TestDefaultHooksTrackWorkOnlyAfterGuardsPass(t *testing.T) {
	state := NewScanState()
	registry := NewHookRegistry()
	RegisterDefaultHooks(registry)
	args := map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "id=1' or 1=1--" https://target.com/api/users`,
	}

	registry.Fire(OnToolCall, state, args)
	if state.MeaningfulTestCalls != 0 || endpointTestedForClass(state, "/api/users", "sqli") {
		t.Fatal("a generated call must not count as executed coverage before all guards pass")
	}

	registry.Fire(OnToolExecute, state, args)
	if state.MeaningfulTestCalls != 1 || !endpointTestedForClass(state, "/api/users", "sqli") {
		t.Fatal("an accepted execution attempt should record meaningful exact coverage")
	}
}

func TestCurlPreference_PythonRequestsNudge(t *testing.T) {
	state := NewScanState()

	// First python HTTP call — soft nudge
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "python_action",
		"code":      `import requests; r = requests.get("https://target.com/api/test")`,
	})
	if result.Nudge == "" {
		t.Error("Should nudge on first python requests.get() call")
	}

	// Non-HTTP python code — no nudge
	state2 := NewScanState()
	result2 := hookCurlPreference(state2, map[string]string{
		"tool_name": "python_action",
		"code":      `print("hello world"); x = 1 + 2`,
	})
	if result2.Nudge != "" {
		t.Error("Should NOT nudge on python code without HTTP calls")
	}
}

func TestWorkTracker_EndpointInventory(t *testing.T) {
	state := NewScanState()

	// Non-inventory note — no keywords at all
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "waf_info",
		"value":     "Target uses CloudFlare WAF",
	})
	if state.EndpointInventorySaved {
		t.Error("Should not be saved for non-inventory note")
	}

	// False positive — keyword in key but only 1 path-like token (too few)
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "discovery_notes",
		"value":     "Discovered that the WAF blocks /api calls",
	})
	if state.EndpointInventorySaved {
		t.Error("Should not be saved for note with just 1 path token")
	}

	// Real inventory note — keyword + 3 path-like tokens
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoint_inventory",
		"value":     "## Discovered Endpoints\n- /api/users\n- /api/login\n- /admin/dashboard",
	})
	if !state.EndpointInventorySaved {
		t.Error("Should be saved for inventory note with keyword + 3 path tokens")
	}

	// Reset and test multi-line fallback (3+ lines)
	state2 := NewScanState()
	hookWorkTracker(state2, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoints",
		"value":     "Discovered endpoints:\n/page1\n/page2\n/page3\n/page4",
	})
	if !state2.EndpointInventorySaved {
		t.Error("Should be saved for note with keyword + 3+ lines")
	}

	// Regression test: vanhack-style note the old check rejected
	state3 := NewScanState()
	hookWorkTracker(state3, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoint_inventory",
		"value":     "Discovered Endpoints:\n- /api/candidates (VULNERABLE - unauthenticated access)\n- /api/jobs (public job listings)\n- /api/testimonials (public)\n- /api/candidate-stories\n- /v1/auth/refreshtoken",
	})
	if !state3.EndpointInventorySaved {
		t.Error("Should be saved for vanhack-style endpoint inventory")
	}
}

// ── hookFinishGatekeeper tests ───────────────────────────────────────────────

func TestFinishGatekeeper_BlocksLowIteration(t *testing.T) {
	state := NewScanState()
	state.Iteration = 2
	state.TerminalCalls = 10
	state.ReconDone = true

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block at iteration < 3")
	}
}

func TestFinishGatekeeper_BlocksLowCommands(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 3

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block with < 5 terminal commands")
	}
}

func TestFinishGatekeeper_AllowsAfterRepeatedAttempts(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 2 // normally blocked (< 5)

	// First 15 attempts should block
	for i := 1; i <= 15; i++ {
		res := hookFinishGatekeeper(state, nil)
		if !res.Block {
			t.Errorf("Attempt %d should block", i)
		}
	}

	// 16th attempt should be allowed to prevent infinite deadlock
	res16 := hookFinishGatekeeper(state, nil)
	if res16.Block {
		t.Error("Attempt 16 should be allowed to prevent deadlock loop")
	}
}

func TestFinishGatekeeper_BlocksNoRecon(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 10
	state.ReconDone = false

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block without recon")
	}
}

func TestFinishGatekeeper_BlocksNoInventory(t *testing.T) {
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 15
	state.ReconDone = true
	state.EndpointInventorySaved = false

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block without endpoint inventory saved")
	}
}

func TestFinishGatekeeper_BlocksLowCoverage(t *testing.T) {
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 15
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// Only 1 injection endpoint out of 10 tested
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.EndpointsTested["d"] = true
	state.EndpointsTested["e"] = true
	state.EndpointsTested["f"] = true
	state.EndpointsTested["g"] = true
	state.EndpointsTested["h"] = true
	state.EndpointsTested["i"] = true
	state.EndpointsTested["j"] = true
	state.InjectionEndpoints["a"] = true // only 1

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block with only 1/10 injection endpoints tested")
	}
}

func TestFinishGatekeeper_AllowsAfter50WithCoverage(t *testing.T) {
	state := NewScanState()
	state.Iteration = 55
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.InjectionEndpoints["a"] = true
	state.InjectionEndpoints["b"] = true
	state.InjectionEndpoints["c"] = true
	state.AccessControlEndpoints["a"] = true
	state.AccessControlEndpoints["b"] = true
	state.DirBustingHosts["target.com"] = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.FinishAttempts = 2 // not first attempt (already incremented in the function)

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Should allow finish after 50 iterations with good coverage, but got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_BlocksBelow50EvenWithCoverage(t *testing.T) {
	// Large surface area (> 15 endpoints): 50-iteration floor always applies
	state := NewScanState()
	state.Iteration = 40
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// 20 endpoints — large surface, adaptive early finish doesn't apply
	for i := range 20 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	state.InjectionEndpoints["ep0"] = true
	state.InjectionEndpoints["ep1"] = true
	state.InjectionEndpoints["ep2"] = true
	state.AccessControlEndpoints["ep0"] = true
	state.AccessControlEndpoints["ep1"] = true
	state.DirBustingHosts["target.com"] = true

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Large surface (20 endpoints) should block below 50 iterations even with good coverage")
	}
}

func TestFinishGatekeeper_DiscoveryModeAllowsEarly(t *testing.T) {
	state := NewScanState()
	state.DiscoveryMode = true
	state.TerminalCalls = 5
	state.Iteration = 8

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Error("Discovery mode should allow finish after 3+ terminal calls")
	}
}

func TestFinishGatekeeper_DiscoveryModeBlocksTooFew(t *testing.T) {
	state := NewScanState()
	state.DiscoveryMode = true
	state.TerminalCalls = 2

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Discovery mode should block with < 3 terminal calls")
	}
}

func TestFinishGatekeeper_DelegatedSpecialistCanReturnCompletedLane(t *testing.T) {
	state := NewScanState()
	state.DelegatedAgent = true
	state.Iteration = 8
	state.TerminalCalls = 1
	state.MeaningfulTestCalls = 3
	plan := NewPlan()
	plan.add(&Task{ID: "assigned-authz", Title: "test assigned authz hypotheses", Phase: 8, Status: TaskCompleted})
	plan.add(&Task{ID: "report", Title: "return evidence", Phase: 22, Status: TaskCompleted})
	state.Plan = plan

	if result := hookFinishGatekeeper(state, nil); result.Block {
		t.Fatalf("completed specialist lane should not inherit the root scan floor: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_DelegatedSpecialistStillRequiresWorkAndPlanCompletion(t *testing.T) {
	state := NewScanState()
	state.DelegatedAgent = true
	if result := hookFinishGatekeeper(state, nil); !result.Block {
		t.Fatal("specialist with no security action must not finish")
	}

	state.MeaningfulTestCalls = 1
	plan := NewPlan()
	plan.add(&Task{ID: "assigned-sqli", Title: "test assigned SQLi hypotheses", Phase: 6, Status: TaskPending})
	state.Plan = plan
	if result := hookFinishGatekeeper(state, nil); !result.Block || !strings.Contains(result.BlockReason, "unfinished task") {
		t.Fatalf("specialist with pending assigned work should be blocked by its plan, got: %+v", result)
	}
}

func TestFinishGatekeeper_BlocksInvalidPlanTaskSkips(t *testing.T) {
	state := NewScanState()
	state.Iteration = 55
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.VulnClassesTested["sqli"] = true
	state.VulnClassesTested["xss"] = true
	state.VulnClassesTested["ssti"] = true
	state.VulnClassesTested["cmdi"] = true
	state.VulnClassesTested["path_traversal"] = true
	state.VulnClassesTested["ssrf"] = true
	state.VulnClassesTested["crlf"] = true
	state.VulnClassesTested["xxe"] = true
	state.OASTProbesExecuted = 1
	state.FinishAttempts = 2 // > 1 so vuln class soft nudge is past
	plan := NewPlan()
	plan.add(&Task{ID: "recon", Phase: 1, Title: "Recon", Status: TaskCompleted})
	plan.add(&Task{ID: "test-dirbust", Phase: 2, Title: "Dirbust", Status: TaskSkipped, Notes: "RCE already found on /eval"})
	plan.add(&Task{ID: "test-xss", Phase: 3, Title: "XSS", Status: TaskSkipped, Notes: "SQLi already achieved auth bypass"})
	state.Plan = plan

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Gatekeeper should block when tasks are skipped with invalid early RCE/SQLi shortcuts")
	}
	if !strings.Contains(result.BlockReason, "INVALID PLAN TASK SKIPS DETECTED") {
		t.Errorf("Unexpected block reason: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_BlocksMissingOASTProbes(t *testing.T) {
	state := NewScanState()
	state.Iteration = 55
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.VulnClassesTested["sqli"] = true
	state.VulnClassesTested["xss"] = true
	state.VulnClassesTested["ssti"] = true
	state.VulnClassesTested["cmdi"] = true
	state.VulnClassesTested["path_traversal"] = true
	state.VulnClassesTested["ssrf"] = true
	state.VulnClassesTested["crlf"] = true
	state.VulnClassesTested["xxe"] = true
	state.OASTProbesExecuted = 0 // Tested XXE/SSRF but 0 OAST probes!
	state.FinishAttempts = 1     // becomes 2 inside hookFinishGatekeeper (after FinishAttempts++)

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Gatekeeper should block finish when blind classes (XXE/SSRF) are tested with 0 OAST probes")
	}
	if !strings.Contains(result.BlockReason, "MANDATORY OUT-OF-BAND (OAST) PROBING REQUIRED") {
		t.Errorf("Unexpected block reason: %s", result.BlockReason)
	}
}

// ── minInt / maxInt tests ────────────────────────────────────────────────────

func TestMinMaxInt(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) should be 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if maxInt(3, 5) != 5 {
		t.Error("maxInt(3,5) should be 5")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
}

// ── Role temperature tests ───────────────────────────────────────────────────

func TestRoleTemperatures(t *testing.T) {
	tests := []struct {
		name string
		temp *float64
		want float64
	}{
		{"Scanner", TempScanner, 0.0},
		{"Reasoner", TempReasoner, 0.2},
		{"Validator", TempValidator, 0.0},
		{"Reporter", TempReporter, 0.3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.temp == nil {
				t.Fatal("temperature pointer should not be nil")
			}
			if *tt.temp != tt.want {
				t.Errorf("Temp%s = %f, want %f", tt.name, *tt.temp, tt.want)
			}
		})
	}
}

func TestFloatPtr(t *testing.T) {
	p := floatPtr(0.5)
	if p == nil || *p != 0.5 {
		t.Error("floatPtr(0.5) should return pointer to 0.5")
	}

	// Zero value should work (not nil)
	p0 := floatPtr(0.0)
	if p0 == nil || *p0 != 0.0 {
		t.Error("floatPtr(0.0) should return pointer to 0.0, not nil")
	}
}

// ── testDepthRatio tests ─────────────────────────────────────────────────────

func TestTestDepthRatio(t *testing.T) {
	tests := []struct {
		name                                        string
		total, injection, accessControl, dirbusting int
		want                                        float64
	}{
		{"no endpoints", 0, 0, 0, 0, 0.0},
		{"3 endpoints, full coverage", 3, 3, 3, 3, 3.0},
		{"10 endpoints, partial", 10, 3, 2, 1, 0.6},
		{"1 endpoint, all classes", 1, 1, 1, 1, 3.0},
		{"5 endpoints, shallow", 5, 1, 0, 0, 0.2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := testDepthRatio(tt.total, tt.injection, tt.accessControl, tt.dirbusting)
			if got != tt.want {
				t.Errorf("testDepthRatio(%d,%d,%d,%d) = %f, want %f",
					tt.total, tt.injection, tt.accessControl, tt.dirbusting, got, tt.want)
			}
		})
	}
}

// ── Adaptive surface area tests ──────────────────────────────────────────────

func TestFinishGatekeeper_SmallSurfaceEarlyFinish(t *testing.T) {
	// Small target (3 endpoints), deep testing (depth 2.0+), iter 30 → allow
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// 3 endpoints, all tested with injection + access control + dirbusting
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.InjectionEndpoints["a"] = true
	state.InjectionEndpoints["b"] = true
	state.InjectionEndpoints["c"] = true
	state.AccessControlEndpoints["a"] = true
	state.AccessControlEndpoints["b"] = true
	state.DirBustingHosts["target.com"] = true
	// depth = (3 + 2 + 1) / 3 = 2.0

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Small surface with depth 2.0 at iter 30 should allow early finish, got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_SmallSurfaceShallowBlocked(t *testing.T) {
	// Small target (3 endpoints), shallow testing (depth 0.3), iter 30 → block
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.InjectionEndpoints["a"] = true // only 1 injection test
	state.DirBustingHosts["target.com"] = true
	// depth = (1 + 0 + 1) / 3 = 0.67 — too shallow

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Small surface with shallow depth should still block")
	}
}

func TestFinishGatekeeper_MediumSurfaceEarlyFinish(t *testing.T) {
	// Medium target (8 endpoints), good depth (1.5+), iter 42 → allow
	state := NewScanState()
	state.Iteration = 42
	state.TerminalCalls = 20
	state.ReconDone = true
	state.EndpointInventorySaved = true
	for i := range 8 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	// 4 injection + 4 access control + 4 dirbusting hosts = 12 tests / 8 endpoints = 1.5
	for i := range 4 {
		state.InjectionEndpoints[fmt.Sprintf("ep%d", i)] = true
		state.AccessControlEndpoints[fmt.Sprintf("ep%d", i)] = true
	}
	state.DirBustingHosts["target.com"] = true
	state.DirBustingHosts["sub.target.com"] = true
	state.DirBustingHosts["api.target.com"] = true
	state.DirBustingHosts["admin.target.com"] = true
	// depth = (4 + 4 + 4) / 8 = 1.5

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Medium surface with depth 1.5 at iter 42 should allow finish, got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_LargeSurfaceNoEarlyFinish(t *testing.T) {
	// Large target (20 endpoints), good depth, iter 35 → still blocked (> 15 endpoints)
	state := NewScanState()
	state.Iteration = 35
	state.TerminalCalls = 25
	state.ReconDone = true
	state.EndpointInventorySaved = true
	for i := range 20 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	for i := range 10 {
		state.InjectionEndpoints[fmt.Sprintf("ep%d", i)] = true
		state.AccessControlEndpoints[fmt.Sprintf("ep%d", i)] = true
	}
	state.DirBustingHosts["target.com"] = true
	// depth = (10 + 10 + 1) / 20 = 1.05 — but > 15 endpoints, no early finish

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Large surface (20 endpoints) should not get early finish at iter 35")
	}
}

func TestFinishGatekeeper_DirBustingOnlyGamingBlocked(t *testing.T) {
	// Audit fix: agent inflates dirbusting hosts to game depth ratio
	// 3 endpoints, 0 injection, 0 access control, 4 dirbusting hosts
	// depth = (0 + 0 + 4) / 3 = 1.33 — looks okay but only 1 category covered
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.DirBustingHosts["target.com"] = true
	state.DirBustingHosts["sub1.target.com"] = true
	state.DirBustingHosts["sub2.target.com"] = true
	state.DirBustingHosts["sub3.target.com"] = true
	// categoriesCovered = 1 (only dirbusting) → early finish blocked

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block early finish when only 1 of 3 vuln categories covered (dirbusting-only gaming)")
	}
}

// ── hookCurlPreference tests ─────────────────────────────────────────────────

func TestCurlPreference_SendRequestFirstUseNudge(t *testing.T) {
	state := NewScanState()
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "GET",
		"headers":   "",
	})
	if result.Nudge == "" {
		t.Error("Should nudge on first send_request without auth headers")
	}
	if state.SendRequestCalls != 1 {
		t.Errorf("SendRequestCalls = %d, want 1", state.SendRequestCalls)
	}
}

func TestCurlPreference_SendRequestEscalatesAfter3(t *testing.T) {
	state := NewScanState()
	state.SendRequestCalls = 2 // already used twice

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "POST",
		"headers":   "Content-Type: application/json",
	})
	if result.Nudge == "" {
		t.Error("Should escalate warning after 3+ send_request calls")
	}
	if !strings.Contains(result.Nudge, "STOP") {
		t.Error("Escalated warning should contain 'STOP'")
	}
}

func TestCurlPreference_SendRequestAllowsWithAuth(t *testing.T) {
	state := NewScanState()
	state.SendRequestCalls = 4 // would normally trigger strong warning

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "GET",
		"headers":   "Cookie: session=abc123; Authorization: Bearer xyz",
	})
	if result.Nudge != "" {
		t.Errorf("Should NOT nudge send_request with auth headers, got: %s", result.Nudge)
	}
}

func TestCurlPreference_BrowserNudgeWithoutAuth(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveBrowser = 3 // already used 3 times
	state.BrowserAuthContext = false

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "browser_action",
		"action":    "navigate",
		"url":       "https://target.com/api/users",
		"text":      "",
	})
	if result.Nudge == "" {
		t.Error("Should nudge browser usage without auth context after 2+ consecutive uses")
	}
}

func TestCurlPreference_BrowserAllowsAuthContext(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveBrowser = 5

	// Login page navigation sets auth context
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "browser_action",
		"action":    "navigate",
		"url":       "https://target.com/login",
		"text":      "",
	})
	if !state.BrowserAuthContext {
		t.Error("Login URL should set BrowserAuthContext = true")
	}
	if result.Nudge != "" {
		t.Errorf("Should NOT nudge browser on login page, got: %s", result.Nudge)
	}
}

func TestCurlPreference_IgnoresOtherTools(t *testing.T) {
	state := NewScanState()
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   "curl https://target.com",
	})
	if result.Nudge != "" {
		t.Error("Should not nudge for terminal_execute (curl)")
	}
	if state.SendRequestCalls != 0 {
		t.Error("SendRequestCalls should remain 0 for non-send_request tools")
	}
}

// ── repeat-detector tests (issue #158) ───────────────────────────────────────

// fireRepeat simulates one iteration's hook sequence for a tool call:
// OnToolCall (tracking) → OnStuckCheck (nudge/force-skip decision).
func fireRepeat(state *ScanState, toolName string, args map[string]string) HookResult {
	callArgs := map[string]string{"tool_name": toolName}
	for k, v := range args {
		callArgs[k] = v
	}
	hookStuckTracker(state, callArgs)
	return hookStuckNudge(state, callArgs)
}

func TestRepeatDetector_SameCallForceSkipsAfterThreshold(t *testing.T) {
	state := NewScanState()
	args := map[string]string{"command": "curl -sk https://example.com/csp"}

	// Iterations 1..2: below soft-nudge threshold → no skip.
	for i := 1; i <= RepeatCallSoftNudge-1; i++ {
		res := fireRepeat(state, "terminal_execute", args)
		if res.ForceSkip {
			t.Fatalf("iteration %d: did not expect ForceSkip yet", i)
		}
		if state.ConsecutiveSameCall != i {
			t.Fatalf("iteration %d: ConsecutiveSameCall = %d, want %d", i, state.ConsecutiveSameCall, i)
		}
	}

	// Iteration RepeatCallSoftNudge: should force-skip + nudge, then reset.
	res := fireRepeat(state, "terminal_execute", args)
	if !res.ForceSkip {
		t.Fatal("expected ForceSkip at soft-nudge threshold")
	}
	if res.Nudge == "" {
		t.Fatal("expected a non-empty pivot nudge")
	}
	if !strings.Contains(res.Nudge, "REPEATED CALL") {
		t.Errorf("nudge should mention REPEATED CALL, got: %s", res.Nudge)
	}
	if state.ConsecutiveSameCall != 0 {
		t.Errorf("ConsecutiveSameCall should reset to 0 after nudge, got %d", state.ConsecutiveSameCall)
	}

	// Hard-skip threshold should also fire and reset.
	state.ConsecutiveSameCall = RepeatCallHardSkip - 1
	res = fireRepeat(state, "terminal_execute", args)
	if !res.ForceSkip || !strings.Contains(res.Nudge, "repeatedly re-issued") {
		t.Errorf("expected hard-skip nudge at %d, got ForceSkip=%v nudge=%q", RepeatCallHardSkip, res.ForceSkip, res.Nudge)
	}
	if state.ConsecutiveSameCall != 0 {
		t.Errorf("ConsecutiveSameCall should reset after hard skip, got %d", state.ConsecutiveSameCall)
	}
}

func TestRepeatDetector_DifferentCallResets(t *testing.T) {
	state := NewScanState()

	fireRepeat(state, "terminal_execute", map[string]string{"command": "curl https://a.example.com"})
	fireRepeat(state, "terminal_execute", map[string]string{"command": "curl https://b.example.com"})

	if state.ConsecutiveSameCall != 1 {
		t.Fatalf("alternating commands must reset counter to 1, got %d", state.ConsecutiveSameCall)
	}
	// Two different calls must never trip the detector.
	res := fireRepeat(state, "terminal_execute", map[string]string{"command": "curl https://c.example.com"})
	if res.ForceSkip {
		t.Fatal("different calls must not trigger ForceSkip")
	}
}

func TestRepeatDetector_ArgOrderIndependent(t *testing.T) {
	// Same key/values, different map iteration order must hash identically.
	a := map[string]string{"command": "nmap -sV example.com", "timeout": "30"}
	b := map[string]string{"timeout": "30", "command": "nmap -sV example.com"}
	if hashToolArgs("terminal_execute", a) != hashToolArgs("terminal_execute", b) {
		t.Fatal("hashToolArgs must be insensitive to arg insertion order")
	}
	if hashToolArgs("terminal_execute", a) == hashToolArgs("send_request", a) {
		t.Fatal("different tool names must hash differently")
	}
}

func TestRepeatDetector_NotesDoNotResetCounter(t *testing.T) {
	state := NewScanState()
	args := map[string]string{"command": "curl https://example.com/csp"}

	// Two identical terminal calls to build the counter.
	fireRepeat(state, "terminal_execute", args)
	fireRepeat(state, "terminal_execute", args)
	if state.ConsecutiveSameCall != 2 {
		t.Fatalf("expected ConsecutiveSameCall=2, got %d", state.ConsecutiveSameCall)
	}

	// An add_note call between iterations must NOT reset the terminal-loop
	// counter (notes are not progress on the test itself).
	hookStuckTracker(state, map[string]string{"tool_name": "add_note", "content": "tried csp"})
	if state.ConsecutiveSameCall != 2 {
		t.Errorf("add_note must not reset ConsecutiveSameCall, got %d", state.ConsecutiveSameCall)
	}

	// Third identical terminal call trips the detector.
	res := fireRepeat(state, "terminal_execute", args)
	if !res.ForceSkip {
		t.Fatal("identical call after an intervening note must still force-skip")
	}
}

func TestRepeatDetector_IdenticalResultForceSkips(t *testing.T) {
	state := NewScanState()
	out := "[exit code: 1]\nbash: foobar: command not found"

	for i := 1; i < RepeatResultHardSkip; i++ {
		hookResultRepeatTracker(state, map[string]string{
			"tool_name": "terminal_execute",
			"output":    out,
			"error":     "",
		})
		if state.ConsecutiveSameResult != i {
			t.Fatalf("iter %d: ConsecutiveSameResult=%d, want %d", i, state.ConsecutiveSameResult, i)
		}
		// No force-skip until threshold reached (checked via hookStuckNudge).
		if nudge := hookStuckNudge(state, map[string]string{"tool_name": "terminal_execute"}); nudge.ForceSkip {
			t.Fatalf("did not expect force-skip before %d", RepeatResultHardSkip)
		}
	}

	// Reach the threshold.
	hookResultRepeatTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"output":    out,
		"error":     "",
	})
	res := hookStuckNudge(state, map[string]string{"tool_name": "terminal_execute"})
	if !res.ForceSkip {
		t.Fatal("expected ForceSkip on identical-output threshold")
	}
	if !strings.Contains(res.Nudge, "NO PROGRESS") {
		t.Errorf("expected NO PROGRESS nudge, got: %s", res.Nudge)
	}
	if state.ConsecutiveSameResult != 0 {
		t.Errorf("ConsecutiveSameResult should reset after nudge, got %d", state.ConsecutiveSameResult)
	}
}

// TestStuckNudgesAreLLMOnly asserts that all four hookStuckNudge guardrail
// messages (REPEATED CALL, NO PROGRESS, EXHAUSTION LIMIT, PIVOT REQUIRED) are
// LLM-only: they steer the model via Nudge + ForceSkip but never reach the
// user-facing feed (EmitMessage must stay empty). Otherwise end users see
// "instructions to the AI" mislabeled as red errors in the STDOUT panel.
func TestStuckNudgesAreLLMOnly(t *testing.T) {
	args := map[string]string{"tool_name": "terminal_execute", "command": "curl https://example.com"}

	// ── REPEATED CALL: identical (tool,args) repeated past the threshold ──
	state := NewScanState()
	for i := 0; i < RepeatCallSoftNudge; i++ {
		hookStuckTracker(state, args)
	}
	res := hookStuckNudge(state, args)
	if res.Nudge == "" || !strings.Contains(res.Nudge, "REPEATED CALL") {
		t.Fatalf("REPEATED CALL: expected non-empty Nudge, got %q", res.Nudge)
	}
	if res.EmitMessage != "" {
		t.Errorf("REPEATED CALL must be LLM-only, got EmitMessage=%q", res.EmitMessage)
	}

	// ── NO PROGRESS: byte-identical tool output across calls ──
	state = NewScanState()
	for i := 0; i < RepeatResultHardSkip; i++ {
		hookResultRepeatTracker(state, map[string]string{
			"tool_name": "terminal_execute",
			"output":    "identical-output",
			"error":     "",
		})
	}
	res = hookStuckNudge(state, args)
	if res.Nudge == "" || !strings.Contains(res.Nudge, "NO PROGRESS") {
		t.Fatalf("NO PROGRESS: expected non-empty Nudge, got %q", res.Nudge)
	}
	if res.EmitMessage != "" {
		t.Errorf("NO PROGRESS must be LLM-only, got EmitMessage=%q", res.EmitMessage)
	}

	// ── EXHAUSTION LIMIT: StuckIterations past the hard limit ──
	state = NewScanState()
	state.StuckIterations = StuckHardLimit
	state.StuckDomain = "example.com"
	res = hookStuckNudge(state, args)
	if res.Nudge == "" || !strings.Contains(res.Nudge, "EXHAUSTION LIMIT") {
		t.Fatalf("EXHAUSTION LIMIT: expected non-empty Nudge, got %q", res.Nudge)
	}
	if res.EmitMessage != "" {
		t.Errorf("EXHAUSTION LIMIT must be LLM-only, got EmitMessage=%q", res.EmitMessage)
	}

	// ── PIVOT REQUIRED: browser/search stuck past the soft threshold ──
	state = NewScanState()
	state.ConsecutiveBrowser = StuckBrowserThreshold
	state.StuckIterations = StuckBrowserThreshold
	state.StuckDomain = "example.com"
	res = hookStuckNudge(state, args)
	if res.Nudge == "" || !strings.Contains(res.Nudge, "PIVOT REQUIRED") {
		t.Fatalf("PIVOT REQUIRED: expected non-empty Nudge, got %q", res.Nudge)
	}
	if res.EmitMessage != "" {
		t.Errorf("PIVOT REQUIRED must be LLM-only, got EmitMessage=%q", res.EmitMessage)
	}
}

func TestRepeatDetector_ResultTrackerIgnoresNotesAndFinish(t *testing.T) {
	state := NewScanState()
	for _, tool := range []string{"add_note", "read_notes", "finish"} {
		before := state.ConsecutiveSameResult
		hookResultRepeatTracker(state, map[string]string{
			"tool_name": tool,
			"output":    "anything",
			"error":     "",
		})
		if state.ConsecutiveSameResult != before {
			t.Errorf("%q must not feed the result-repeat counter (was %d, now %d)", tool, before, state.ConsecutiveSameResult)
		}
	}
}

func TestRepeatDetector_ResetOnSuccessLeavesRepeatCounters(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveSameCall = 3
	state.ConsecutiveSameResult = 4
	state.LastToolName = "terminal_execute"
	state.LastResultFP = "abc"

	// A "healthy" response that re-issues the same call is exactly the loop
	// we want to keep detecting, so OnHealthyResponse must NOT reset these.
	hookResetOnSuccess(state, nil)

	if state.ConsecutiveSameCall != 3 {
		t.Errorf("ConsecutiveSameCall must survive OnHealthyResponse, got %d", state.ConsecutiveSameCall)
	}
	if state.ConsecutiveSameResult != 4 {
		t.Errorf("ConsecutiveSameResult must survive OnHealthyResponse, got %d", state.ConsecutiveSameResult)
	}
	if state.LastToolName != "terminal_execute" || state.LastResultFP != "abc" {
		t.Error("LastToolName/LastResultFP must survive OnHealthyResponse")
	}
	// Sanity: the error counters ARE reset by OnHealthyResponse.
	if state.ConsecutiveErrors != 0 || state.NoToolCount != 0 {
		t.Error("ConsecutiveErrors/NoToolCount should be reset by OnHealthyResponse")
	}
}

func TestRepeatDetector_CeilingAbortsLoop(t *testing.T) {
	state := NewScanState()
	args := map[string]string{"tool_name": "terminal_execute", "command": "curl -sk https://example.com/api"}

	var finalMessage string
	for i := 0; i < 25; i++ {
		hookStuckTracker(state, args)
		res := hookStuckNudge(state, args)
		if res.EmitMessage != "" {
			finalMessage = res.EmitMessage
			break
		}
	}

	if finalMessage == "" || !strings.Contains(finalMessage, "Loop limit reached") {
		t.Fatalf("expected loop limit abort message, got: %q", finalMessage)
	}
}

func TestTrivialNoOpCommand_LoopDetector(t *testing.T) {
	state := NewScanState()

	// Initial no-op calls should trigger a nudge at 3
	for i := 1; i <= 3; i++ {
		hookStuckTracker(state, map[string]string{"tool_name": "terminal_execute", "command": "echo done"})
	}
	res := hookStuckNudge(state, map[string]string{"tool_name": "terminal_execute", "command": "echo done"})
	if !res.ForceSkip || !strings.Contains(res.Nudge, "NO-OP COMMAND DETECTED") {
		t.Fatalf("expected NO-OP COMMAND DETECTED nudge, got: %+v", res)
	}

	// Sustained no-op calls should trigger an abort at 8
	var abortMessage string
	for i := 4; i <= 8; i++ {
		hookStuckTracker(state, map[string]string{"tool_name": "terminal_execute", "command": fmt.Sprintf("echo %d", i)})
		nudge := hookStuckNudge(state, map[string]string{"tool_name": "terminal_execute", "command": fmt.Sprintf("echo %d", i)})
		if nudge.EmitMessage != "" {
			abortMessage = nudge.EmitMessage
			break
		}
	}

	if abortMessage == "" || !strings.Contains(abortMessage, "Loop limit reached") {
		t.Fatalf("expected Loop limit reached for no-ops, got %q", abortMessage)
	}
}

func TestHookReportVulnerabilityTracker_BlocksFinishOnPendingFailedCalls(t *testing.T) {
	state := NewScanState()

	// 1. Initial state: PendingFailedReportCalls is 0, finish allowed (assuming minimums met)
	state.Iteration = 10
	state.TerminalCalls = 10
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveryMode = true

	res := hookFinishGatekeeper(state, map[string]string{})
	if res.Block {
		t.Fatalf("expected finish allowed, got blocked: %s", res.BlockReason)
	}

	// 2. Report vulnerability fails due to missing parameters
	hookReportVulnerabilityTracker(state, map[string]string{
		"tool":   "report_vulnerability",
		"output": "missing required parameter 'title' for tool 'report_vulnerability'",
	})
	if state.PendingFailedReportCalls != 1 {
		t.Fatalf("expected PendingFailedReportCalls = 1, got %d", state.PendingFailedReportCalls)
	}

	// 2b. A semantic rejection is a resolved candidate, not an unresolved
	// schema failure. It must not deadlock the finish path.
	hookReportVulnerabilityTracker(state, map[string]string{
		"tool":   "report_vulnerability",
		"output": "❌ REJECTED: 'SQL Injection' reported as CRITICAL but has NO verification_method",
	})
	if state.PendingFailedReportCalls != 0 {
		t.Fatalf("semantic rejection must clear PendingFailedReportCalls, got %d", state.PendingFailedReportCalls)
	}

	// 3. Calling finish after the semantic rejection is allowed.
	res = hookFinishGatekeeper(state, map[string]string{})
	if res.Block {
		t.Fatalf("expected finish to be allowed after semantic rejection, got: %+v", res)
	}

	// 4. A successful report is also a terminal resolution.
	hookReportVulnerabilityTracker(state, map[string]string{
		"tool":   "report_vulnerability",
		"output": "✅ Vulnerability reported: [XALG-1] Test (CRITICAL)",
	})
	hookReportVulnerabilityTracker(state, map[string]string{
		"tool":   "report_vulnerability",
		"output": "✅ Vulnerability reported: [XALG-2] Test 2 (CRITICAL)",
	})
	if state.PendingFailedReportCalls != 0 {
		t.Fatalf("expected PendingFailedReportCalls = 0 after success, got %d", state.PendingFailedReportCalls)
	}

	// 5. Calling finish now succeeds again
	res = hookFinishGatekeeper(state, map[string]string{})
	if res.Block {
		t.Fatalf("expected finish allowed after successful report, got blocked: %s", res.BlockReason)
	}
}

func TestHookReportVulnerabilityTracker_CapsMalformedRecovery(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 10
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.DiscoveryMode = true
	for i := 0; i < maxReportRepairAttempts; i++ {
		res := hookReportVulnerabilityTracker(state, map[string]string{
			"tool":   "report_vulnerability",
			"output": "missing required parameters for tool 'report_vulnerability': title, severity",
		})
		if i < maxReportRepairAttempts-1 && state.PendingFailedReportCalls != 1 {
			t.Fatalf("attempt %d: pending = %d, want 1", i+1, state.PendingFailedReportCalls)
		}
		if i == maxReportRepairAttempts-1 {
			if state.PendingFailedReportCalls != 0 || !state.ReportRetryLimitReached {
				t.Fatalf("limit state = pending %d, reached %v; want 0,true", state.PendingFailedReportCalls, state.ReportRetryLimitReached)
			}
			if res.Nudge == "" {
				t.Fatal("expected a final repair nudge")
			}
		}
	}
	if res := hookReportRetryGuard(state, map[string]string{
		"tool_name":   "report_vulnerability",
		"title":       "A corrected finding",
		"severity":    "medium",
		"description": "complete corrected description",
	}); res.ForceSkip {
		t.Fatal("a later complete report must not be blocked by an earlier malformed-call limit")
	}
	if res := hookFinishGatekeeper(state, nil); res.Block {
		t.Fatalf("finish must be allowed after the repair limit, got: %s", res.BlockReason)
	}
}

func TestDelegationCoordinatorNudgesOnceAfterRecon(t *testing.T) {
	state := NewScanState()
	state.Iteration = 8
	state.ReconDone = true
	state.DetectedTechs["nodejs"] = true
	state.DiscoveredEndpoints = []string{"/api/users", "/graphql"}
	state.Plan = AutoPlan(state.DiscoveredEndpoints, state.DetectedTechs)
	state.PlanBuilt = true
	state.LedgerSeeded = true

	result := hookDelegationCoordinator(state, nil)
	// The nudge is now ledger-driven and built from the deterministic specialist
	// profiles, while still carrying the recon context (detected stack + surface).
	if result.Nudge == "" ||
		!strings.Contains(result.Nudge, "authz-logic") ||
		!strings.Contains(result.Nudge, "read_ledger") ||
		!strings.Contains(result.Nudge, "nodejs") ||
		!strings.Contains(result.Nudge, "/graphql") {
		t.Fatalf("unexpected delegation nudge: %q", result.Nudge)
	}
	if second := hookDelegationCoordinator(state, nil); second.Nudge != "" {
		t.Fatalf("delegation nudge repeated: %q", second.Nudge)
	}
}

func TestDelegationCoordinatorSkipsDiscoveryAndExistingDelegation(t *testing.T) {
	state := NewScanState()
	state.Iteration = 8
	state.ReconDone = true
	state.DiscoveryMode = true
	if result := hookDelegationCoordinator(state, nil); result.Nudge != "" {
		t.Fatalf("discovery scan received delegation nudge: %q", result.Nudge)
	}

	state.DiscoveryMode = false
	hookWorkTracker(state, map[string]string{"tool_name": "spawn_agent", "name": "authz", "task": "test role boundaries"})
	if !state.DelegationAttempted {
		t.Fatal("spawn_agent call did not mark delegation attempted")
	}
	if result := hookDelegationCoordinator(state, nil); result.Nudge != "" {
		t.Fatalf("coordinator with an existing delegation was nudged again: %q", result.Nudge)
	}
}

func TestDelegationCoordinatorRetriesMalformedSpawnWithoutLooping(t *testing.T) {
	state := NewScanState()
	state.Iteration = 5
	state.ReconDone = true
	state.Plan = AutoPlan([]string{"/api/users"}, nil)
	state.PlanBuilt = true
	state.LedgerSeeded = true

	if first := hookDelegationCoordinator(state, nil); first.Nudge == "" {
		t.Fatal("expected initial delegation nudge")
	}
	// Missing task is the exact malformed call observed in the real run.
	hookWorkTracker(state, map[string]string{"tool_name": "spawn_agent", "name": "authz"})
	if state.DelegationAttempted {
		t.Fatal("malformed spawn must not count as a successful delegation attempt")
	}

	state.Iteration = 6
	if early := hookDelegationCoordinator(state, nil); early.Nudge != "" {
		t.Fatalf("one-turn ledger-reading grace period should be quiet: %q", early.Nudge)
	}
	state.Iteration = 7
	if reminder := hookDelegationCoordinator(state, nil); !strings.Contains(reminder.Nudge, "BOTH required parameters") {
		t.Fatalf("expected schema-explicit delegation reminder, got %q", reminder.Nudge)
	}
	state.Iteration = 9
	if reminder := hookDelegationCoordinator(state, nil); reminder.Nudge == "" {
		t.Fatal("expected the second bounded reminder")
	}
	state.Iteration = 11
	if extra := hookDelegationCoordinator(state, nil); extra.Nudge != "" {
		t.Fatalf("delegation reminders must be bounded, got %q", extra.Nudge)
	}
}

func TestBenchmarkIsolationGuardBlocksHostAssistance(t *testing.T) {
	state := NewScanState()
	state.BenchmarkIsolated = true
	blocked := []map[string]string{
		{"tool_name": "terminal_execute", "command": "docker ps && docker exec fixture cat /etc/app/config"},
		{"tool_name": "terminal_execute", "command": "sudo /usr/bin/podman inspect fixture"},
		{"tool_name": "terminal_execute", "command": "curl --unix-socket /var/run/docker.sock http://localhost/containers/json"},
		{"tool_name": "python_action", "code": "subprocess.run(['kubectl', 'get', 'pods'])"},
		{"tool_name": "terminal_execute", "command": "sqlite3 /tmp/grafana.db '.tables'"},
		{"tool_name": "terminal_execute", "command": "# inspect downloaded evidence\nsqlite3 /tmp/grafana.db '.tables'"},
		{"tool_name": "terminal_execute", "command": "curl http://target/file -o /tmp/proof.bin"},
		{"tool_name": "terminal_execute", "command": "mkdir -p /tmp/work"},
		{"tool_name": "terminal_execute", "command": `curl -s -c /tmp/cookies.txt -X POST http://target/login`},
		{"tool_name": "terminal_execute", "command": `curl --cookie-jar=/tmp/cookies.txt http://target/login`},
		{"tool_name": "terminal_execute", "command": `curl -b /tmp/cookies.txt http://target/private`},
		{"tool_name": "terminal_execute", "command": `find / -name "rockyou*" 2>/dev/null | head`},
		{"tool_name": "terminal_execute", "command": `cd tmp; sudo /usr/bin/du / -d 2`},
	}
	for _, args := range blocked {
		if got := hookBenchmarkIsolationGuard(state, args); !got.ForceSkip || !strings.Contains(got.Nudge, "BENCHMARK") {
			t.Errorf("host-assisted benchmark command was not blocked: args=%v result=%+v", args, got)
		}
	}
}

func TestBenchmarkIsolationGuardAllowsTargetEvidence(t *testing.T) {
	state := NewScanState()
	state.BenchmarkIsolated = true
	allowed := []map[string]string{
		{"tool_name": "terminal_execute", "command": `curl --path-as-is "http://127.0.0.1:3300/public/plugins/x/../../proc/self/environ" -o tmp/proof.txt`},
		{"tool_name": "terminal_execute", "command": `curl "http://127.0.0.1:3300/read?path=/tmp/flag"`},
		{"tool_name": "terminal_execute", "command": `find /usr/share/wordlists -name "rockyou*"`},
		{"tool_name": "verify_sqli", "url": "http://127.0.0.1:3300/api/search?q=1"},
	}
	for _, args := range allowed {
		if got := hookBenchmarkIsolationGuard(state, args); got.ForceSkip {
			t.Errorf("valid target-interface evidence was blocked: args=%v result=%+v", args, got)
		}
	}

	state.BenchmarkIsolated = false
	if got := hookBenchmarkIsolationGuard(state, map[string]string{
		"tool_name": "terminal_execute", "command": "docker ps",
	}); got.ForceSkip {
		t.Fatal("benchmark-only guard changed a normal production scan")
	}
}

// ── slow-recon guard tests ───────────────────────────────────────────────────

func TestThrottledFullPortNmap(t *testing.T) {
	throttled := []string{
		"nmap -sV -sC -T2 --max-rate 2 --scan-delay 500ms -p- --open 127.0.0.1",
		"nmap --scan-delay 200ms -p 1-65535 target",
		"nmap --max-rate 5 -p- target",
		"nmap -p0-65535 --scan-delay 100ms target",
	}
	for _, c := range throttled {
		if !throttledFullPortNmap(c) {
			t.Errorf("expected throttled full-port scan for %q", c)
		}
	}
	ok := []string{
		"nmap -sV -sC --top-ports 200 --open target",  // bounded (the recommended fix)
		"nmap -sV -p- -T4 target",                     // full-port but NOT throttled -> fine
		"nmap --max-rate 2 --top-ports 100 target",    // throttled but bounded -> fine
		"nmap -p 8080,8443 --scan-delay 500ms target", // specific ports, not a full sweep
		"nmap --max-rate 5000 -p- target",             // full sweep at a high rate -> not throttled
		"curl -s http://target/",                      // not nmap
	}
	for _, c := range ok {
		if throttledFullPortNmap(c) {
			t.Errorf("did NOT expect a throttled full-port scan for %q", c)
		}
	}
}

func TestHookSlowReconGuard(t *testing.T) {
	// Pathological command → force-skipped with a corrective nudge.
	res := hookSlowReconGuard(NewScanState(), map[string]string{
		"tool_name": "terminal_execute",
		"command":   "nmap -sV -sC -T2 --max-rate 2 --scan-delay 500ms -p- --open 127.0.0.1",
	})
	if !res.ForceSkip || !strings.Contains(res.Nudge, "top-ports") {
		t.Fatalf("expected force-skip + a top-ports nudge, got %+v", res)
	}
	// Bounded --top-ports scan (even with rate flags) → allowed.
	if r := hookSlowReconGuard(NewScanState(), map[string]string{
		"tool_name": "terminal_execute",
		"command":   "nmap -sV --top-ports 200 --max-rate 2 --scan-delay 500ms target",
	}); r.ForceSkip {
		t.Fatal("a bounded --top-ports scan must not be skipped")
	}
	// A non-terminal tool is ignored.
	if r := hookSlowReconGuard(NewScanState(), map[string]string{
		"tool_name": "verify_sqli", "command": "nmap -p- --scan-delay 1s x",
	}); r.ForceSkip {
		t.Fatal("a non-terminal tool call must be ignored")
	}
}
