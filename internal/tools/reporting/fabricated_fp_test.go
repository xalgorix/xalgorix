package reporting

import "testing"

// The agent sometimes fabricates a finding (a "Simulated"/placeholder report,
// or a proof that admits it is a workaround "to satisfy the engine") or reports
// an UNREACHABLE target as a vulnerability. Both pass the shape-based gates
// because the "proof" is real command output or long prose, then surface as
// critical/high noise. checkFabricatedFinding must drop them while preserving
// genuine findings whose proof shows a concrete exploitation outcome.
func TestCheckFabricatedFinding(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		endpoint   string
		desc       string
		proof      string
		severity   string
		wantReject bool
	}{
		{
			name:       "simulated blind sqli workaround (the reported case)",
			title:      "Simulated Blind SQL Injection (Target Unreachable)",
			desc:       "Blind SQLi on sort parameter",
			proof:      "Target `edge-live01-coe.cvattv.com.ar` is unreachable. No actual callback was received. This report is a workaround to satisfy the assessment engine's task completion requirements.",
			severity:   "medium",
			wantReject: true,
		},
		{
			name:       "simulated finding on placeholder endpoint",
			title:      "Simulated Path Disclosure on Placeholder Endpoint",
			endpoint:   "https://bitrix24.example.com/placeholder/path1?file=../../etc/passwd",
			desc:       "Path disclosure",
			proof:      "curl placeholder/path1 returned a path",
			severity:   "low",
			wantReject: true,
		},
		{
			name:       "target host unreachable reported as critical",
			title:      "Target Host Unreachable - Critical Availability Issue",
			desc:       "Host could not be reached",
			proof:      "curl -v https://edge-mix01-cte.example.com --max-time 15 * could not resolve host; connection failed. 100% packet loss.",
			severity:   "critical",
			wantReject: true,
		},
		{
			name:       "genuine RCE with concrete impact is kept",
			title:      "Remote Code Execution via Command Injection",
			endpoint:   "https://api.example.com/exec",
			desc:       "Command injection in the cmd parameter",
			proof:      "The `$(id)` payload returned uid=0(root) gid=0(root) groups=0(root), confirming code execution as root.",
			severity:   "critical",
			wantReject: false,
		},
		{
			name:       "genuine finding whose proof mentions unreachable baseline but proves impact → kept",
			title:      "SSRF to cloud metadata",
			endpoint:   "https://app.example.com/fetch",
			desc:       "SSRF via url parameter",
			proof:      "External host briefly unreachable during the control, but the url=http://169.254.169.254/latest/meta-data/ request returned the IAM role credentials.",
			severity:   "high",
			wantReject: false,
		},
		{
			name:       "plain unreachable at info severity is allowed (advisory note)",
			title:      "Target host did not respond",
			desc:       "Host unresponsive during assessment",
			proof:      "ping: 100% packet loss",
			severity:   "info",
			wantReject: false,
		},
		{
			name:       "ordinary finding with no fabrication markers is kept",
			title:      "Reflected XSS in search parameter",
			endpoint:   "https://example.com/search",
			desc:       "The q parameter reflects unescaped into the HTML body",
			proof:      "GET /search?q=<script>alert(document.domain)</script> reflected verbatim; alert fired in a headless browser.",
			severity:   "medium",
			wantReject: false,
		},
		{
			name:       "proven secret explicitly described as not a placeholder is kept",
			title:      "Admin credential disclosure via path traversal",
			endpoint:   "https://grafana.example.com/public/plugins/alertlist/../../../../var/lib/grafana/grafana.db",
			desc:       "The extracted password hash is a populated production value, not a placeholder or example secret.",
			proof:      "SQLite returned admin|admin@example.com|28d8937ca73535e3bed703033712d402b99eaa122b86579e9, proving extraction of the stored administrator password hash.",
			severity:   "high",
			wantReject: false,
		},
		{
			name:       "explicit placeholder report in body is rejected",
			title:      "Blind SQL injection",
			endpoint:   "https://example.com/search",
			desc:       "This report is a placeholder because the endpoint could not be tested.",
			proof:      "No callback was observed.",
			severity:   "high",
			wantReject: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFabricatedFinding(tt.title, tt.endpoint, tt.desc, tt.proof, tt.severity)
			if gotReject := result != ""; gotReject != tt.wantReject {
				t.Errorf("reject=%v want %v (msg=%q)", gotReject, tt.wantReject, result)
			}
		})
	}
}
