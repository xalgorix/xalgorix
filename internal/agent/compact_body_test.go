package agent

import (
	"regexp"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func compactAgentPrompt(t *testing.T, mode string) string {
	t.Helper()
	a := playbookTestAgent(t, &config.Config{Checklist: mode})
	a.nativeToolCalling = true
	return a.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
}

// The compact body consolidates the reporting run but must not drop any rule.
// Each required token is checked against the FULL prompt too, so the list can't
// rot, and against the COMPACT prompt, so a dropped rule fails the build.
func TestCompactBodyKeepsReportingRules(t *testing.T) {
	full := compactAgentPrompt(t, "full")
	compact := compactAgentPrompt(t, "compact")

	required := []string{
		// Real-time reporting and the literal tool-call requirement.
		`report_vulnerability`, `(?i)real-time`, `<function=report_vulnerability>`,
		// Chaining and per-endpoint/role breadth.
		`(?i)chain`, `IDOR`, `(?i)open redirect`, `(?i)every role|EVERY role`,
		// What NOT to report (INFO-only items).
		`X-Frame-Options`, `Content-Security-Policy`, `TRACE`, `HttpOnly`, `SPF`,
		`(?i)self-XSS`, `(?i)weak TLS|weak ciphers`,
		// Severity bands and score ranges.
		`CRITICAL`, `HIGH`, `MEDIUM`, `\bLOW\b`, `\bINFO\b`,
		`9\.0-10\.0`, `7\.0-8\.9`, `4\.0-6\.9`, `0\.1-3\.9`,
		// CVSS vector requirement and the error-based SQLi anchor.
		`CVSS:3\.1/AV`, `(?i)error-based`, `7\.5`,
		// Fabrication guards.
		`(?i)UNREACHABLE`, `(?i)placeholder`, `(?i)empty findings`,
		// Proof integrity.
		`(?i)byte-for-byte`, `(?i)never invent`, `exploitation_proof`,
		// WAF bypass techniques.
		`(?i)double`, `X-Forwarded-For`, `(?i)time-based`, `Content-Type`,
		`(?i)null byte`, `(?i)case variation|SeLeCt`,
	}

	var missFull, missCompact []string
	for _, pat := range required {
		re := regexp.MustCompile(pat)
		if !re.MatchString(full) {
			missFull = append(missFull, pat)
		}
		if !re.MatchString(compact) {
			missCompact = append(missCompact, pat)
		}
	}
	if len(missFull) > 0 {
		t.Fatalf("required tokens missing from the FULL prompt (update this test): %v", missFull)
	}
	if len(missCompact) > 0 {
		t.Fatalf("compact body dropped required rule tokens: %v", missCompact)
	}
}

func TestCompactBodyIsSmallerAndCoreKept(t *testing.T) {
	full := compactAgentPrompt(t, "full")
	compact := compactAgentPrompt(t, "compact")

	// The consolidation must have actually happened: the eight original
	// sub-headers collapse to the single consolidated header.
	for _, gone := range []string{
		"### HackerOne Severity Classification",
		"### CVSS Vector String (REQUIRED with every report)",
		"### PROOF-INTEGRITY RULE",
		"### WAF Bypass Rules (MANDATORY)",
	} {
		if strings.Contains(compact, gone) {
			t.Errorf("compact body still contains the un-consolidated header %q", gone)
		}
		if !strings.Contains(full, gone) {
			t.Errorf("full prompt no longer has %q — update this test", gone)
		}
	}
	if !strings.Contains(compact, "### Reporting & proof rules") {
		t.Fatal("compact body is missing the consolidated reporting block")
	}
	// The core proof bar before the consolidated run is preserved verbatim.
	if !strings.Contains(compact, "### EVIDENCE STANDARD — WHAT COUNTS AS PROOF") {
		t.Fatal("compact body dropped the core EVIDENCE STANDARD block")
	}
	// Safety/authorization text is untouched.
	for _, keep := range []string{"## ENGAGEMENT AUTHORIZATION", "## TARGET SCOPE", "### Safety Rules"} {
		if !strings.Contains(compact, keep) {
			t.Errorf("compact body dropped safety section %q", keep)
		}
	}
	if len(compact) >= len(full) {
		t.Fatalf("compact prompt (%d) is not smaller than full (%d)", len(compact), len(full))
	}
}

// applyCompactBody is a no-op when the reporting markers are absent (e.g. a
// future body rewrite), so it can never panic or mangle an unexpected prompt.
func TestApplyCompactBodyNoopWithoutMarkers(t *testing.T) {
	const s = "## Some Prompt\nno reporting run here\n"
	if got := applyCompactBody(s); got != s {
		t.Fatalf("applyCompactBody changed a prompt with no reporting run:\n%s", got)
	}
}

// Compact mode must load skills lazily and one at a time — not preload a batch
// of recon skills up front (each skill is ~2.3K tokens).
func TestCompactModeLoadsSkillsLazily(t *testing.T) {
	full := compactAgentPrompt(t, "full")
	compact := compactAgentPrompt(t, "compact")

	// The full checklist's eager "Load reconnaissance skills FIRST: read_skill(
	// api-discovery), read_skill(javascript-analysis), read_skill(...)" batch
	// must NOT survive in compact. Detect a 3-in-a-row read_skill preload.
	batch := regexp.MustCompile(`read_skill\(name="[^"]+"\),\s*read_skill\(name="[^"]+"\),\s*read_skill\(name="[^"]+"\)`)
	if batch.MatchString(compact) {
		t.Error("compact prompt still preloads a batch of recon skills; it should load one at a time on a live signal")
	}
	// The lazy guidance must be present, and read_skill must still be taught.
	if !regexp.MustCompile(`(?i)load (a skill|one|at most the one).{0,40}(only|when|most relevant)`).MatchString(compact) {
		t.Error("compact prompt is missing the load-selectively guidance")
	}
	if !strings.Contains(compact, "read_skill") {
		t.Error("compact prompt no longer teaches read_skill at all")
	}
	// Sanity: the full prompt DID carry the eager batch (so this test tracks a
	// real difference, not a vacuous one).
	if !batch.MatchString(full) {
		t.Skip("full checklist no longer has the eager recon-skill batch; lazy test is moot")
	}
}
