package agent

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// The compact checklist trims scripts and prose but must keep the full
// checklist's actual methodology: every phase, every deterministic verifier,
// every registered and external tool, and every vulnerability class. This test
// derives the required vocabulary FROM defaultChecklist, so a term added to the
// full checklist later is automatically required of the compact one too.

func compactAndFull(t *testing.T) (compact, full string) {
	t.Helper()
	full = defaultChecklist
	compact = compactChecklist
	if full == "" || compact == "" {
		t.Fatal("checklist constants are empty")
	}
	return compact, full
}

func TestCompactChecklistKeepsEveryPhase(t *testing.T) {
	compact, full := compactAndFull(t)
	phase := regexp.MustCompile(`(?m)^### PHASE (\d+)`)
	fullPhases := phase.FindAllStringSubmatch(full, -1)
	if len(fullPhases) != 22 {
		t.Fatalf("expected 22 phases in the full checklist, found %d", len(fullPhases))
	}
	compactPhases := map[string]bool{}
	for _, m := range phase.FindAllStringSubmatch(compact, -1) {
		compactPhases[m[1]] = true
	}
	for _, m := range fullPhases {
		if !compactPhases[m[1]] {
			t.Errorf("compact checklist is missing PHASE %s", m[1])
		}
	}
	if len(compactPhases) != 22 {
		t.Errorf("compact checklist has %d phases, want 22", len(compactPhases))
	}
}

func TestCompactChecklistKeepsVocabulary(t *testing.T) {
	compact, full := compactAndFull(t)

	// Terms that must survive compaction. Each regex is required to match the
	// full checklist (so the list can't rot) and the compact one.
	required := []string{
		// Deterministic verifiers and the authz matrix.
		`verify_sqli`, `verify_xss`, `verify_ssti`, `verify_xxe`, `verify_csrf`,
		`verify_oob`, `verify_timing`, `verify_path_traversal`, `authz_matrix`,
		// Registered engine tools.
		`report_vulnerability`, `read_skill`, `add_note`, `read_notes`,
		`browser_action`, `agentmail`, `send_request`, `list_requests`,
		// External tools the methodology depends on.
		`nuclei`, `ffuf`, `sqlmap`, `dalfox`, `subfinder`, `httpx`, `katana`,
		`gau`, `waymore`, `waybackurls`, `paramspider`, `arjun`, `nmap`,
		`whatweb`, `wafw00f`, `wpscan`, `joomscan`, `droopescan`, `feroxbuster`,
		`dirsearch`, `subjack`, `dnsx`, `theHarvester`, `gospider`, `hakrawler`,
		// Vulnerability classes / techniques.
		`SQLi`, `XSS`, `SSTI`, `SSRF`, `IDOR`, `BOLA`, `XXE`, `CSRF`,
		`command injection`, `path traversal`, `NoSQL`, `CRLF`,
		`request smuggling`, `cache poisoning`, `deserialization`,
		`prototype pollution`, `jndi`, `[Jj][Ww][Tt]`, `OAuth`, `GraphQL`,
		`subdomain takeover`, `open redirect`, `file upload`, `race condition`,
		`mass assignment`, `WebSocket`, `CORS`,
		// Cloud metadata SSRF target and the auth-matrix CWE.
		`169\.254\.169\.254`, `CWE-639`,
		// Rate-policy placeholders the rate rewriter substitutes.
		`RATE_LIMIT`, `RATE_DELAY`,
		// Evidence discipline that keeps findings honest.
		`exploitation_proof`, `DEDUPLICATION`, `read-only`,
	}

	var missingFull, missingCompact []string
	for _, pat := range required {
		re := regexp.MustCompile("(?i)" + pat)
		if !re.MatchString(full) {
			missingFull = append(missingFull, pat)
		}
		if !re.MatchString(compact) {
			missingCompact = append(missingCompact, pat)
		}
	}
	sort.Strings(missingFull)
	sort.Strings(missingCompact)
	if len(missingFull) > 0 {
		t.Fatalf("required terms not found in the FULL checklist (update this test): %v", missingFull)
	}
	if len(missingCompact) > 0 {
		t.Fatalf("compact checklist dropped required terms: %v", missingCompact)
	}
}

func TestCompactChecklistIsSmallerButWhole(t *testing.T) {
	compact, full := compactAndFull(t)
	if len(compact) >= len(full) {
		t.Fatalf("compact checklist (%d) is not smaller than full (%d)", len(compact), len(full))
	}
	// It is meant to roughly halve the checklist; guard against it silently
	// collapsing to the professional checklist's size or ballooning back.
	ratio := float64(len(compact)) / float64(len(full))
	if ratio < 0.15 || ratio > 0.55 {
		t.Fatalf("compact/full size ratio %.2f is outside the intended 0.15–0.55 band (compact %d, full %d)", ratio, len(compact), len(full))
	}
	if strings.Contains(compact, "`") {
		t.Fatal("compact checklist contains a backtick, which would break the Go raw string literal")
	}
}

// The mode must be reachable end to end: config normalization keeps "compact",
// and buildSystemPrompt then uses compactChecklist rather than the full one.
func TestCompactChecklistSelectedByConfig(t *testing.T) {
	if got := config.NormalizeChecklist("compact"); got != "compact" {
		t.Fatalf("NormalizeChecklist(\"compact\") = %q, want \"compact\"", got)
	}
	if got := config.NormalizeChecklist("COMPACT"); got != "compact" {
		t.Fatalf("NormalizeChecklist is case-sensitive: got %q", got)
	}

	full := playbookTestAgent(t, &config.Config{Checklist: "full"})
	full.nativeToolCalling = true
	compact := playbookTestAgent(t, &config.Config{Checklist: "compact"})
	compact.nativeToolCalling = true

	fullPrompt := full.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)
	compactPrompt := compact.buildSystemPrompt([]string{"https://example.test"}, "", playbookTestPolicy)

	if len(compactPrompt) >= len(fullPrompt) {
		t.Fatalf("compact system prompt (%d) is not smaller than full (%d)", len(compactPrompt), len(fullPrompt))
	}
	// A distinctive line that exists only in the full checklist's inline script
	// (dropped by the compact rewrite) confirms the compact path was taken.
	if strings.Contains(compactPrompt, "ssrf_params = [") {
		t.Fatal("compact prompt still contains the full checklist's inline SSRF script")
	}
	if !strings.Contains(compactPrompt, "### PHASE 22") {
		t.Fatal("compact prompt lost PHASE 22")
	}
}
