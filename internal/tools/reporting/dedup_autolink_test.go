package reporting

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// newTestLedgerCtx creates an active in-memory scan context with a ledger.
func newTestLedgerCtx(t *testing.T) (*scanctx.ScanContext, string) {
	t.Helper()
	id := "dedup-autolink-test-" + t.Name()
	ctx := scanctx.New(id, "")
	scanctx.Activate(ctx)
	t.Cleanup(func() { scanctx.Deactivate(id) })
	return ctx, id
}

// TestDedupTitleFirstExtractionStopsProsePoisoning (P4): the pentest-ground
// scan stored the SAME /eval eval() RCE twice. The first report's
// description mentioned SQL context ("read of the SQLite database..."),
// so keyword extraction classified the RCE as "sqli" and the later "rce"
// report slipped past the same-type gate. Title-first extraction fixes the
// label; the cross-type root-cause rule is the backstop.
func TestDedupTitleFirstExtractionStopsProsePoisoning(t *testing.T) {
	existing := []Vulnerability{{
		ID:       "XALG-3",
		Title:    "Unauthenticated Python eval() RCE on /eval?s= — file read + OS command execution as root",
		Target:   "https://pentest-ground.com:9000",
		Endpoint: "https://pentest-ground.com:9000/eval?s=<expr>",
		Description: "The /eval endpoint evaluates the s query parameter via Python eval(). " +
			"__import__('os').popen('id').read() returned uid=0(root); open('/etc/passwd').read() dumped the file; " +
			"the same request also read of the SQLite database used by the tokens endpoint.",
		Verified: true,
	}}

	// The exact production shape of the later duplicate report.
	v, msg, dup := findDuplicateVulnerability(existing,
		"Unauthenticated Remote Code Execution via /eval?s=  (Python eval() injection as root)",
		"GET /eval passes the s query parameter directly to Python eval(); full arbitrary code execution as root.",
		"", "", "https://pentest-ground.com:9000", "https://pentest-ground.com:9000/eval")
	if !dup {
		t.Fatalf("LEAK: the same eval() RCE was not detected as a duplicate (type=%q existing=%q)",
			extractVulnType(existing[0].Title, existing[0].Description),
			extractVulnType("Unauthenticated Remote Code Execution via /eval?s= (Python eval() injection as root)", "GET /eval eval()"))
	}
	if !strings.Contains(msg, "XALG-3") {
		t.Errorf("duplicate message should name the existing finding: %q", msg)
	}
	_ = v
}

// TestDedupCrossTypeCodeExecutionRootCause (P4 backstop): even when BOTH
// titles lack an extractable class label and prose poisons one side's type,
// two reports with concrete code-execution language on the same endpoint
// are the same root cause.
func TestDedupCrossTypeCodeExecutionRootCause(t *testing.T) {
	existing := []Vulnerability{{
		ID:       "XALG-9",
		Title:    "Arbitrary expression evaluation on /eval",
		Target:   "https://pentest-ground.com:9000",
		Endpoint: "https://pentest-ground.com:9000/eval",
		Description: "eval() evaluates the parameter. " +
			"This executes commands: __import__('os').system('id') runs as root (uid=0).",
		Verified: true,
	}}
	_, _, dup := findDuplicateVulnerability(existing,
		"Unauthenticated remote code execution via eval",
		"Python eval() runs arbitrary code; command execution as root confirmed.",
		"", "", "https://pentest-ground.com:9000", "/eval")
	if !dup {
		t.Fatal("cross-type code-execution root cause not detected on the same endpoint")
	}

	// A genuine NON-code-execution finding on the same endpoint is NOT
	// collapsed (e.g. a separate SQLi on the same path).
	_, _, dup = findDuplicateVulnerability(existing,
		"SQL Injection in the s parameter of /eval",
		"The s parameter is concatenated into a SQLite query; UNION SELECT extracts the users table.",
		"", "", "https://pentest-ground.com:9000", "/eval")
	if dup {
		t.Fatal("a genuine SQLi on the same endpoint must not be collapsed with the code-execution finding")
	}
}

// TestAutoLinkFindingToLedgerHypotheses (P3): a proven lead without a
// finding reference is auto-linked when a just-reported finding matches its
// class family and endpoint — the model forgot the hypothesis_id on the
// pentest-ground scan and the precision gate stranded H-21/H-57/H-7 at
// exhaustion.
func TestAutoLinkFindingToLedgerHypotheses(t *testing.T) {
	ctx, id := newTestLedgerCtx(t)
	_ = ctx

	proven := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "eval() executes python on /eval", VulnClass: "rce", Endpoint: "https://pentest-ground.com:9000/eval?s=x",
		Status: scanctx.HypothesisProven,
	})
	mismatchClass := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "SQLi on /tokens", VulnClass: "sqli", Endpoint: "https://pentest-ground.com:9000/tokens",
		Status: scanctx.HypothesisProven,
	})
	mismatchEndpoint := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "RCE elsewhere", VulnClass: "rce", Endpoint: "https://pentest-ground.com:9000/uptime/x",
		Status: scanctx.HypothesisProven,
	})
	testingClaim := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "eval() in-flight claim", VulnClass: "cmdi", Endpoint: "/eval",
		Status: scanctx.HypothesisTesting,
	})

	vuln := Vulnerability{
		ID: "XALG-5", Title: "Unauthenticated Remote Code Execution via /eval (Python eval() injection as root)",
		Target: "https://pentest-ground.com:9000", Endpoint: "https://pentest-ground.com:9000/eval",
	}
	note := autoLinkFindingToLedgerHypotheses(id, vuln, "rce")
	if note == "" {
		t.Fatal("expected proven rce hypothesis on /eval to auto-link")
	}
	if !strings.Contains(note, proven.ID) {
		t.Errorf("auto-link note %q should name %s", note, proven.ID)
	}
	linked, ok := ctx.Ledger.Get(proven.ID)
	if !ok || !hypothesisHasFindingLink(linked) {
		t.Fatalf("hypothesis %s was not linked to the finding", proven.ID)
	}
	// The in-flight cmdi claim on the same endpoint also settles (class
	// family rce covers cmdi).
	if !strings.Contains(note, testingClaim.ID) {
		t.Errorf("in-flight cmdi claim %s on /eval should auto-link too: %q", testingClaim.ID, note)
	}
	// Class mismatch and endpoint mismatch are NOT linked.
	if strings.Contains(note, mismatchClass.ID) {
		t.Errorf("sqli hypothesis on /tokens must not link to an rce finding: %q", note)
	}
	if strings.Contains(note, mismatchEndpoint.ID) {
		t.Errorf("rce hypothesis on a different endpoint must not link: %q", note)
	}
}

// TestAutoLinkUnambiguousEndpointlessCandidate: an endpoint-less proven
// hypothesis links only when it is the single family candidate.
func TestAutoLinkUnambiguousEndpointlessCandidate(t *testing.T) {
	ctx, id := newTestLedgerCtx(t)
	solo := ctx.Ledger.Upsert(scanctx.Hypothesis{
		Title: "csrf lead, no endpoint recorded", VulnClass: "csrf", Status: scanctx.HypothesisProven,
	})
	vuln := Vulnerability{ID: "XALG-7", Title: "Cross-Site Request Forgery on logout",
		Target: "https://t.example", Endpoint: "https://t.example/logout"}
	note := autoLinkFindingToLedgerHypotheses(id, vuln, "csrf")
	if !strings.Contains(note, solo.ID) {
		t.Fatalf("single unambiguous candidate should auto-link: %q", note)
	}

	// Two candidates → ambiguity → no auto-link.
	ctx2, id2 := newTestLedgerCtx(t)
	ctx2.Ledger.Upsert(scanctx.Hypothesis{Title: "csrf a", VulnClass: "csrf", Parameter: "a", Status: scanctx.HypothesisProven})
	ctx2.Ledger.Upsert(scanctx.Hypothesis{Title: "csrf b", VulnClass: "csrf", Parameter: "b", Status: scanctx.HypothesisProven})
	if note := autoLinkFindingToLedgerHypotheses(id2, vuln, "csrf"); note != "" {
		t.Fatalf("ambiguous endpointless candidates must not auto-link: %q", note)
	}
}
