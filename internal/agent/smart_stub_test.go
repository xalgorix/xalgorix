package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// A smart stub must keep security-relevant lines that sit PAST the 300-byte head
// a head-only stub would have kept — this is the coverage fix.
func TestExtractSecuritySignal_KeepsBuriedEvidenceWithinBudget(t *testing.T) {
	head := strings.Repeat("ordinary benign output line here\n", 30) // ~990 B of noise
	sqlErr := "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given"
	secret := "authorization: Bearer sk-live-ABCDEF1234567890"
	content := head + sqlErr + "\n" + secret + "\n" + strings.Repeat("tail noise line\n", 30)

	// Precondition: the evidence really is past the old head-only window.
	if strings.Contains(trimToValidUTF8(content, archiveHeadBytes), "mysql_fetch_array") {
		t.Fatal("test setup: evidence must sit past archiveHeadBytes to be meaningful")
	}

	got := extractSecuritySignal(content, archiveSmartStubBytes)
	if len(got) > archiveSmartStubBytes {
		t.Fatalf("excerpt %d bytes exceeds budget %d", len(got), archiveSmartStubBytes)
	}
	for _, want := range []string{"mysql_fetch_array", "Bearer sk-live-ABCDEF1234567890"} {
		if !strings.Contains(got, want) {
			t.Errorf("excerpt dropped %q; got:\n%s", want, got)
		}
	}
}

// With no security markers, the fallback keeps a plain head that is still larger
// than the old 300-byte head-only stub, so a smart stub is never worse.
func TestExtractSecuritySignal_FallsBackToLargerHead(t *testing.T) {
	content := strings.Repeat("completely benign content with nothing notable at all\n", 100)
	got := extractSecuritySignal(content, archiveSmartStubBytes)
	if len(got) == 0 {
		t.Fatal("fallback must return a non-empty head")
	}
	if len(got) > archiveSmartStubBytes {
		t.Fatalf("fallback %d bytes exceeds budget %d", len(got), archiveSmartStubBytes)
	}
	if len(got) <= archiveHeadBytes {
		t.Fatalf("fallback head (%d) should exceed archiveHeadBytes (%d)", len(got), archiveHeadBytes)
	}
}

func TestLineHasSecuritySignal(t *testing.T) {
	hits := []string{
		"You have an error in your SQL syntax near X",
		"ORA-01756: quoted string not properly terminated",
		"HTTP/1.1 500 Internal Server Error",
		"Set-Cookie: session=abc; HttpOnly",
		"<script>alert(1)</script>",
		"aws_secret_access_key = AKIAEXAMPLE",
		"root:x:0:0:root:/root:/bin/bash",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0",
	}
	for _, h := range hits {
		if !lineHasSecuritySignal(h) {
			t.Errorf("expected security signal for %q", h)
		}
	}
	misses := []string{"", "just some words", "the quick brown fox jumps over"}
	for _, m := range misses {
		if lineHasSecuritySignal(m) {
			t.Errorf("unexpected security signal for %q", m)
		}
	}
}

// End-to-end: with the flag on, an aged-out tool result is stubbed AND the
// buried evidence survives in the stub; the recent window stays verbatim.
func TestAgeOutToolOutputs_SmartStubKeepsBuriedEvidence(t *testing.T) {
	cfg := &config.Config{
		BoundedContext:          true,
		ToolArchiveSmartStub:    true,
		ToolArchiveActiveWindow: 1,
	}
	sctx := scanctx.New("smart-stub-test", t.TempDir())
	scanctx.Activate(sctx)
	t.Cleanup(sctx.Close)
	a := NewAgent(cfg, "test", make(chan Event, 8), scopeguard.Config{}, sctx)

	filler := strings.Repeat("GET /page benign line no signal\n", 60) // push evidence past the head
	evidence := "You have an error in your SQL syntax near ''1''' at line 1"
	old := toolResultMsg("send_request", filler+evidence+"\n"+strings.Repeat("trailing\n", 40))
	old.Content += "\n" + archiveToolResultMarker("to_000042")
	newer := toolResultMsg("send_request", "fresh verbatim result")

	a.msgMu.Lock()
	a.messages = []llm.Message{{Role: "system", Content: "sys"}, old, newer}
	a.msgMu.Unlock()

	a.ageOutToolOutputs()

	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	stub := a.messages[1].Content
	if !strings.Contains(stub, archiveStubPrefix) {
		t.Fatalf("aged-out tool result must be stubbed; got:\n%s", stub)
	}
	if !strings.Contains(stub, "SQL syntax") {
		t.Fatalf("smart stub dropped the buried SQL error; got:\n%s", stub)
	}
	if a.messages[2].Content != newer.Content {
		t.Fatal("recent (in-window) tool result must stay verbatim")
	}
}
