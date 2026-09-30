package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// TestRemoveVulnSummariesByID (P6 unit): the record-row purge removes every
// row carrying the upgraded finding ID and keeps the rest in order.
func TestRemoveVulnSummariesByID(t *testing.T) {
	rows := []VulnSummary{
		{ID: "XALG-1", Title: "first"},
		{ID: "XALG-9", Title: "stale candidate"},
		{ID: "XALG-10", Title: "unrelated"},
		{ID: "XALG-9", Title: "stale duplicate"},
	}
	removeVulnSummariesByID(&rows, "XALG-9")
	if len(rows) != 2 || rows[0].ID != "XALG-1" || rows[1].ID != "XALG-10" {
		t.Fatalf("purge kept wrong rows: %+v", rows)
	}
	removeVulnSummariesByID(&rows, "")
	if len(rows) != 2 {
		t.Fatal("empty id must be a no-op")
	}
	removeVulnSummariesByID(&rows, "XALG-missing")
	if len(rows) != 2 {
		t.Fatal("missing id must be a no-op")
	}
}

// TestMetadataBool (P6 unit): bool and "true" string metadata both read as
// true; anything else as false.
func TestMetadataBool(t *testing.T) {
	if !metadataBool(map[string]any{"upgraded": true}, "upgraded") {
		t.Error("bool true must read as true")
	}
	if !metadataBool(map[string]any{"upgraded": "true"}, "upgraded") {
		t.Error("string true must read as true")
	}
	if metadataBool(map[string]any{"upgraded": false}, "upgraded") ||
		metadataBool(map[string]any{"upgraded": "false"}, "upgraded") ||
		metadataBool(map[string]any{}, "upgraded") ||
		metadataBool(map[string]any{"upgraded": 1}, "upgraded") {
		t.Error("false/absent/non-bool values must read as false")
	}
}

// TestProcessEventUpgradedReportReplacesRecordRow (P6): when the reporting
// store replaces an unverified candidate IN PLACE (same finding ID), the
// scan record must mirror the replacement. The v4.6.123 pentest-ground run
// stored two distinct findings under the same ID (XALG-9) because the live
// record appended the upgrade instead of replacing the stale candidate.
func TestProcessEventUpgradedReportReplacesRecordRow(t *testing.T) {
	s := newTestServer(t, nil)
	ctxID := "web-upgrade-record-" + t.Name()
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	t.Cleanup(func() {
		scanctx.Deactivate(ctxID)
		reporting.ResetVulnerabilitiesForContext(ctxID)
	})
	sess := &scanSession{
		id:      "upg-rec",
		target:  "https://example.com",
		scanDir: t.TempDir(),
		record:  &ScanRecord{ID: "upg-rec", Target: "https://example.com", Status: "running"},
		sctx:    sc,
		server:  s,
	}

	confirmed := false
	reg := tools.NewRegistry()
	reg.SetScanContextID(ctxID)
	reporting.RegisterWithVerifier(reg, func(reporting.VerificationRequest) reporting.VerificationVerdict {
		if confirmed {
			return reporting.VerificationVerdict{Confirmed: true, Reason: "reproduced", Evidence: "extracted admin records"}
		}
		return reporting.VerificationVerdict{Inconclusive: true}
	})

	baseArgs := func(title, proof string) map[string]string {
		return map[string]string{
			"title":               title,
			"severity":            "high",
			"description":         "Union-based SQL injection allows extraction of user records from the login endpoint.",
			"exploitation_proof":  proof,
			"verification_method": "data_extracted",
			"impact":              "Unauthorized attackers can extract sensitive user data.",
			"target":              "https://example.com",
			"endpoint":            "https://example.com/login?id=1",
			"method":              "GET",
			"cvss":                "7.5",
			"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		}
	}

	// 1) The unverified candidate lands in the record: weak proof, and the
	// verifier cannot reproduce it within its budget.
	res1, err := reg.Execute("report_vulnerability", baseArgs(
		"SQL Injection in Login Endpoint",
		"a single quote in the id parameter returned a 500 database error; data extraction not yet demonstrated"))
	if err != nil {
		t.Fatal(err)
	}
	if res1.Metadata == nil {
		t.Fatalf("candidate report failed: %s", res1.Output)
	}
	if res1.Metadata["verified"] == true {
		t.Fatalf("fixture requires an unverified candidate, got verified=true (%s)", res1.Output)
	}
	s.processEvent(agent.Event{
		Type: "tool_result", ToolName: "report_vulnerability",
		ToolResult: tools.Result{Output: res1.Output, Metadata: res1.Metadata},
	}, sess)
	if len(sess.record.Vulns) != 1 {
		t.Fatalf("candidate row missing: %+v", sess.record.Vulns)
	}
	firstID := sess.record.Vulns[0].ID
	if firstID == "" {
		t.Fatal("candidate row carries no finding ID")
	}

	// 2) The verified upgrade (same class, same endpoint/title) replaces
	// the candidate IN PLACE — same finding ID, upgraded=true metadata.
	confirmed = true
	res2, err := reg.Execute("report_vulnerability", baseArgs(
		"SQL Injection in Login Endpoint (verified upgrade)",
		"sql injection data extraction confirmed; dumped user data including email address records from database"))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Metadata == nil || res2.Metadata["upgraded"] != true {
		t.Fatalf("expected an in-place upgrade result, got metadata=%v output=%s", res2.Metadata, res2.Output)
	}
	if id2, _ := metadataString(res2.Metadata, "vuln_id"); id2 != firstID {
		t.Fatalf("upgrade must retain the candidate ID: %q vs %q", id2, firstID)
	}
	s.processEvent(agent.Event{
		Type: "tool_result", ToolName: "report_vulnerability",
		ToolResult: tools.Result{Output: res2.Output, Metadata: res2.Metadata},
	}, sess)

	// 3) The record mirrors the store: ONE row with the upgraded title.
	rows := 0
	var kept VulnSummary
	for _, v := range sess.record.Vulns {
		if v.ID == firstID {
			rows++
			kept = v
		}
	}
	if rows != 1 {
		t.Fatalf("record must carry exactly one row for %s after the upgrade, got %d: %+v",
			firstID, rows, sess.record.Vulns)
	}
	if kept.Title != "SQL Injection in Login Endpoint (verified upgrade)" {
		t.Errorf("record row was not replaced with the upgrade: %+v", kept)
	}
}
