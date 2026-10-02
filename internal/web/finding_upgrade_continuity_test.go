package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func upgradeContinuityRows() (VulnSummary, VulnSummary, VulnSummary) {
	candidate := VulnSummary{ID: "XALG-4", SourceScanID: "physical-run", Title: "Reflected XSS candidate", Target: "https://example.invalid", Endpoint: "/search?q=first", Method: "GET"}
	verified := VulnSummary{ID: "XALG-4", SourceScanID: "physical-run", Title: "Verified reflected XSS", Target: "https://example.invalid", Endpoint: "/search?q=proven", Method: "browser", CWE: "CWE-79", Verified: true}
	unrelated := VulnSummary{ID: "XALG-4", SourceScanID: "physical-run", Title: "SQL injection", Target: "https://example.invalid", Endpoint: "/account", Method: "POST"}
	return candidate, verified, unrelated
}

func TestUpgradeReceiptPreventsStaleSnapshotReinsertion(t *testing.T) {
	candidate, verified, unrelated := upgradeContinuityRows()
	verified.Replaces = reporting.IdentityForFinding(vulnFromSummary(candidate))
	rows := []VulnSummary{verified, unrelated}
	if appendVulnSummaryUnique(&rows, candidate) || len(rows) != 2 {
		t.Fatal("stale snapshot reinserted a retired candidate")
	}
	s := newTestServer(t, nil)
	s.instances["upgrade-overlay"] = &ScanInstance{ID: "upgrade-overlay", Vulns: []VulnSummary{candidate}}
	rec := &ScanRecord{ID: "physical-run", InstanceID: "upgrade-overlay", Vulns: rows}
	s.applyInstanceSnapshot(rec, false)
	if len(rec.Vulns) != 2 || rec.Vulns[0].Replaces == nil {
		t.Fatal("instance overlay resurrected the stale candidate or lost its receipt")
	}
}

func TestLegacyUpgradeReceiptPreservesAmbiguousCandidates(t *testing.T) {
	candidate, verified, _ := upgradeContinuityRows()
	second := candidate
	second.Title = "Another reflected XSS candidate"
	rows := []VulnSummary{candidate, second}
	applySummaryReplacement(&rows, &verified, true)
	if len(rows) != 2 || verified.Replaces != nil {
		t.Fatal("ambiguous legacy receipt retired a candidate without exact evidence")
	}
}

func TestRotatedUpgradeReceiptRepairsPhysicalAndExactSnapshots(t *testing.T) {
	s := newTestServer(t, nil)
	candidate, verified, unrelated := upgradeContinuityRows()
	dir := s.makeScanDir("example.invalid")
	rec := &ScanRecord{ID: candidate.SourceScanID, InstanceID: "upgrade-journal-instance", Target: candidate.Target, Status: "finished",
		Vulns: []VulnSummary{candidate, verified, unrelated}}
	s.saveScanRecordTo(rec, dir)
	if err := prepareScanEventJournal(dir, rec, false); err != nil {
		t.Fatal(err)
	}
	event := WSEvent{EventID: "upgrade:1", Type: "tool_result", ToolName: "report_vulnerability", ResultMeta: map[string]any{"upgraded": true}, Vulns: []VulnSummary{verified}}
	if err := appendScanEventJournal(dir, event); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < detailEventTail+1; i++ {
		if err := appendScanEventJournal(dir, WSEvent{Type: "message", Content: "later event"}); err != nil {
			t.Fatal(err)
		}
	}
	s.saveScanRecordTo(rec, dir)
	exact := *rec
	exact.ID = rec.InstanceID
	exact.Vulns = append([]VulnSummary(nil), rec.Vulns...)
	if err := s.saveExactDispatchSnapshot(&exact); err != nil {
		t.Fatal(err)
	}
	s.reconcileSavedFindingUpgrades(rec, dir)
	if len(rec.Vulns) != 2 || rec.Vulns[0].Replaces == nil {
		t.Fatal("physical recovery lost the rotated upgrade receipt")
	}
	_, recovered := s.findScanByInstanceID(exact.InstanceID)
	if recovered == nil || len(recovered.Vulns) != 2 || recovered.Vulns[0].Replaces == nil {
		t.Fatal("exact snapshot retained the candidate after journal recovery")
	}
	s.rebuildInstancesFromDisk()
	if inst := s.instances[exact.InstanceID]; inst == nil || len(inst.Vulns) != 2 {
		t.Fatal("restart reconstruction retained the retired candidate")
	}
}

func TestSummaryEnrichmentRetainsVerifiedEvidence(t *testing.T) {
	candidate, verified, _ := upgradeContinuityRows()
	verified.Title, verified.Endpoint, verified.Method = candidate.Title, candidate.Endpoint, candidate.Method
	verified.ExploitationProof, verified.Severity = "reproduced script execution", "high"
	rows := []VulnSummary{candidate}
	appendVulnSummaryUnique(&rows, verified)
	if len(rows) != 1 || !rows[0].Verified || rows[0].ExploitationProof != verified.ExploitationProof {
		t.Fatal("semantic deduplication discarded a verified evidence upgrade")
	}
}

func TestVerifiedUpgradeRetiresCandidateFromCoordinator(t *testing.T) {
	s := newTestServer(t, nil)
	candidate, verified, unrelated := upgradeContinuityRows()
	inst := &ScanInstance{ID: "upgrade-coordinator", Status: "running", Vulns: []VulnSummary{candidate, unrelated}}
	s.instances[inst.ID] = inst
	s.broadcastToInstance(inst.ID, WSEvent{Type: "tool_result", ToolName: "report_vulnerability", ResultMeta: map[string]any{"upgraded": true, "vuln_id": "XALG-4"}, Vulns: []VulnSummary{verified}})
	if len(inst.Vulns) != 2 {
		t.Fatalf("upgrade retained a stale candidate: %d rows", len(inst.Vulns))
	}
	for _, row := range inst.Vulns {
		if row.Title == candidate.Title {
			t.Fatal("coordinator retained the replaced candidate")
		}
	}
	if inst.Vulns[0].Title != unrelated.Title && inst.Vulns[1].Title != unrelated.Title {
		t.Fatal("upgrade removed an unrelated historical ID collision")
	}
}
