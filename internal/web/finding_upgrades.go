package web

import (
	"log"
	"os"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func summaryIsReplaced(candidate, incoming VulnSummary) bool {
	ref := incoming.Replaces
	if ref == nil || !incoming.Verified || candidate.Verified || incoming.SourceScanID == "" || candidate.SourceScanID != incoming.SourceScanID || candidate.ID != ref.ID {
		return false
	}
	return vulnSummaryKey(candidate) == vulnSummaryKey(VulnSummary{Title: ref.Title, Target: ref.Target, Endpoint: ref.Endpoint, Method: ref.Method, CVE: ref.CVE})
}

func applySummaryReplacement(vulns *[]VulnSummary, incoming *VulnSummary, legacyReceipt bool) {
	if incoming.Replaces == nil && incoming.Verified && legacyReceipt && incoming.SourceScanID != "" {
		var candidate *VulnSummary
		for i := range *vulns {
			row := &(*vulns)[i]
			if row.SourceScanID != incoming.SourceScanID || !reporting.IsVerifiedUpgrade(vulnFromSummary(*row), vulnFromSummary(*incoming)) {
				continue
			}
			if candidate != nil {
				return // Ambiguous historical collisions cannot prove replacement.
			}
			candidate = row
		}
		if candidate != nil {
			incoming.Replaces = reporting.IdentityForFinding(vulnFromSummary(*candidate))
		}
	}
	if incoming.Replaces == nil {
		return
	}
	kept := (*vulns)[:0]
	for _, row := range *vulns {
		if !summaryIsReplaced(row, *incoming) {
			kept = append(kept, row)
		}
	}
	*vulns = kept
}

func applyFindingUpgradeEvent(rec *ScanRecord, event WSEvent) {
	if event.ToolName != "report_vulnerability" || !metadataBool(event.ResultMeta, "upgraded") {
		return
	}
	for _, incoming := range event.Vulns {
		if incoming.SourceScanID == "" && rec.InstanceID != rec.ID && (rec.ScanMode != "wildcard" || rec.ParentTarget != "") {
			incoming.SourceScanID = rec.ID
		}
		applySummaryReplacement(&rec.Vulns, &incoming, true)
		appendVulnSummaryUnique(&rec.Vulns, incoming)
	}
}

func applyRecordedFindingUpgrades(rec *ScanRecord) {
	for _, event := range rec.Events {
		applyFindingUpgradeEvent(rec, event)
	}
	rows := rec.Vulns
	rec.Vulns = make([]VulnSummary, 0, len(rows))
	for _, row := range rows {
		appendVulnSummaryUnique(&rec.Vulns, row)
	}
}

func (s *Server) reconcileSavedFindingUpgrades(rec *ScanRecord, dir string) {
	if rec == nil {
		return
	}
	for i := range rec.Vulns {
		if rec.Vulns[i].SourceScanID == "" && (rec.ScanMode != "wildcard" || rec.ParentTarget != "") {
			rec.Vulns[i].SourceScanID = rec.ID
		}
	}
	applyRecordedFindingUpgrades(rec)
	// Older snapshots can outlive the receipt's rotating event tail. Stream
	// the durable journal only for rows that still carry a physical ID collision.
	seen := make(map[string]bool)
	collision := false
	for _, row := range rec.Vulns {
		key := row.SourceScanID + ":" + row.ID
		collision = collision || seen[key]
		seen[key] = true
	}
	if collision && rec.EventsJournal {
		if _, _, err := walkEventJournal(dir, func(_ int, event WSEvent) { applyFindingUpgradeEvent(rec, event) }); err != nil && !os.IsNotExist(err) {
			log.Printf("[checkpoint] finding upgrade history could not be reconciled: %v", err)
		}
	}
}

func (s *Server) reconcileExactFindingUpgrades(rec *ScanRecord) {
	applyRecordedFindingUpgrades(rec)
	seen := make(map[string]bool)
	sources := make(map[string]bool)
	for _, row := range rec.Vulns {
		if row.SourceScanID == "" || row.ID == "" {
			continue
		}
		key := row.SourceScanID + ":" + row.ID
		if seen[key] {
			sources[row.SourceScanID] = true
		}
		seen[key] = true
	}
	if len(sources) == 0 {
		return
	}
	owned := make(map[string][]scanEntry)
	for _, entry := range s.findAllScanSummaries() {
		if sources[entry.rec.ID] && entry.rec.InstanceID == rec.InstanceID {
			owned[entry.rec.ID] = append(owned[entry.rec.ID], entry)
		}
	}
	for source, entries := range owned {
		if len(entries) != 1 {
			continue
		}
		entry := entries[0]
		if _, _, err := walkEventJournal(entry.dir, func(_ int, event WSEvent) {
			for i := range event.Vulns {
				if event.Vulns[i].SourceScanID == "" {
					event.Vulns[i].SourceScanID = source
				}
			}
			applyFindingUpgradeEvent(rec, event)
		}); err != nil && !os.IsNotExist(err) {
			log.Printf("[checkpoint] exact finding upgrade history could not be reconciled: %v", err)
		}
	}
}
