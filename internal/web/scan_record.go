package web

import (
	"log"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func (s *Server) scanRecordForSession(sess *scanSession) *ScanRecord {
	startedAt := time.Now().Format(time.RFC3339)
	rec := s.freshScanRecordForSession(sess, startedAt)
	sess.recordTokenOffset = 0

	if sess.resetState {
		return rec
	}

	existing, ok := s.loadScanRecordForDetail(sess.scanDir, detailEventTail)
	if !ok || existing == nil {
		return rec
	}
	if existing.ID != "" && existing.ID != sess.id {
		log.Printf("[AUTO-RESUME] Ignoring scan record %s in %s while resuming %s", existing.ID, sess.scanDir, sess.id)
		return rec
	}

	rec = existing
	s.reconcileSavedFindingUpgrades(rec, sess.scanDir)
	s.refreshResumedScanRecord(rec, sess, startedAt)
	sess.recordTokenOffset = rec.TotalTokens
	return rec
}

func (s *Server) freshScanRecordForSession(sess *scanSession, startedAt string) *ScanRecord {
	return &ScanRecord{
		ID:                       sess.id,
		InstanceID:               sess.instanceID,
		Name:                     sess.name,
		Target:                   sess.target,
		ParentTarget:             sess.parentTarget,
		ScanMode:                 sess.scanMode,
		Instruction:              sess.userInstruction,
		SeverityFilter:           append([]string(nil), sess.severityFilter...),
		DiscordWebhook:           sess.discordWebhook,
		DiscordWebhookConfigured: sess.discordWebhook != "" || s.discordWebhook != "",
		TelegramConfigured:       s.telegramConfigured(),
		ReconMode:                normalizeActivityMode(sess.reconMode),
		ScanIntensity:            normalizeActivityMode(sess.scanIntensity),
		StartedAt:                startedAt,
		Status:                   "running",
		Events:                   []WSEvent{},
		Vulns:                    []VulnSummary{},
		CompanyName:              sess.companyName,
		LogoPath:                 sess.logoPath,
		Phases:                   append([]int(nil), sess.phases...),
		CurrentPhase:             firstSelectedPhase(sess.phases),
		WorkStarted:              true,
	}
}

func (s *Server) refreshResumedScanRecord(rec *ScanRecord, sess *scanSession, fallbackStartedAt string) {
	if rec.ID == "" {
		rec.ID = sess.id
	}
	rec.InstanceID = sess.instanceID
	if sess.name != "" || rec.Name == "" {
		rec.Name = sess.name
	}
	rec.Target = sess.target
	rec.ParentTarget = sess.parentTarget
	rec.ScanMode = sess.scanMode
	if sess.userInstruction != "" || rec.Instruction == "" {
		rec.Instruction = sess.userInstruction
	}
	rec.SeverityFilter = append([]string(nil), sess.severityFilter...)
	rec.DiscordWebhook = sess.discordWebhook
	rec.DiscordWebhookConfigured = sess.discordWebhook != "" || s.discordWebhook != ""
	rec.TelegramConfigured = s.telegramConfigured()
	rec.ReconMode = normalizeActivityMode(sess.reconMode)
	rec.ScanIntensity = normalizeActivityMode(sess.scanIntensity)
	if rec.StartedAt == "" {
		rec.StartedAt = fallbackStartedAt
	}
	rec.Status = "running"
	rec.Completion = ""
	rec.WorkStarted = true
	rec.FinishedAt = ""
	rec.StopReason = ""
	if rec.Events == nil {
		rec.Events = []WSEvent{}
	}
	if rec.Vulns == nil {
		rec.Vulns = []VulnSummary{}
	}
	if sess.companyName != "" || rec.CompanyName == "" {
		rec.CompanyName = sess.companyName
	}
	if sess.logoPath != "" || rec.LogoPath == "" {
		rec.LogoPath = sess.logoPath
	}
	rec.Phases = append([]int(nil), sess.phases...)
	if rec.CurrentPhase == 0 || !phaseAllowed(sess.phases, rec.CurrentPhase) {
		rec.CurrentPhase = firstSelectedPhase(sess.phases)
	}
}

func mergeReportedVulnerabilitiesIntoRecord(rec *ScanRecord, reported []reporting.Vulnerability) {
	if rec == nil {
		return
	}
	existing := append([]VulnSummary(nil), rec.Vulns...)
	rec.Vulns = make([]VulnSummary, 0, len(existing)+len(reported))
	for _, vuln := range existing {
		if vuln.SourceScanID == "" {
			vuln.SourceScanID = rec.ID
		}
		appendVulnSummaryUnique(&rec.Vulns, vuln)
	}
	for _, vuln := range reported {
		summary := vulnToSummary(vuln)
		summary.SourceScanID = rec.ID
		appendVulnSummaryUnique(&rec.Vulns, summary)
	}
}

// mirrorPersistedSessionVulnerabilities copies the session findings that have
// already been saved to scan.json into the exact parent instance snapshot.
// Wildcard children use the shared parent instance ID, so this also builds the
// complete parent finding set without a disk walk. The copy happens before a
// terminal instance can become observable.
func (s *Server) mirrorPersistedSessionVulnerabilities(instanceID string, vulns []VulnSummary) {
	if instanceID == "" || len(vulns) == 0 {
		return
	}
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	if inst != nil {
		inst.mu.Lock()
		for _, vuln := range vulns {
			appendVulnSummaryUnique(&inst.Vulns, vuln)
		}
		inst.VulnCount = len(inst.Vulns)
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()
}

// effectiveVulnCount returns the most stable counter source for an instance.
// Strategy: prefer in-memory while running (live), fall back to on-disk
// VulnCount once the scan is finished or torn down (stable across teardown).
//
// This consolidates the three triple-source assignments at the legacy
// VulnCount call sites (resume seeding and per-event status update),
// which previously caused visible counter drift as the scan moved between
// phases. See Property 2 (counter monotonicity) in
// .kiro/specs/findings-consistency-and-pagination/design.md.
//
// When sess is non-nil and the instance is actively running, the count
// comes from reporting.GetVulnerabilitiesForContext, preferring the
// parent reporting context when present (covers wildcard child sessions).
// In every other state — finished, stopped, errored, paused, torn down —
// the count comes from len(inst.Vulns), the on-disk-derived in-memory
// mirror that survives reporting.CleanupContext.
//
// The caller is responsible for holding inst.mu at the appropriate level
// (RLock to read inst.Status / inst.Vulns, Lock when assigning the
// returned value back into inst.VulnCount).
func (s *Server) effectiveVulnCount(inst *ScanInstance, sess *scanSession) int {
	if inst == nil {
		return 0
	}
	if sess != nil && inst.Status == "running" {
		ctxID := ""
		if sess.parentReportingCtxID != "" {
			ctxID = sess.parentReportingCtxID
		} else if sess.sctx != nil {
			ctxID = sess.sctx.ID
		}
		if ctxID != "" {
			seen := make(map[string]bool)
			key := func(v VulnSummary) string {
				if strings.TrimSpace(v.Title) == "" {
					return "id:" + v.SourceScanID + "/" + v.ID
				}
				return dedupFindingKey(v.Target, v)
			}
			for _, v := range inst.Vulns {
				seen[key(v)] = true
			}
			for _, v := range reporting.GetVulnerabilitiesForContext(ctxID) {
				seen[key(vulnToSummary(v))] = true
			}
			return len(seen)
		}
	}
	return len(inst.Vulns)
}

// totalPersistedVulnCount returns the total number of persisted (on-disk)
// vulnerabilities across every scan record under cfg.DataDir, deduplicated
// by (target, endpoint, title, severity). This is the stable on-disk
// corpus used by both /api/findings/summary and the vulns_persisted field
// on /api/status. The dedup matches the WebUI's dedupFindings helper so
// the totals strip and the row count never disagree. See Property 2
// (counter monotonicity) — the on-disk total is monotonic-non-decreasing
// across teardown because reporting.CleanupContext does not touch
// ScanRecord.Vulns.
func (s *Server) totalPersistedVulnCount() int {
	seen := make(map[string]struct{})
	for _, entry := range s.findAllScanSummaries() {
		for _, v := range entry.rec.Vulns {
			key := dedupFindingKey(entry.rec.Target, v)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

// dedupFindingKey computes the same lowercase (target, endpoint, title,
// severity) key the WebUI's dedupFindings helper uses, so the server
// counter sources and the WebUI row list are always in agreement.
//
// Severity is bucketed via normalizeSeverityBucket so "Informational",
// "info", and "" all collapse to "info" (mirrors the WebUI's
// normalizeSeverity).
func dedupFindingKey(target string, v VulnSummary) string {
	return strings.ToLower(strings.TrimSpace(target)) + "|" +
		strings.ToLower(strings.TrimSpace(v.Endpoint)) + "|" +
		strings.ToLower(strings.TrimSpace(v.Title)) + "|" +
		normalizeSeverityBucket(v.Severity)
}

// normalizeSeverityBucket folds free-form severity strings into one of
// the five canonical buckets. Mirrors the WebUI's normalizeSeverity so
// server-side dedup keys match client-side ones.
func normalizeSeverityBucket(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func (s *Server) seedResumeInstanceFromRecord(inst *ScanInstance, req ScanRequest) {
	if inst == nil || !req.IsResume {
		return
	}
	resumeDir := req.ResumeScanDir
	if resumeDir == "" && len(req.Targets) > 0 {
		resumeDir = s.findLatestScanDirForTarget(req.Targets[0])
	}
	if resumeDir == "" {
		return
	}
	rec, ok := loadScanRecordFromDir(resumeDir)
	if !ok || rec == nil {
		return
	}
	s.reconcileSavedFindingUpgrades(rec, resumeDir)
	if rec.StartedAt != "" {
		inst.StartedAt = rec.StartedAt
	}
	applyRecordIntegrityLocked(inst, rec)
	inst.AdmittedAt = rec.AdmittedAt
	inst.ResumedAt = rec.ResumedAt
	inst.AssessmentProgress = rec.AssessmentProgress
	inst.UsageBySession = cloneSessionUsage(rec.UsageBySession)
	if rec.Name != "" {
		inst.Name = rec.Name
	}
	if rec.Target != "" && strings.TrimSpace(inst.Targets) == "" {
		inst.Targets = rec.Target
	}
	if rec.ScanMode != "" {
		inst.ScanMode = rec.ScanMode
	}
	if rec.Instruction != "" {
		inst.Instruction = rec.Instruction
	}
	if len(rec.SeverityFilter) > 0 {
		inst.SeverityFilter = append([]string(nil), rec.SeverityFilter...)
	}
	if len(rec.Phases) > 0 {
		inst.Phases = append([]int(nil), rec.Phases...)
	}
	if rec.ReconMode != "" {
		inst.ReconMode = rec.ReconMode
	}
	if rec.ScanIntensity != "" {
		inst.ScanIntensity = rec.ScanIntensity
	}
	if rec.CompanyName != "" {
		inst.CompanyName = rec.CompanyName
	}
	if rec.LogoPath != "" {
		inst.LogoPath = rec.LogoPath
	}
	if rec.Iterations > inst.Iterations {
		inst.Iterations = rec.Iterations
	}
	if rec.ToolCalls > inst.ToolCalls {
		inst.ToolCalls = rec.ToolCalls
	}
	if rec.TotalTokens > inst.TotalTokens {
		inst.TotalTokens = rec.TotalTokens
	}
	inst.Vulns = append([]VulnSummary(nil), rec.Vulns...)
	if rec.SubScans != nil {
		inst.SubScans = cloneSubScanSummaries(rec.SubScans)
	}
	inst.SubScanTotal = rec.SubScanTotal
	inst.SubScanCompleted = rec.SubScanCompleted
	inst.SubScanRunning = rec.SubScanRunning
	inst.SubScanRemaining = rec.SubScanRemaining
	inst.Discovery = cloneSubScanSummary(rec.Discovery)
	inst.SubScanSkipped = rec.SubScanSkipped
	if inst.ScanMode == "wildcard" {
		aggregateWildcardInstanceLocked(inst)
	}
	// Resume path: scan is being seeded from on-disk record, no live session
	// exists yet, so effectiveVulnCount falls back to len(inst.Vulns).
	inst.VulnCount = s.effectiveVulnCount(inst, nil)
	if rec.CurrentPhase > 0 {
		inst.CurrentPhase = rec.CurrentPhase
	}
	events := rec.Events
	if len(events) > 500 {
		events = events[len(events)-500:]
	}
	inst.events = append([]WSEvent(nil), events...)
}
