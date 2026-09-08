package web

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	pdfreport "github.com/xalgord/xalgorix/v4/internal/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                 v.ID,
		Title:              v.Title,
		Severity:           v.Severity,
		Target:             v.Target,
		Endpoint:           v.Endpoint,
		CVSS:               v.CVSS,
		CVSSVector:         v.CVSSVector,
		Description:        v.Description,
		Impact:             v.Impact,
		Method:             v.Method,
		CVE:                v.CVE,
		CWE:                v.CWE,
		OWASP:              v.OWASP,
		TechnicalAnalysis:  v.TechnicalAnalysis,
		PoCDescription:     v.PoCDescription,
		PoCScript:          v.PoCScript,
		Remediation:        v.Remediation,
		Fix:                v.Fix,
		ExploitationProof:  v.ExploitationProof,
		VerificationMethod: v.VerificationMethod,
		Verified:           v.Verified,
		Tags:               v.Tags,
	}
}

func metadataString(metadata map[string]any, key string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	value, ok := metadata[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.TrimSpace(text)
	return text, text != ""
}

func findReportedVulnerabilityByID(vulns []reporting.Vulnerability, id string) (reporting.Vulnerability, bool) {
	for _, vuln := range vulns {
		if vuln.ID == id {
			return vuln, true
		}
	}
	return reporting.Vulnerability{}, false
}

func appendVulnSummaryUnique(vulns *[]VulnSummary, vuln VulnSummary) bool {
	key := vulnSummaryKey(vuln)
	for i := range *vulns {
		existing := &(*vulns)[i]
		if vulnSummaryKey(*existing) == key {
			// A live parent snapshot can arrive before the persisted wildcard
			// child. Preserve the row while enriching it with authoritative
			// physical provenance once the child copy is attached.
			if existing.SourceScanID == "" && vuln.SourceScanID != "" {
				existing.SourceScanID = vuln.SourceScanID
			}
			return false
		}
	}
	*vulns = append(*vulns, vuln)
	return true
}

func vulnSummaryKey(v VulnSummary) string {
	return strings.Join([]string{
		normalizeSummaryPart(v.Title),
		normalizeSummaryPart(v.Target),
		normalizeSummaryPart(v.Endpoint),
		normalizeSummaryPart(v.Method),
		normalizeSummaryPart(v.CVE),
	}, "|")
}

func normalizeSummaryPart(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// toReportingScan projects a ScanRecord (plus its VulnSummary/WSEvent
// children) onto the internal/reporting package's transport types by direct
// field copy. internal/reporting owns the actual PDF rendering; this is the
// only conversion the web layer needs to do to use it.
func toReportingScan(scan *ScanRecord) *pdfreport.Scan {
	vulns := make([]pdfreport.Vuln, len(scan.Vulns))
	for i, v := range scan.Vulns {
		vulns[i] = pdfreport.Vuln{
			ID:                 v.ID,
			Title:              v.Title,
			Severity:           v.Severity,
			Target:             v.Target,
			Endpoint:           v.Endpoint,
			CVSS:               v.CVSS,
			CVSSVector:         v.CVSSVector,
			Description:        v.Description,
			Impact:             v.Impact,
			Method:             v.Method,
			CVE:                v.CVE,
			CWE:                v.CWE,
			OWASP:              v.OWASP,
			TechnicalAnalysis:  v.TechnicalAnalysis,
			PoCDescription:     v.PoCDescription,
			PoCScript:          v.PoCScript,
			Remediation:        v.Remediation,
			Fix:                v.Fix,
			ExploitationProof:  v.ExploitationProof,
			VerificationMethod: v.VerificationMethod,
			Verified:           v.Verified,
		}
	}
	events := make([]pdfreport.Event, len(scan.Events))
	for i, e := range scan.Events {
		events[i] = pdfreport.Event{
			Type:     e.Type,
			Content:  e.Content,
			ToolName: e.ToolName,
			ToolArgs: e.ToolArgs,
			Output:   e.Output,
			Error:    e.Error,
		}
	}
	return &pdfreport.Scan{
		ID:          scan.ID,
		Name:        scan.Name,
		Target:      scan.Target,
		StartedAt:   scan.StartedAt,
		FinishedAt:  scan.FinishedAt,
		Status:      scan.Status,
		CompanyName: scan.CompanyName,
		LogoPath:    scan.LogoPath,
		Phases:      scan.Phases,
		Iterations:  scan.Iterations,
		ToolCalls:   scan.ToolCalls,
		TotalTokens: scan.TotalTokens,
		Vulns:       vulns,
		Events:      events,
	}
}

// generateReportAt generates a PDF report, saving it to a specific directory.
func (s *Server) generateReportAt(scan *ScanRecord, scanDir string) (string, error) {
	// The redesigned reporting package currently renders with Latin core
	// fonts. Preserve the localized/CJK renderer added on main for non-English
	// reports until that support is moved into internal/reporting.
	language := config.DefaultLanguage
	if s.cfg != nil {
		language = config.NormalizeLanguage(s.cfg.Language)
	}
	if language != config.DefaultLanguage {
		// The localized renderer still uses currentScanDir for its output path.
		s.mu.Lock()
		prevDir := s.currentScanDir
		s.currentScanDir = scanDir
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.currentScanDir = prevDir
			s.mu.Unlock()
		}()
		return s.generateReport(scan)
	}

	logoData, logoType := s.loadReportLogo(scan.LogoPath)

	return pdfreport.Generate(toReportingScan(scan), pdfreport.Options{
		LogoData:    logoData,
		LogoType:    logoType,
		ScanDir:     scanDir,
		FallbackDir: s.dataDir,
	})
}

// scanEntry holds a discovered scan.json path and its parsed record.
type scanEntry struct {
	dir string     // directory containing scan.json
	rec ScanRecord // parsed record
}

// walkScanDirs invokes fn with the path to every scan.json under root WITHOUT
// descending into a scan directory's artifact subtree. A directory that
// contains a scan.json IS a scan directory; its subdirectories (tool output,
// downloaded site assets, caches — collectively tens of GB and, on a busy
// install, ~millions of filesystem entries) are never traversed. This keeps a
// full walk proportional to the number of SCANS (a few thousand directory
// listings) instead of the total data size.
//
// Before this, both walkers used filepath.WalkDir over the entire data dir, so
// every scan-list / scan-resolve request statted the whole artifact tree
// (~1.9M entries for 401 scans here). That, not any single scan.json's size,
// was what made the scan pages slow.
func walkScanDirs(root string, fn func(scanJSONPath string)) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && e.Name() == "scan.json" {
			fn(filepath.Join(root, "scan.json"))
			return // this is a scan dir; do not descend into its artifacts
		}
	}
	for _, e := range entries {
		// e.IsDir() is false for symlinks, so symlinked dirs are not followed
		// (no traversal loops).
		if e.IsDir() {
			walkScanDirs(filepath.Join(root, e.Name()), fn)
		}
	}
}

// findAllScans finds all scan.json files under dataDir and fully parses each
// (event log included). Structure: dataDir/target/date/slug/scan.json.
func (s *Server) findAllScans() []scanEntry {
	var results []scanEntry
	walkScanDirs(s.dataDir, func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) != nil {
			return
		}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
	})
	return results
}

// scanSummaryCacheEntry is one memoized, events-free scan record plus the file
// stat used to detect staleness.
type scanSummaryCacheEntry struct {
	modNano int64
	size    int64
	rec     ScanRecord
}

// scanRecordLite parses a scan.json while skipping the heavy events array.
// The embedded ScanRecord carries every field; the shadow Events field — a
// json.RawMessage at depth 0 — captures the "events" key so encoding/json
// routes it here instead of unmarshaling thousands of WSEvent structs into the
// embedded slice (encoding/json picks the shallowest field on a tag conflict).
// The captured bytes are discarded: list, findings, and summary views never
// read events, and skipping the per-event struct decode is the bulk of the
// parse-cost saving.
type scanRecordLite struct {
	ScanRecord
	Events json.RawMessage `json:"events"`
}

// findAllScanSummaries is the events-free, cached counterpart to findAllScans.
// It walks the data dir (pruning artifact subtrees via walkScanDirs), parses
// each scan.json without decoding its event log, and memoizes the result per
// file keyed by (modtime, size). Subsequent walks only stat each scan.json and
// re-parse the few that changed. Callers that need the event log (report
// generation) must use findAllScans instead.
func (s *Server) findAllScanSummaries() []scanEntry {
	var results []scanEntry

	s.scanSummaryCacheMu.Lock()
	defer s.scanSummaryCacheMu.Unlock()
	if s.scanSummaryCache == nil {
		s.scanSummaryCache = make(map[string]scanSummaryCacheEntry)
	}
	seen := make(map[string]struct{})

	walkScanDirs(s.dataDir, func(path string) {
		info, ierr := os.Stat(path)
		if ierr != nil {
			return
		}
		seen[path] = struct{}{}
		modNano := info.ModTime().UnixNano()
		size := info.Size()
		if c, ok := s.scanSummaryCache[path]; ok && c.modNano == modNano && c.size == size {
			results = append(results, scanEntry{dir: filepath.Dir(path), rec: c.rec})
			return
		}
		recPtr, ok := readScanSummary(path)
		if !ok {
			return
		}
		rec := *recPtr
		s.scanSummaryCache[path] = scanSummaryCacheEntry{modNano: modNano, size: size, rec: rec}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
	})

	// Drop cache entries for files that no longer exist so deleted scans
	// don't leak memory across the process lifetime.
	if len(s.scanSummaryCache) > len(seen) {
		for p := range s.scanSummaryCache {
			if _, ok := seen[p]; !ok {
				delete(s.scanSummaryCache, p)
			}
		}
	}

	return results
}

// resolveScanDirByID locates the on-disk directory for a scan id WITHOUT
// loading (and therefore without parsing the potentially huge event log of)
// the matched record. It uses the cached, events-free summaries so resolution
// is O(1) full parses. Callers that need the record decide how much of it to
// load: findScanByID loads the whole record; the scan-detail path loads only a
// tail of events (loadScanRecordForDetail).
func (s *Server) resolveScanDirByID(scanID string) (string, bool) {
	// Sanitize: prevent path traversal via ../
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == ".." {
		return "", false
	}

	entries := s.findAllScanSummaries()
	resolveUniqueDir := func(topLevelOnly bool) (string, bool, bool) {
		var matchedDir string
		found := false
		for _, entry := range entries {
			if topLevelOnly && entry.rec.ParentTarget != "" {
				continue
			}
			if entry.rec.ID != scanID && entry.rec.InstanceID != scanID && filepath.Base(entry.dir) != scanID {
				continue
			}
			if found {
				log.Printf("[scan] refusing ambiguous scan id %q: multiple records match", scanID)
				return "", false, true // ambiguous → resolved, no match
			}
			matchedDir = entry.dir
			found = true
		}
		return matchedDir, found, false
	}
	if dir, found, ambiguous := resolveUniqueDir(true); ambiguous {
		return "", false
	} else if found {
		return dir, true
	}
	if dir, found, ambiguous := resolveUniqueDir(false); ambiguous {
		return "", false
	} else if found {
		return dir, true
	}

	// Legacy flat path fallback (dataDir/scanID/scan.json).
	direct := filepath.Join(s.dataDir, scanID, "scan.json")
	if _, err := os.Stat(direct); err == nil {
		return filepath.Join(s.dataDir, scanID), true
	}
	return "", false
}

// findScanByID searches for a scan by its AgentID (the slug dir name) and
// returns the fully-loaded record (event log included). Prefer
// resolveScanDirByID + a tail loader on the read hot path.
func (s *Server) findScanByID(scanID string) (string, *ScanRecord) {
	dir, ok := s.resolveScanDirByID(scanID)
	if !ok {
		return "", nil
	}
	if rec, ok := loadScanRecordFromDir(dir); ok {
		return dir, rec
	}
	return "", nil
}

// persistedInstanceIDClaim reports whether any top-level persisted record
// claims an external instance ID. Ambiguous duplicate claims are still a hard
// reservation conflict even though they are intentionally non-authoritative
// for reads.
func (s *Server) persistedInstanceIDClaim(instanceID string) (string, bool) {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return "", false
	}
	if rec, err := s.loadExactDispatchSnapshot(instanceID); err == nil {
		return rec.Status, true
	} else if !errors.Is(err, errDispatchSnapshotNotFound) {
		return "conflict", true
	}
	status := ""
	claims := 0
	for _, entry := range s.findAllScans() {
		if entry.rec.ParentTarget == "" && entry.rec.InstanceID == instanceID {
			claims++
			status = entry.rec.Status
		}
	}
	if claims > 1 {
		return "conflict", true
	}
	return status, claims == 1
}

// findScanByInstanceID resolves only the immutable external instance identity
// persisted on a top-level scan record. It deliberately does not accept record
// IDs, directory names, target similarity, or short aliases: authoritative
// status snapshots must either prove the requested run identity or return no
// news.
func (s *Server) findScanByInstanceID(instanceID string) (string, *ScanRecord) {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return "", nil
	}
	if rec, err := s.loadExactDispatchSnapshot(instanceID); err == nil {
		return filepath.Dir(s.dispatchSnapshotPath(instanceID)), rec
	} else if !errors.Is(err, errDispatchSnapshotNotFound) {
		log.Printf("[scan] refusing unreadable exact dispatch snapshot %q: %v", instanceID, err)
		return "", nil
	}
	var matchedDir string
	var matched *ScanRecord
	for _, entry := range s.findAllScans() {
		if entry.rec.ParentTarget != "" || entry.rec.InstanceID != instanceID {
			continue
		}
		if matched != nil {
			log.Printf("[scan] refusing ambiguous external instance id %q: records %q and %q both claim it", instanceID, matched.ID, entry.rec.ID)
			return "", nil
		}
		rec := entry.rec
		matchedDir = entry.dir
		matched = &rec
	}
	return matchedDir, matched
}

func (s *Server) markDiscordWebhookConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.DiscordWebhookConfigured = rec.DiscordWebhookConfigured ||
		rec.DiscordWebhook != "" ||
		s.discordWebhook != ""
}

// markTelegramConfigured sets the TelegramConfigured flag on a scan
// record when global Telegram notifications are enabled. Telegram is
// global-only in v1 (no per-scan override), so the flag reflects the
// server-wide configuration rather than any per-scan field. The bot
// token itself is never written to the record (only the boolean).
func (s *Server) markTelegramConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.TelegramConfigured = s.telegramConfigured()
}

func cloneSubScanSummaries(source []SubScanSummary) []SubScanSummary {
	if source == nil {
		return nil
	}
	cloned := make([]SubScanSummary, len(source))
	copy(cloned, source)
	return cloned
}

func (s *Server) scanRecordFromInstance(inst *ScanInstance) *ScanRecord {
	if inst == nil {
		return nil
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()

	events := make([]WSEvent, len(inst.events))
	copy(events, inst.events)
	vulns := make([]VulnSummary, len(inst.Vulns))
	copy(vulns, inst.Vulns)
	phases := append([]int(nil), inst.Phases...)
	severityFilter := append([]string(nil), inst.SeverityFilter...)
	subScans := cloneSubScanSummaries(inst.SubScans)

	return &ScanRecord{
		ID:                       inst.ID,
		InstanceID:               inst.ID,
		Name:                     inst.Name,
		Target:                   inst.Targets,
		ParentTarget:             inst.ParentTarget,
		StartedAt:                inst.StartedAt,
		FinishedAt:               inst.FinishedAt,
		Status:                   inst.Status,
		StopReason:               inst.StopReason,
		ScanMode:                 inst.ScanMode,
		Instruction:              inst.Instruction,
		SeverityFilter:           severityFilter,
		DiscordWebhook:           inst.DiscordWebhook,
		DiscordWebhookConfigured: inst.DiscordWebhook != "",
		TelegramConfigured:       s.telegramConfigured(),
		ReconMode:                inst.ReconMode,
		ScanIntensity:            inst.ScanIntensity,
		Events:                   events,
		Vulns:                    vulns,
		TotalTokens:              inst.TotalTokens,
		Iterations:               inst.Iterations,
		ToolCalls:                inst.ToolCalls,
		CompanyName:              inst.CompanyName,
		LogoPath:                 inst.LogoPath,
		Phases:                   phases,
		CurrentPhase:             inst.CurrentPhase,
		SubScans:                 subScans,
		SubScanTotal:             inst.SubScanTotal,
		SubScanCompleted:         inst.SubScanCompleted,
		SubScanRunning:           inst.SubScanRunning,
		SubScanRemaining:         inst.SubScanRemaining,
		WorkStarted:              inst.WorkStarted,
	}
}

// mirrorWildcardProgress copies the persisted wildcard parent snapshot into
// its live instance. The copy keeps /api/instances/{id} lock-only and avoids
// sharing the mutable parentRecord slice with concurrent HTTP encoders.
func (s *Server) mirrorWildcardProgress(instanceID string, rec *ScanRecord) {
	if instanceID == "" || rec == nil {
		return
	}
	children := cloneSubScanSummaries(rec.SubScans)

	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	if inst != nil {
		inst.mu.Lock()
		inst.SubScans = children
		inst.SubScanTotal = rec.SubScanTotal
		inst.SubScanCompleted = rec.SubScanCompleted
		inst.SubScanRunning = rec.SubScanRunning
		inst.SubScanRemaining = rec.SubScanRemaining
		normalizeTerminalWildcardInstanceLocked(inst)
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()
}

// normalizeTerminalSubScans converts unresolved children to a terminal status
// while preserving whether the scanner ever dispatched them. Never-started
// pending children remain without lifecycle timestamps; running/started
// children receive the parent's terminal timestamp.
func normalizeTerminalSubScans(children []SubScanSummary, parentStatus, finishedAt string) int {
	fallbackStatus := terminalSubScanStatus(parentStatus)
	completed := 0
	for i := range children {
		status := strings.ToLower(strings.TrimSpace(children[i].Status))
		started := status == "running" || children[i].StartedAt != "" || children[i].ID != "" ||
			children[i].VulnCount > 0 || children[i].TotalTokens > 0
		if isUnresolvedSubScanStatus(status) {
			children[i].Status = fallbackStatus
			if started && children[i].FinishedAt == "" {
				children[i].FinishedAt = finishedAt
			}
		}
		if isFinishedSubScanStatus(children[i].Status) {
			completed++
		}
	}
	return completed
}

// normalizeTerminalWildcardProgress prevents a terminal compact snapshot from
// retaining children as pending/running. This mirrors the historical full
// response's normalization without its disk walk.
func normalizeTerminalWildcardProgress(rec *ScanRecord) {
	if rec == nil || !isTerminalScanStatus(rec.Status) {
		return
	}
	finishedAt := rec.FinishedAt
	if finishedAt == "" {
		finishedAt = time.Now().Format(time.RFC3339)
	}
	completed := normalizeTerminalSubScans(rec.SubScans, rec.Status, finishedAt)
	if rec.SubScanTotal < len(rec.SubScans) {
		rec.SubScanTotal = len(rec.SubScans)
	}
	rec.SubScanCompleted = completed
	rec.SubScanRunning = 0
	rec.SubScanRemaining = rec.SubScanTotal - completed
	if rec.SubScanRemaining < 0 {
		rec.SubScanRemaining = 0
	}
}

// normalizeTerminalWildcardInstanceLocked keeps status and wildcard children
// coherent for exact instance readers. The caller must hold inst.mu.
func normalizeTerminalWildcardInstanceLocked(inst *ScanInstance) {
	if inst == nil || inst.ScanMode != "wildcard" || !isTerminalScanStatus(inst.Status) {
		return
	}
	finishedAt := inst.FinishedAt
	if finishedAt == "" {
		finishedAt = time.Now().Format(time.RFC3339)
	}
	completed := normalizeTerminalSubScans(inst.SubScans, inst.Status, finishedAt)
	if inst.SubScanTotal < len(inst.SubScans) {
		inst.SubScanTotal = len(inst.SubScans)
	}
	inst.SubScanCompleted = completed
	inst.SubScanRunning = 0
	inst.SubScanRemaining = inst.SubScanTotal - completed
	if inst.SubScanRemaining < 0 {
		inst.SubScanRemaining = 0
	}
}

func normalizeScanTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimRight(target, "/")
	return target
}

func isFinishedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

func isCompletedScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed":
		return true
	default:
		return false
	}
}

func isFinalScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "failed":
		return true
	default:
		return false
	}
}

func isTerminalScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

// isInterruptedRecoverableRecord reports whether an on-disk scan record was
// interrupted by something the operator did NOT intend as a final stop, and is
// therefore a candidate for auto-resume on the next startup.
//
// Two cases qualify:
//   - running/pending: the process died before the scan reached a terminal
//     state (crash / SIGKILL). scan.json still says running/pending.
//   - stopped with a signal_/panic_/server_shutdown reason: a graceful
//     SIGTERM/SIGINT, a recovered panic, or a scan that was still QUEUED
//     (pending, waiting for an admission slot) when the server shut down.
//     All persist the scan as "stopped" but PRESERVE its queue_state on
//     purpose (shouldPreserveQueueStateOnExit / the admission-loop shutdown
//     branch). Without this case those scans stayed "stopped"/"pending"
//     forever and only a fresh "Start" was offered — the bug this closes.
//
// The "server_shutdown" reason specifically is set for a scan that never got a
// slot before shutdown (orchestrator admission loop). Its queue_state is kept
// (preserveQueue), so it MUST also be recognized here — otherwise auto-resume
// keeps the queue_state but the exact-stop tombstone refuses dispatch, and the
// scan is stranded as an orphaned "pending" record with no driver goroutine
// that nothing ever promotes (observed: queued wildcard scans never starting
// after a restart even with free slots).
//
// A user-initiated stop is deliberately NOT recoverable: handleStop clears the
// queue_state, so even when such a record reaches this function the downstream
// resumability check (valid queue_state ownership) fails and it stays stopped.
// Gating resume on queue_state ownership — not on this predicate alone — is
// what keeps user-stopped/finished scans from being revived.
func isInterruptedRecoverableRecord(status, stopReason string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "pending":
		return true
	case "stopped":
		reason := strings.ToLower(strings.TrimSpace(stopReason))
		return strings.HasPrefix(reason, "signal_") ||
			reason == "panic_recovered" ||
			reason == "server_restart_resuming" ||
			reason == "server_shutdown"
	default:
		return false
	}
}

func isUnresolvedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending", "running":
		return true
	default:
		return false
	}
}

func terminalSubScanStatus(parentStatus string) string {
	if strings.EqualFold(strings.TrimSpace(parentStatus), "failed") {
		return "failed"
	}
	return "stopped"
}

func isChildOfScan(parent, child *ScanRecord) bool {
	if parent == nil || child == nil || child.ParentTarget == "" {
		return false
	}
	// Instance-aware matching: when the parent has an InstanceID (all
	// multi-instance scans do), the child must belong to the same
	// instance. Without this gate a new yahoo.com scan would absorb
	// every subdomain record from *previous* yahoo.com scans on disk,
	// instantly showing stale vulns and inflated subdomain counts.
	if parent.InstanceID != "" {
		return child.InstanceID == parent.InstanceID
	}
	// Legacy fallback for scans created before multi-instance mode:
	// match by target name only.
	return normalizeScanTarget(child.ParentTarget) == normalizeScanTarget(parent.Target)
}

func (s *Server) instanceForRecord(rec *ScanRecord) *ScanInstance {
	if rec == nil {
		return nil
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if rec.InstanceID != "" {
		if inst := s.instances[rec.InstanceID]; inst != nil {
			return inst
		}
	}
	return s.instances[rec.ID]
}

func (s *Server) applyInstanceSnapshot(rec *ScanRecord, includeEvents bool) {
	inst := s.instanceForRecord(rec)
	if inst == nil {
		return
	}
	snapshot := s.scanRecordFromInstance(inst)
	if snapshot == nil {
		return
	}
	if rec.InstanceID == "" {
		rec.InstanceID = snapshot.InstanceID
	}
	// Terminal states are FINAL. A stale in-memory instance — e.g. one left in
	// the map after an engine restart + auto-resume, or an orphaned pre-resume
	// instance — can report "running" for a scan that already reached a
	// terminal state on disk. Overwriting the persisted terminal status with
	// that live "running" made GET /api/scans/{id} report the scan as running
	// forever, so a poller (the SaaS reaper) never reconciled it (the
	// crowdproof.id desync). Only adopt the snapshot's status when we are NOT
	// downgrading an already-terminal persisted status to a non-terminal one.
	// Only guard genuinely-FINAL states (completed/finished). "stopped" is
	// resumable and "failed" is re-runnable, so a live "running" instance must
	// still win for those (see TestApplyInstanceSnapshotDoesNotErasePersistedResumeData).
	// But a completed scan is done forever: a stale in-memory instance left
	// after a restart/auto-resume must not downgrade it back to "running".
	if isFinalScanStatus(rec.Status) && !isFinalScanStatus(snapshot.Status) {
		log.Printf("[scan] %s (instance %s): kept final disk status %q over stale in-memory instance status %q — not downgrading a final scan to running",
			rec.ID, rec.InstanceID, rec.Status, snapshot.Status)
	} else {
		rec.Status = snapshot.Status
		rec.FinishedAt = snapshot.FinishedAt
		rec.StopReason = snapshot.StopReason
	}
	if snapshot.Iterations > rec.Iterations {
		rec.Iterations = snapshot.Iterations
	}
	if snapshot.ToolCalls > rec.ToolCalls {
		rec.ToolCalls = snapshot.ToolCalls
	}
	if snapshot.TotalTokens > rec.TotalTokens {
		rec.TotalTokens = snapshot.TotalTokens
	}
	rec.WorkStarted = rec.WorkStarted || snapshot.WorkStarted
	for _, vuln := range snapshot.Vulns {
		appendVulnSummaryUnique(&rec.Vulns, vuln)
	}
	// Phase is monotonic progress — only ever advance it. A stale in-memory
	// instance (post-restart/resume) could otherwise drag a finished scan's
	// phase back down (e.g. 22 → 11), same root cause as the status downgrade.
	if snapshot.CurrentPhase > rec.CurrentPhase {
		rec.CurrentPhase = snapshot.CurrentPhase
	}
	if includeEvents && len(snapshot.Events) >= len(rec.Events) {
		rec.Events = snapshot.Events
	}
}

// attachWildcardSubScans resolves a wildcard parent scan's child sub-scans by
// walking the data dir. It is a thin wrapper around attachWildcardSubScansFrom
// for callers that do not already hold a walked entry slice.
func (s *Server) attachWildcardSubScans(rec *ScanRecord) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}
	// Use the cached, events-free summaries: sub-scan attachment only reads
	// child target/status/counts/vulns, never the event log. Calling the
	// full findAllScans() here (per parent, on every GET) was a primary
	// driver of the JSON-decode CPU and multi-GB transient allocations.
	s.attachWildcardSubScansFrom(rec, s.findAllScanSummaries())
}

// attachWildcardSubScansFrom is the same as attachWildcardSubScans but reuses
// a pre-walked slice of scan entries instead of calling findAllScans() itself.
// This lets bulk callers (e.g. cachedScanList) walk the data dir ONCE and
// resolve children for every parent from the same slice, instead of triggering
// a full disk walk + parse per parent scan (previously O(parents × allScans)).
func (s *Server) attachWildcardSubScansFrom(rec *ScanRecord, entries []scanEntry) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}

	children := make(map[string]*SubScanSummary)
	order := []string{}
	add := func(key string, summary SubScanSummary) *SubScanSummary {
		key = normalizeScanTarget(key)
		if key == "" {
			key = normalizeScanTarget(summary.Target)
		}
		if key == "" {
			return nil
		}
		if existing := children[key]; existing != nil {
			if summary.ID != "" {
				existing.ID = summary.ID
			}
			if summary.Target != "" {
				existing.Target = summary.Target
			}
			if summary.StartedAt != "" {
				existing.StartedAt = summary.StartedAt
			}
			if summary.FinishedAt != "" {
				existing.FinishedAt = summary.FinishedAt
			}
			if summary.Status != "" && (!isFinishedSubScanStatus(existing.Status) || !strings.EqualFold(summary.Status, "running")) {
				existing.Status = summary.Status
			}
			if summary.VulnCount > 0 {
				existing.VulnCount = summary.VulnCount
			}
			if summary.TotalTokens > 0 {
				existing.TotalTokens = summary.TotalTokens
			}
			return existing
		}
		if summary.Status == "" {
			summary.Status = "running"
		}
		children[key] = &summary
		order = append(order, key)
		return children[key]
	}

	total := 0
	if rec.SubScanTotal > total {
		total = rec.SubScanTotal
	}
	for _, child := range rec.SubScans {
		add(child.Target, child)
	}

	for _, entry := range entries {
		child := entry.rec
		if !isChildOfScan(rec, &child) {
			continue
		}
		for _, vuln := range child.Vulns {
			// Reconstruct provenance for historical records and override stale
			// promoted metadata with the physical child that owns the finding.
			vuln.SourceScanID = child.ID
			appendVulnSummaryUnique(&rec.Vulns, vuln)
		}
		add(child.Target, SubScanSummary{
			ID:          child.ID,
			Target:      child.Target,
			StartedAt:   child.StartedAt,
			FinishedAt:  child.FinishedAt,
			Status:      child.Status,
			VulnCount:   len(child.Vulns),
			TotalTokens: child.TotalTokens,
		})
	}

	for _, evt := range rec.Events {
		if evt.SubTargetTotal > total {
			total = evt.SubTargetTotal
		}
		if evt.ParentTarget == "" && evt.SubTargetTotal == 0 {
			continue
		}
		target := strings.TrimSpace(evt.Target)
		if target == "" {
			continue
		}
		status := ""
		startedAt := ""
		finishedAt := ""
		switch evt.Type {
		case "target_started":
			status = "running"
			startedAt = evt.Timestamp
		case "target_completed":
			status = "finished"
			finishedAt = evt.Timestamp
		case "subdomains_discovered":
			for _, line := range strings.Split(evt.Output, "\n") {
				target := strings.TrimSpace(line)
				if target == "" {
					continue
				}
				add(target, SubScanSummary{Target: target, Status: "pending"})
			}
			continue
		default:
			continue
		}
		summary := add(target, SubScanSummary{
			ID:         evt.AgentID,
			Target:     target,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     status,
		})
		_ = summary
	}

	if total < len(children) {
		total = len(children)
	}
	if total == 0 {
		return
	}

	summaries := make([]SubScanSummary, 0, len(order))
	for _, key := range order {
		child := *children[key]
		summaries = append(summaries, child)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].StartedAt == "" || summaries[j].StartedAt == "" {
			return summaries[i].Target < summaries[j].Target
		}
		return summaries[i].StartedAt < summaries[j].StartedAt
	})

	danglingActive := false
	if isTerminalScanStatus(rec.Status) {
		fallbackStatus := terminalSubScanStatus(rec.Status)
		finishedAt := rec.FinishedAt
		if finishedAt == "" {
			finishedAt = time.Now().Format(time.RFC3339)
		}
		for i := range summaries {
			if !isUnresolvedSubScanStatus(summaries[i].Status) {
				continue
			}
			danglingActive = true
			summaries[i].Status = fallbackStatus
			if summaries[i].FinishedAt == "" {
				summaries[i].FinishedAt = finishedAt
			}
		}
	}

	completed := 0
	running := 0
	for _, child := range summaries {
		if isFinishedSubScanStatus(child.Status) {
			completed++
		} else if strings.EqualFold(child.Status, "running") {
			running++
		}
	}
	remaining := total - completed - running
	if remaining < 0 {
		remaining = 0
	}
	if isCompletedScanStatus(rec.Status) && (danglingActive || running > 0 || remaining > 0) {
		rec.Status = "stopped"
		if rec.StopReason == "" {
			rec.StopReason = "incomplete_wildcard_subscans"
		}
		if rec.FinishedAt == "" {
			rec.FinishedAt = time.Now().Format(time.RFC3339)
		}
	}
	rec.SubScans = summaries
	rec.SubScanTotal = total
	rec.SubScanCompleted = completed
	rec.SubScanRunning = running
	rec.SubScanRemaining = remaining
}

func finalizeScanRecordForResponse(rec *ScanRecord) {
	if rec == nil {
		return
	}
	// Native and historical findings may predate provenance metadata. Any
	// child/live finding with known provenance has already retained it through
	// aggregation, so only unresolved rows fall back to the displayed record.
	for i := range rec.Vulns {
		if rec.Vulns[i].SourceScanID == "" {
			rec.Vulns[i].SourceScanID = rec.ID
		}
	}
	if isCompletedScanStatus(rec.Status) && phaseAllowed(rec.Phases, 22) {
		rec.CurrentPhase = 22
	}
}

// rebuildInstancesFromDisk populates s.instances from all saved scan.json files on disk.
// This ensures the dashboard shows historical scans immediately after server restart.
// Skips subdomain scans (those with ParentTarget set) — those are shown under their parent.
// Interrupted running/pending records are resumable only when a valid queue-state entry
// still owns them; otherwise they are terminalized so they cannot remain pending forever.
func (s *Server) rebuildInstancesFromDisk() {
	queueEntries := s.validQueueStateEntries(false)
	qMap := make(map[string]string)
	for _, qe := range queueEntries {
		if qe.state != nil && qe.state.InstanceID != "" {
			if qe.state.ActiveScanDir != "" {
				qMap[filepath.Clean(qe.state.ActiveScanDir)] = qe.state.InstanceID
			}
			if qe.state.ActiveScanID != "" {
				qMap[qe.state.ActiveScanID] = qe.state.InstanceID
			}
			if qe.state.WildcardActiveScanDir != "" {
				qMap[filepath.Clean(qe.state.WildcardActiveScanDir)] = qe.state.InstanceID
			}
			if qe.state.WildcardActiveScanID != "" {
				qMap[qe.state.WildcardActiveScanID] = qe.state.InstanceID
			}
			if len(qe.state.Targets) > 0 {
				qMap[normalizeScanTarget(qe.state.Targets[0])] = qe.state.InstanceID
			}
			if qe.state.WildcardActiveTarget != "" {
				qMap[normalizeScanTarget(qe.state.WildcardActiveTarget)] = qe.state.InstanceID
			}
		}
	}

	entries := s.findAllScans()
	externalIdentityCounts := make(map[string]int)
	for i := range entries {
		entry := &entries[i]
		if entry.rec.ParentTarget == "" {
			if persistedID := strings.TrimSpace(entry.rec.InstanceID); persistedID != "" {
				externalIdentityCounts[persistedID]++
			}
		}
	}
	instanceIdentity := func(entry *scanEntry) (string, bool) {
		// ScanRecord.InstanceID is immutable run ownership metadata. Once it
		// exists, queue recovery may prove that same run resumable but must never
		// replace it with an identity inferred from a target, directory, or
		// canonical record ID.
		persistedID := strings.TrimSpace(entry.rec.InstanceID)
		candidates := []string{
			qMap[filepath.Clean(entry.dir)],
			qMap[entry.rec.ID],
			qMap[normalizeScanTarget(entry.rec.Target)],
		}
		if persistedID != "" {
			for _, mappedID := range candidates {
				if mappedID == persistedID {
					return persistedID, true
				}
			}
			return persistedID, false
		}

		// Legacy records without ownership metadata can only inherit an active
		// instance ID from an exact queue-state relationship. Historical terminal
		// records are keyed by their canonical record ID; no short-alias guess is
		// permitted.
		for _, mappedID := range candidates {
			if mappedID != "" {
				return mappedID, true
			}
		}
		return entry.rec.ID, false
	}

	// First normalize every interrupted record so wildcard parent aggregation
	// below observes the recovered child statuses rather than stale running
	// values captured before the restart.
	for i := range entries {
		entry := &entries[i]
		_, resumable := instanceIdentity(entry)
		if !isInterruptedRecoverableRecord(entry.rec.Status, entry.rec.StopReason) {
			continue
		}
		if resumable {
			entry.rec.Status = "pending"
			entry.rec.StopReason = "server_restart_resuming"
			entry.rec.FinishedAt = ""
		} else if entry.rec.Status != "stopped" {
			// Only terminalize records that were mid-flight (running/pending)
			// and have no resume state. A signal-stopped record with no valid
			// queue_state is already correctly "stopped"; leave its reason
			// intact rather than rewriting it every boot.
			entry.rec.Status = "stopped"
			entry.rec.StopReason = "server_restart_no_resume_state"
			entry.rec.FinishedAt = time.Now().Format(time.RFC3339)
		}
		normalizeTerminalWildcardProgress(&entry.rec)
		s.saveScanRecordTo(&entry.rec, entry.dir)
	}

	for i := range entries {
		entry := &entries[i]
		// Skip subdomain scans — they belong to their parent wildcard scan.
		if entry.rec.ParentTarget != "" {
			continue
		}

		instID, _ := instanceIdentity(entry)
		if externalIdentityCounts[instID] > 1 {
			log.Printf("[scan] refusing to rebuild ambiguous external instance id %q claimed by %d top-level records", instID, externalIdentityCounts[instID])
			continue
		}
		if entry.rec.ScanMode == "wildcard" || entry.rec.SubScans != nil || entry.rec.SubScanTotal > 0 {
			// Rebuild the exact parent snapshot from the now-normalized child
			// records. This restores findings and physical provenance as well as
			// authoritative child counters without requiring request-time I/O.
			s.attachWildcardSubScansFrom(&entry.rec, entries)
			normalizeTerminalWildcardProgress(&entry.rec)
			s.saveScanRecordTo(&entry.rec, entry.dir)
		}

		inst := &ScanInstance{
			ID:               instID,
			Name:             entry.rec.Name,
			Targets:          entry.rec.Target,
			ParentTarget:     entry.rec.ParentTarget,
			Status:           entry.rec.Status,
			StartedAt:        entry.rec.StartedAt,
			FinishedAt:       entry.rec.FinishedAt,
			StopReason:       entry.rec.StopReason,
			Iterations:       entry.rec.Iterations,
			ToolCalls:        entry.rec.ToolCalls,
			VulnCount:        len(entry.rec.Vulns),
			TotalTokens:      entry.rec.TotalTokens,
			ScanMode:         entry.rec.ScanMode,
			Instruction:      entry.rec.Instruction,
			SeverityFilter:   entry.rec.SeverityFilter,
			Phases:           entry.rec.Phases,
			ReconMode:        entry.rec.ReconMode,
			ScanIntensity:    entry.rec.ScanIntensity,
			CompanyName:      entry.rec.CompanyName,
			LogoPath:         entry.rec.LogoPath,
			DiscordWebhook:   entry.rec.DiscordWebhook,
			Vulns:            entry.rec.Vulns,
			CurrentPhase:     entry.rec.CurrentPhase,
			SubScans:         cloneSubScanSummaries(entry.rec.SubScans),
			SubScanTotal:     entry.rec.SubScanTotal,
			SubScanCompleted: entry.rec.SubScanCompleted,
			SubScanRunning:   entry.rec.SubScanRunning,
			SubScanRemaining: entry.rec.SubScanRemaining,
			WorkStarted:      entry.rec.WorkStarted,
			events:           append([]WSEvent(nil), entry.rec.Events...),
		}
		if inst.CurrentPhase == 0 {
			inst.CurrentPhase = firstSelectedPhase(inst.Phases)
		}
		inst.ReconMode = normalizeActivityMode(inst.ReconMode)
		inst.ScanIntensity = normalizeActivityMode(inst.ScanIntensity)
		chatCfg := *s.cfg
		inst.chatCfg = &chatCfg
		s.instances[instID] = inst
	}
	// Statuses may have been rewritten on disk above (running → stopped), so
	// drop any memoized scan list built before recovery.
	s.invalidateScanListCache()
}
