package web

import (
	"fmt"
	"log"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// vulnNotificationDetails renders the Markdown body pushed to Telegram/Discord
// for a reported vulnerability. It includes the concrete exploitation evidence
// (proof + verification method + verified/manual-review status) that
// report_vulnerability's gates guarantee for actionable findings — without it
// every alert reads like an unsubstantiated claim and gets treated as a false
// positive (issue #429). Fields are written only when present, mirroring the
// PDF report's evidence section.
func vulnNotificationDetails(vs VulnSummary) string {
	var details strings.Builder
	details.WriteString(fmt.Sprintf("**%s**\n\n", vs.Title))
	if vs.Description != "" {
		details.WriteString(fmt.Sprintf("📝 **Description:**\n%s\n\n", vs.Description))
	}
	if vs.Endpoint != "" {
		details.WriteString(fmt.Sprintf("🔗 **Endpoint:** `%s`\n", vs.Endpoint))
	}
	if vs.Method != "" {
		details.WriteString(fmt.Sprintf("📡 **Method:** `%s`\n", vs.Method))
	}
	if vs.CVE != "" {
		details.WriteString(fmt.Sprintf("🏷️ **CVE:** `%s`\n", vs.CVE))
	}
	details.WriteString(fmt.Sprintf("📊 **CVSS:** `%.1f` | **Severity:** `%s`\n\n", vs.CVSS, strings.ToUpper(vs.Severity)))
	if vs.Impact != "" {
		details.WriteString(fmt.Sprintf("💥 **Impact:**\n%s\n\n", vs.Impact))
	}
	if vs.TechnicalAnalysis != "" {
		details.WriteString(fmt.Sprintf("🔬 **Technical Analysis:**\n%s\n\n", vs.TechnicalAnalysis))
	}
	if vs.PoCDescription != "" {
		details.WriteString(fmt.Sprintf("🧪 **PoC:**\n%s\n", vs.PoCDescription))
	}
	if vs.PoCScript != "" {
		details.WriteString(fmt.Sprintf("```\n%s\n```\n\n", truncateForNotification(vs.PoCScript, 800)))
	}
	// Exploitation evidence — the concrete proof (extracted data, command
	// output like `uid=0(root)`, reflected payload) that distinguishes a real
	// finding from an unsubstantiated claim. This is the fix for issue #429.
	if vs.ExploitationProof != "" {
		details.WriteString(fmt.Sprintf("🔓 **Exploitation Proof:**\n```\n%s\n```\n\n", truncateForNotification(vs.ExploitationProof, 800)))
	}
	if vs.VerificationMethod != "" {
		status := "unverified — needs manual review"
		if vs.Verified {
			status = "verified — independently reproduced"
		}
		details.WriteString(fmt.Sprintf("✅ **Verified via:** `%s` (%s)\n\n", vs.VerificationMethod, status))
	}
	if vs.Remediation != "" {
		details.WriteString(fmt.Sprintf("🛡️ **Remediation:**\n%s", vs.Remediation))
	}
	return details.String()
}

// truncateForNotification caps a code/proof block at maxBytes without splitting
// a multi-byte UTF-8 rune (so the notification never carries invalid bytes),
// appending a truncation marker when it trims.
func truncateForNotification(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	// Back up to a rune boundary.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n... (truncated)"
}

// shouldFailInstanceOnAbort reports whether an LLM-abort (no-tool / empty /
// repeated-error / rate-limit) in THIS session may mark the whole scan
// instance failed.
//
// Only a top-level single/DAST scan qualifies. A wildcard scan runs a discovery
// session plus one session per subdomain, and every one of them shares the
// parent instance ID: Phase 1 discovery normally ends with a no-tool abort
// after it has already enumerated the subdomains, and a single subdomain
// session can abort while hundreds more are still queued. Failing the instance
// from any wildcard sub-session marks a scan that is still actively running as
// "failed" (and wrongly refunds it). Wildcard parent status is decided by the
// orchestrator, so those sessions must fall through to the normal finalize.
func shouldFailInstanceOnAbort(scanMode, parentTarget string, discoveryMode bool) bool {
	if strings.EqualFold(strings.TrimSpace(scanMode), "wildcard") {
		return false
	}
	if discoveryMode {
		return false
	}
	if strings.TrimSpace(parentTarget) != "" {
		return false
	}
	return true
}

// registerSessionAgent is the single admission transition shared with exact
// stop. If registration wins, stop sees and stops this agent. If stop wins,
// status is already terminal and no session can be published or run afterward.
func (s *Server) registerSessionAgent(sess *scanSession, sctx *scanctx.ScanContext, agnt *agent.Agent) bool {
	if sess.instanceID != "" {
		// Exact stop and work admission share dispatchMu. If admission wins, its
		// positive evidence is durable before any target work starts. If stop
		// wins, the terminal status is visible before this session can publish.
		s.dispatchMu.Lock()
		s.instancesMu.RLock()
		inst := s.instances[sess.instanceID]
		if inst == nil {
			s.instancesMu.RUnlock()
			s.dispatchMu.Unlock()
			return false
		}
		inst.mu.Lock()
		canceled := false
		if sess.parentCtx != nil {
			select {
			case <-sess.parentCtx.Done():
				canceled = true
			default:
			}
		}
		if inst.Status != "running" || canceled {
			inst.mu.Unlock()
			s.instancesMu.RUnlock()
			s.dispatchMu.Unlock()
			return false
		}
		inst.sctx = sctx
		inst.agent = agnt
		inst.scanDir = sess.scanDir
		inst.lastSessionTokens = 0
		inst.WorkStarted = true
		inst.mu.Unlock()
		s.instancesMu.RUnlock()

		// Positive work admission must survive a process restart before any
		// source preparation or target activity begins. dispatchMu remains held,
		// so exact stop cannot be overwritten by this running snapshot.
		if err := s.persistExactInstanceSnapshotLocked(inst); err != nil {
			inst.mu.Lock()
			if inst.Status == "running" {
				inst.Status = "failed"
				inst.StopReason = "dispatch_evidence_persist_failed"
				inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
				inst.WorkStarted = false
			}
			inst.mu.Unlock()
			s.dispatchMu.Unlock()
			log.Printf("[scan] refusing session %s: could not persist work admission: %v", sess.id, err)
			return false
		}
		s.dispatchMu.Unlock()
	}

	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgents[sess.id] = agnt
	s.mu.Unlock()
	return true
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v\n%s", sess.id, r, debug.Stack())
			if sess.instanceID != "" {
				s.broadcastToInstance(sess.instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			} else {
				s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			}
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 0. Create and activate a per-session ScanContext for isolation.
	//    This must happen BEFORE any tool state is touched.
	sctx := scanctx.New(sess.id, sess.scanDir)
	scanctx.Activate(sctx)
	sess.sctx = sctx
	log.Printf("[scanctx] Activated context %s for target %s (dir=%s)", sctx.ID, sess.target, sess.scanDir)

	// Panic-safe persistence: register the child→parent reporting mapping so
	// reporting.PromoteToParent runs incrementally on every report_vulnerability
	// call. CleanupContext clears the mapping on session teardown.
	if sess.parentReportingCtxID != "" {
		reporting.SetParentContext(sctx.ID, sess.parentReportingCtxID)
	}

	// Parent instance publication happens atomically with agent admission below;
	// publishing the context earlier would reopen a stop-before-agent race.

	// 1. Reset per-context state if requested (context-aware)
	if sess.resetState {
		func() {
			defer logRecover("session.resetContextState")
			reporting.ResetVulnerabilitiesForContext(sctx.ID)
			notes.ResetNotesForContext(sctx.ID)
		}()
	}

	// 1b. Configure notes disk persistence → saves notes.json in scan directory
	notes.SetPersistPathForContext(sctx.ID, sess.scanDir)
	if !sess.resetState {
		// Resume scenario: load previously saved notes from disk
		notes.LoadFromDiskForContext(sctx.ID)
	}

	// 1c. Configure hypothesis/evidence ledger persistence → ledger.json.
	// The ledger lives on the ScanContext and is shared by the coordinator and
	// every delegated specialist, so persisting it makes the whole hypothesis
	// graph durable across restart/resume (not just findings and notes).
	sctx.Ledger.SetPersistPath(sess.scanDir)
	if sess.resetState {
		sctx.Ledger.Reset()
	} else {
		// Resume scenario: reload the durable hypothesis/evidence graph.
		sctx.Ledger.LoadFromDisk()
	}

	// 2. Set working directory (context-aware)
	sctx.Terminal.SetWorkDir(sess.scanDir)
	sctx.Browser.SetSessionPath(sess.scanDir)

	// 3. Create agent with session's config AND ScanContext.
	// When the per-scan code path supplied a pre-resolved llm.Client
	// (B1: provider_profile-aware endpoint), thread it through
	// agent.WithLLMClient so the agent's outbound traffic actually
	// uses the operator's chosen credentials. A nil llmClient falls
	// back to the agent's default llm.NewClient(cfg) construction,
	// preserving the legacy behavior for tests / CLI / call sites
	// that have not opted in.
	events := make(chan agent.Event, 512)
	sess.events = events
	agentOpts := []any{sctx}
	if sess.llmClient != nil {
		agentOpts = append(agentOpts, agent.WithLLMClient(sess.llmClient))
	}
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events, scopeguard.Config{
		BindAddr:           s.cfg.BindAddr,
		Port:               s.port,
		AllowLoopbackPorts: sess.allowLoopbackPorts,
		AllowLocalTargets:  s.cfg.AllowLocalTargets,
	}, agentOpts...)
	agnt.SetPhaseRestrictions(sess.phases)
	agnt.SetActivityPolicy(sess.reconMode, sess.scanIntensity, []string{sess.target, sess.parentTarget})
	if sess.discoveryMode || isReconReportOnlyPhaseSelection(sess.phases) {
		agnt.SetDiscoveryMode(true)
	}
	// Per-scan authenticated scanning and whitebox source. Empty values are
	// no-ops; non-empty values override the agent's cfg-derived defaults so
	// each scan can carry its own credentials/source without leaking across
	// sessions. SetSourceRepo only records intent — the clone/open happens
	// lazily inside Run via prepareScanEnvironment.
	if sess.targetAuth != "" {
		agnt.SetTargetAuth(sess.targetAuth)
	}
	if sess.targetAuthB != "" {
		agnt.SetTargetAuthSecondary(sess.targetAuthB)
	}
	if sess.sourceRepo != "" {
		agnt.SetSourceRepo(sess.sourceRepo)
	}
	if sess.scanContext != "" {
		agnt.SetScanContext(sess.scanContext)
	}
	if sess.codeScanMode != agent.CodeScanNone {
		agnt.SetCodeScanMode(sess.codeScanMode)
	}
	sess.agent = agnt
	if !s.registerSessionAgent(sess, sctx, agnt) {
		// Exact stop, deletion, or parent cancellation won before admission.
		// Stop-before-Run is safe because Agent.Run checks the stopped flag before
		// preparing source or touching the target.
		agnt.Stop()
		return
	}

	// 4. Initialize scan record. Resume paths preserve previously persisted
	// events, vulnerabilities, counters, and sub-scan progress.
	sess.record = s.scanRecordForSession(sess)
	s.saveScanRecordTo(sess.record, sess.scanDir)

	if !sess.resetState && sess.record != nil {
		if sess.record.Iterations > 0 {
			agnt.SetInitialIteration(sess.record.Iterations)
		}
		if briefing := formatResumeBriefing(sess.record, sctx.ID); briefing != "" {
			agnt.SetResumeBriefing(briefing)
		}
	}

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Event processor panicked: %v — continuing\n%s", r, debug.Stack())
			}
		}() // never let panic escape event processor
		for evt := range events {
			s.processEvent(evt, sess)
		}
	}()

	// 6. Build instruction with severity filter
	instruction := sess.instruction
	if len(sess.severityFilter) > 0 {
		instruction = buildSeverityPrefix(sess.severityFilter) + "\n\n" + instruction
	}

	// 7. Run agent (blocks until finished or stopped). Recheck the parent after
	// record setup; a stop racing this point either makes this check fail or
	// observes the registered agent and sets its stopped flag before Run works.
	if status, _ := s.instanceRunStatus(sess.instanceID); sess.instanceID != "" && status != "running" {
		agnt.Stop()
	}
	agnt.Run([]string{sess.target}, instruction)

	// 8. Close events channel and wait for event processor to drain
	close(events)
	<-done

	if status, stopReason := s.instanceRunStatus(sess.instanceID); isInterruptedInstanceStatus(status) {
		sess.record.Status = status
		sess.record.StopReason = stopReason
		sess.record.FinishedAt = time.Now().Format(time.RFC3339)
		// NOTE: in-memory→record merge and child→parent reporting merge
		// are deferred to sess.cleanup() (Wave C 4.2) so they survive an
		// agent panic. The deferred path is idempotent: merge dedups by
		// vuln summary key and MergeVulnsToContext skips ID/semantic
		// duplicates, so the success path merges exactly once.
		s.saveScanRecordTo(sess.record, sess.scanDir)
		return
	}

	// 8b. Abnormal LLM-side abort (agent bailed: refused tools / empty responses
	// / repeated errors / rate-limit).
	//
	// Distinguish two very different situations that both surface as "the model
	// stopped calling tools":
	//
	//   (a) The scan already reported findings — it ran the assessment and just
	//       failed to emit the final `finish` call, then rambled until the
	//       no-tool guard fired. This is effectively a COMPLETION: the report
	//       reflects real work, so record it as "finished" (and let step 10
	//       generate the report). Failing/refunding here would throw away a real
	//       result the customer is entitled to.
	//
	//   (b) The scan bailed with NOTHING to show (no findings) — a genuine
	//       malfunction that produced no result. Record it as "failed" with a
	//       diagnostic stop reason so it is never shown as a clean completion and
	//       (on hosted) is refunded.
	//
	// For (b) we update BOTH the persisted record AND the live instance: the
	// scan-status API (applyInstanceSnapshot) overlays the in-memory instance
	// status over the record, and runMultiScan's deferred finalize would
	// otherwise flip a still-"running" instance to "finished". This runs after
	// the event processor has drained (<-done above), so there is no concurrent
	// processEvent writer.
	//
	// CRITICAL: only a TOP-LEVEL single/DAST session may fail the instance on
	// abort. A wildcard scan runs one discovery session + one session per
	// subdomain, and they ALL share the parent instance ID. Phase 1 discovery
	// routinely ends with a no-tool abort AFTER it has already enumerated the
	// subdomains, and individual subdomain sessions can abort while hundreds
	// more are still queued. Failing the instance from any of those clobbers a
	// scan that is genuinely still running (the reported "running but marked
	// failed" bug) and wrongly refunds it. Wildcard parent status is owned by
	// the orchestrator (runWildcardTarget / runMultiScan), so wildcard
	// sub-sessions fall through to the normal "finished" finalize below.
	if sess.abortReason != "" && shouldFailInstanceOnAbort(sess.scanMode, sess.parentTarget, sess.discoveryMode) {
		reportedVulns := 0
		if sess.sctx != nil {
			reportedVulns = len(reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
		}
		producedResults := reportedVulns > 0 || len(sess.record.Vulns) > 0 || sess.record.CurrentPhase >= 20 || sess.record.ToolCalls >= 5
		if !producedResults {
			finishedAt := time.Now().Format(time.RFC3339)
			sess.record.Status = "failed"
			sess.record.StopReason = sess.abortReason
			sess.record.FinishedAt = finishedAt
			if sess.instanceID != "" {
				s.instancesMu.RLock()
				inst, ok := s.instances[sess.instanceID]
				s.instancesMu.RUnlock()
				if ok {
					inst.mu.Lock()
					// Never clobber a user-initiated stop/pause; only downgrade a
					// still-active instance to failed.
					if inst.Status == "running" || inst.Status == "pending" || inst.Status == "" {
						inst.Status = "failed"
						inst.StopReason = sess.abortReason
						inst.FinishedAt = finishedAt
						normalizeTerminalWildcardInstanceLocked(inst)
					}
					inst.mu.Unlock()
				}
			}
			s.saveScanRecordTo(sess.record, sess.scanDir)
			return
		}
		// (a) findings exist or testing was performed → fall through to a normal "finished" completion.
		log.Printf("[SCAN] %s: agent stopped calling tools (%s) after testing (phase %d, %d tool calls); recording as completed with report intact",
			sess.id, sess.abortReason, sess.record.CurrentPhase, sess.record.ToolCalls)
	}

	// 9. Finalize record
	sess.record.Status = "finished"
	sess.record.FinishedAt = time.Now().Format(time.RFC3339)

	// NOTE: merges are deferred to sess.cleanup() (Wave C 4.2) under
	// safe.Recover boundaries to guarantee panic-safe persistence. Both
	// mergeReportedVulnerabilitiesIntoRecord and MergeVulnsToContext are
	// idempotent (each entry keyed by vuln id / summary tuple), so the
	// clean-finish path runs the merges exactly once via cleanup().

	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 10. Generate report if requested (always generate, even for clean scans)
	if sess.genReport {
		if p, err := s.generateReportAt(sess.record, sess.scanDir); err == nil {
			log.Printf("PDF report saved: %s", p)
			// Scan-completion summary ("Scan Finished") is opt-in via
			// XALGORIX_NOTIFY_SCAN_COMPLETE (default off) so operators get only
			// per-vulnerability alerts, not a summary after every scan (including
			// clean scans). Per-finding notifications are sent separately in
			// processEvent and are unaffected by this toggle.
			if s.notifyScanComplete.Load() {
				vulnCount := len(sess.record.Vulns)
				if vulnCount > 0 {
					desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s",
						sess.target, vulnCount, time.Now().Format("15:04:05 MST"))
					if s.telegramConfigured() {
						s.sendTelegramWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
					}
				} else {
					desc := fmt.Sprintf("**Target:** %s\n**Result:** No vulnerabilities found (clean scan)\n**Completed at:** %s",
						sess.target, time.Now().Format("15:04:05 MST"))
					if s.telegramConfigured() {
						s.sendTelegramWithFile(0x2dd4bf, "✅ Scan Finished - Clean Report", desc, p)
					}
				}
			}
			if sess.instanceID != "" {
				reportEvt := WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)}
				if phaseAllowed(sess.phases, 22) {
					reportEvt.CurrentPhase = 22
				}
				s.broadcastToInstance(sess.instanceID, reportEvt)
			} else {
				s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
			}
		} else {
			log.Printf("Failed to generate PDF report: %v", err)
		}
	}
}

// processEvent handles a single agent event — forwards to WebSocket, updates scan record, sends Discord.
func (s *Server) processEvent(evt agent.Event, sess *scanSession) {
	wsEvt := WSEvent{
		Type:        evt.Type,
		Content:     evt.Content,
		ToolName:    evt.ToolName,
		ToolArgs:    evt.ToolArgs,
		AgentID:     evt.AgentID,
		Timestamp:   evt.Timestamp.Format(time.RFC3339),
		TotalTokens: evt.TotalTokens,
	}

	if evt.Type == "tool_result" {
		wsEvt.Output = evt.ToolResult.Output
		wsEvt.Error = evt.ToolResult.Error

		// Push vuln to UI in real-time when report_vulnerability succeeds
		if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
			vulnID, reported := metadataString(evt.ToolResult.Metadata, "vuln_id")
			if !reported {
				log.Printf("[VULN] report_vulnerability returned without a new vuln_id; not broadcasting stored vuln again")
			} else {
				vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
				log.Printf("[VULN] report_vulnerability tool created %s, vulns in list: %d", vulnID, len(vulns))
				latest, found := findReportedVulnerabilityByID(vulns, vulnID)
				if !found {
					log.Printf("[VULN] report_vulnerability metadata referenced %s, but it was not found in context %s", vulnID, sess.sctx.ID)
				} else {
					vs := vulnToSummary(latest)
					vs.SourceScanID = sess.id
					log.Printf("[VULN] Latest vuln: %s %s (CVSS %.1f)", vs.Severity, vs.Title, vs.CVSS)

					// Severity filter is a DISPLAY/BROADCAST gate, NOT a
					// persistence gate. Every vuln the agent reports must be
					// persisted to the scan record (and thus the on-disk
					// scan.json + the PDF report) so the report reflects
					// everything found — not just the severities the operator
					// chose to surface live. Filtering here previously dropped
					// below-threshold vulns from the record entirely, causing
					// "report shows no findings but logs show critical" (#157
					// customer feedback).
					allowed := true
					if len(sess.severityFilter) > 0 {
						allowed = false
						for _, sev := range sess.severityFilter {
							if strings.EqualFold(sev, vs.Severity) {
								allowed = true
								break
							}
						}
						log.Printf("[VULN] Severity filter active: filter=%v, allowed=%v", sess.severityFilter, allowed)
					}

					// Always persist to the record (report + on-disk source of truth).
					if appendVulnSummaryUnique(&sess.record.Vulns, vs) {
						log.Printf("[VULN] Vuln persisted to record: %s %s", vs.Severity, vs.Title)
						// Broadcast + notify only when the severity filter allows it.
						if allowed {
							wsEvt.Vulns = []VulnSummary{vs}
							log.Printf("[VULN] Vuln broadcast real-time: %s %s", vs.Severity, vs.Title)

							// Discord: vulnerability found (respects XALGORIX_DISCORD_MIN_SEVERITY)
							sevColor := 0xef4444 // red for critical/high
							switch vs.Severity {
							case "medium":
								sevColor = 0xd97706
							case "low", "info":
								sevColor = 0x3b82f6
							}
							details := vulnNotificationDetails(vs)
							// Apply Discord minimum severity filter
							if severityMeetsThreshold(vs.Severity, s.discordMinSeverity) {
								s.sendDiscordTo(s.discordWebhookForScan(sess.discordWebhook), sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details)
							} else {
								log.Printf("[DISCORD] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.discordMinSeverity)
							}
							// Apply Telegram minimum severity filter (independent of Discord)
							if s.telegramConfigured() && severityMeetsThreshold(vs.Severity, s.telegramMinSeverity) {
								s.sendTelegram(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details)
							} else if s.telegramConfigured() {
								log.Printf("[TELEGRAM] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.telegramMinSeverity)
							}
						}
					} else {
						log.Printf("[VULN] Skipping duplicate vuln already present in session record: %s %s", vs.ID, vs.Title)
					}
					if !allowed {
						log.Printf("[VULN] Vuln persisted but NOT broadcast (filtered out by severity: %s, filter: %v)", vs.Severity, sess.severityFilter)
					}
				}
			}
		}
	}

	if phase := inferCurrentPhase(wsEvt, sess.phases); phase > 0 {
		// Monotonic: the phase-progress bar only ever moves forward. The agent
		// is autonomous and non-linear — it dips back into recon between
		// exploit attempts — so a last-wins update made the bar bounce
		// backward (and, before the keyword cleanup above, snap forward on a
		// single stray request). Reporting the max reached keeps progress
		// honest and stable.
		if sess.record != nil {
			if phase > sess.record.CurrentPhase {
				sess.record.CurrentPhase = phase
			}
			wsEvt.CurrentPhase = sess.record.CurrentPhase
		} else {
			wsEvt.CurrentPhase = phase
		}
	}

	if evt.Type == "finished" {
		// An abnormal LLM-side abort (refused tools / empty responses / repeated
		// errors / rate-limit) reuses the "finished" event type but is NOT a
		// clean completion. Record the reason so finalize marks the scan failed.
		// Delegated-agent events share the root event stream. A failed specialist
		// must be surfaced to the coordinator (the agent graph marks it failed),
		// but must not poison the root session's final status: the coordinator can
		// still cover that lane itself or use another specialist.
		if evt.Aborted && evt.AgentID == "" {
			sess.abortReason = evt.AbortReason
			if sess.abortReason == "" {
				sess.abortReason = "llm_aborted"
			}
		}
		// Build set of vulns already broadcast in real-time to avoid duplicates
		seen := make(map[string]bool)
		for _, v := range sess.record.Vulns {
			seen[vulnSummaryKey(v)] = true
		}
		vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
		log.Printf("[VULN] Finished event: total vulns in system: %d, already broadcast: %d", len(vulns), len(seen))
		for _, v := range vulns {
			vs := vulnToSummary(v)
			vs.SourceScanID = sess.id
			if seen[vulnSummaryKey(vs)] {
				log.Printf("[VULN] Finished: skipping already-broadcast vuln: %s %s", v.ID, v.Title)
				continue
			}
			allowed := true
			if len(sess.severityFilter) > 0 {
				allowed = false
				for _, sev := range sess.severityFilter {
					if strings.EqualFold(sev, vs.Severity) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				wsEvt.Vulns = append(wsEvt.Vulns, vs)
				seen[vulnSummaryKey(vs)] = true
				log.Printf("[VULN] Finished: adding new vuln to final broadcast: %s %s", vs.Severity, vs.Title)
			} else {
				log.Printf("[VULN] Finished: filtered vuln (not added to broadcast): %s (filter: %v)", vs.Severity, sess.severityFilter)
			}
		}
		log.Printf("[VULN] Finished: total vulns in final broadcast: %d", len(wsEvt.Vulns))
	}

	// Track stats on per-session record
	if evt.Type == "thinking" {
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
		// If no thinking event was emitted for this turn, fallback to tracking iteration on tool_call
		if sess.record.Iterations < sess.record.ToolCalls {
			sess.record.Iterations = sess.record.ToolCalls
		}
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = sess.recordTokenOffset + evt.TotalTokens
	}

	// Update parent instance stats — ACCUMULATE across sessions (phases/subdomains),
	// don't overwrite. Each subdomain scan creates a fresh scanSession with zeroed
	// counters, so we increment the instance counters on each event.
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			if evt.Type == "thinking" {
				inst.Iterations++
			}
			if evt.Type == "tool_call" {
				inst.ToolCalls++
				if inst.Iterations < inst.ToolCalls {
					inst.Iterations = inst.ToolCalls
				}
			}
			if evt.TotalTokens > 0 {
				// Tokens are cumulative within a session but reset between sessions,
				// so we track the delta
				inst.TotalTokens += evt.TotalTokens - inst.lastSessionTokens
				inst.lastSessionTokens = evt.TotalTokens
			}
			// Vulns: route through effectiveVulnCount so the counter source
			// is consistent across the scan lifecycle. While running, this
			// returns the in-memory count (parent context for wildcard child
			// sessions, session context otherwise); after teardown the
			// helper falls back to len(inst.Vulns). See Task 3.1 in
			// .kiro/specs/findings-consistency-and-pagination/tasks.md.
			inst.VulnCount = s.effectiveVulnCount(inst, sess)
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// Filter thinking events from being stored or broadcast to the frontend
	if evt.Type == "thinking" {
		return
	}

	// Accumulate events for persistence (limit stored output size)
	savedEvt := wsEvt
	if len(savedEvt.Output) > 500 {
		savedEvt.Output = savedEvt.Output[:500] + "..."
	}
	sess.record.Events = append(sess.record.Events, savedEvt)

	// Periodically save scan record (every 10 events)
	if len(sess.record.Events)%10 == 0 {
		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	// Use instance-scoped broadcasting
	log.Printf("[VULN] Broadcasting: type=%s, instanceID=%s, vulns=%d", evt.Type, sess.instanceID, len(wsEvt.Vulns))
	if sess.instanceID != "" {
		s.broadcastToInstance(sess.instanceID, wsEvt)
	} else {
		s.broadcast(wsEvt)
	}
}

// buildSeverityPrefix creates the severity filter instruction prefix.
func buildSeverityPrefix(severityFilter []string) string {
	severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
	severities := make([]string, len(severityFilter))
	copy(severities, severityFilter)
	severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
	severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
	severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
	severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
	return severityText
}

func firstSelectedPhase(phases []int) int {
	if len(phases) == 0 {
		return 1
	}
	first := 0
	for _, phase := range phases {
		if phase < 1 || phase > 22 {
			continue
		}
		if first == 0 || phase < first {
			first = phase
		}
	}
	if first == 0 {
		return 1
	}
	return first
}

func phaseAllowed(phases []int, phase int) bool {
	if phase < 1 || phase > 22 {
		return false
	}
	if len(phases) == 0 {
		return true
	}
	for _, allowed := range phases {
		if allowed == phase {
			return true
		}
	}
	return false
}

func isReconReportOnlyPhaseSelection(phases []int) bool {
	if len(phases) == 0 {
		return false
	}
	for _, phase := range phases {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}

var phaseMentionRe = regexp.MustCompile(`(?i)\bphase\s+([0-9]{1,2})\b`)

func inferCurrentPhase(evt WSEvent, allowed []int) int {
	if phase := parsePhaseMention(evt.Content); phaseAllowed(allowed, phase) {
		return phase
	}
	switch evt.Type {
	case "queue_started", "target_started", "scan_started":
		return firstSelectedPhase(allowed)
	case "queue_finished", "report_ready":
		if phaseAllowed(allowed, 22) {
			return 22
		}
	}

	if evt.Type != "tool_call" {
		return 0
	}
	args := strings.ToLower(strings.Join(mapValues(evt.ToolArgs), " "))

	switch {
	case strings.Contains(args, "sqlmap") || strings.Contains(args, "dalfox") ||
		strings.Contains(args, "union select") || strings.Contains(args, "<script") ||
		strings.Contains(args, "sleep("):
		if phaseAllowed(allowed, 6) {
			return 6
		}
	case strings.Contains(args, "ffuf") || strings.Contains(args, "gobuster") ||
		strings.Contains(args, "dirsearch") || strings.Contains(args, "feroxbuster"):
		if phaseAllowed(allowed, 3) {
			return 3
		}
	case strings.Contains(args, "ssrf") || strings.Contains(args, "169.254.169.254"):
		if phaseAllowed(allowed, 7) {
			return 7
		}
	// Phase 8: IDOR & Broken Access Control — detect from IDOR/BAC testing patterns
	case strings.Contains(args, "idor") || strings.Contains(args, "broken access") ||
		strings.Contains(args, "access control") || strings.Contains(args, "horizontal") ||
		strings.Contains(args, "vertical privilege") || strings.Contains(args, "privilege escalation"):
		if phaseAllowed(allowed, 8) {
			return 8
		}
	// Phase 9: API & GraphQL Testing
	case strings.Contains(args, "graphql") || strings.Contains(args, "introspection") ||
		strings.Contains(args, "__schema") || strings.Contains(args, "batch query") ||
		strings.Contains(args, "rest api") || strings.Contains(args, "swagger") ||
		strings.Contains(args, "openapi"):
		if phaseAllowed(allowed, 9) {
			return 9
		}
	// Phase 10: File Upload Testing
	case strings.Contains(args, "file upload") || strings.Contains(args, "multipart") ||
		strings.Contains(args, "upload.php") || strings.Contains(args, "webshell") ||
		strings.Contains(args, "shell.php"):
		if phaseAllowed(allowed, 10) {
			return 10
		}
	// Phase 11: Deserialization & RCE
	case strings.Contains(args, "deserialize") || strings.Contains(args, "rce") ||
		strings.Contains(args, "command injection") || strings.Contains(args, "code execution") ||
		strings.Contains(args, "pickle") || strings.Contains(args, "ysoserial"):
		if phaseAllowed(allowed, 11) {
			return 11
		}
	// Phase 12: Race Conditions & Business Logic
	case strings.Contains(args, "race condition") || strings.Contains(args, "concurrent") ||
		strings.Contains(args, "business logic") || strings.Contains(args, "turbo intruder") ||
		strings.Contains(args, "time-of-check"):
		if phaseAllowed(allowed, 12) {
			return 12
		}
	// Phase 13: Subdomain Takeover
	case strings.Contains(args, "subdomain takeover") || strings.Contains(args, "dangling") ||
		strings.Contains(args, "cname") || strings.Contains(args, "can-i-take-over-xyz") ||
		strings.Contains(args, "nuclei takeover"):
		if phaseAllowed(allowed, 13) {
			return 13
		}
	// Phase 14: Open Redirect Testing
	case strings.Contains(args, "open redirect") || strings.Contains(args, "url redirect") ||
		strings.Contains(args, "redirect=") || strings.Contains(args, "next=") ||
		strings.Contains(args, "returnurl=") || strings.Contains(args, "return_to="):
		if phaseAllowed(allowed, 14) {
			return 14
		}
	// Phase 16: Cloud & Infrastructure
	case strings.Contains(args, "s3 bucket") || strings.Contains(args, "aws") ||
		strings.Contains(args, "gcp") || strings.Contains(args, "azure") ||
		strings.Contains(args, "cloud storage") || strings.Contains(args, "terraform"):
		if phaseAllowed(allowed, 16) {
			return 16
		}
	// Phase 17: WebSocket Testing
	case strings.Contains(args, "websocket") || strings.Contains(args, "ws://") ||
		strings.Contains(args, "wss://") || strings.Contains(args, "socket.io"):
		if phaseAllowed(allowed, 17) {
			return 17
		}
	// Phase 20: Exploit Verification
	case strings.Contains(args, "exploit") || strings.Contains(args, "verify exploit") ||
		strings.Contains(args, "proof of concept") || strings.Contains(args, "poc"):
		if phaseAllowed(allowed, 20) {
			return 20
		}
	// Phase 21: Novel Vulnerability Discovery
	case strings.Contains(args, "novel") || strings.Contains(args, "fuzzing") ||
		strings.Contains(args, "mutation") || strings.Contains(args, "edge case"):
		if phaseAllowed(allowed, 21) {
			return 21
		}
	// NOTE: we deliberately do NOT infer phases 4/5 from tool-arg keywords
	// like "authorization", "cookie", "login", or "session". Those tokens
	// appear in ORDINARY requests on almost every target (an authed scan
	// sends an Authorization header from the first recon request), so they
	// caused the progress bar to false-jump to a late phase during early
	// reconnaissance. Those phases advance via the agent's own phase
	// narration (parsePhaseMention above), which is a real signal.
	case strings.Contains(args, "nmap") || strings.Contains(args, "naabu") ||
		strings.Contains(args, "masscan") || strings.Contains(args, "dig ") ||
		strings.Contains(args, "nslookup") || strings.Contains(args, "host ") ||
		strings.Contains(args, "whatweb") || strings.Contains(args, "wappalyzer") ||
		strings.Contains(args, "httpx") || strings.Contains(args, "wafw00f") ||
		strings.Contains(args, "subfinder") || strings.Contains(args, "amass") ||
		strings.Contains(args, "crt.sh"):
		if phaseAllowed(allowed, 1) {
			return 1
		}
	}

	return 0
}

func parsePhaseMention(text string) int {
	match := phaseMentionRe.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	var phase int
	if _, err := fmt.Sscanf(match[1], "%d", &phase); err != nil {
		return 0
	}
	if phase < 1 || phase > 22 {
		return 0
	}
	return phase
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func formatResumeBriefing(rec *ScanRecord, contextID string) string {
	if rec == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🔄 SCENARIO RESUME BRIEFING (Continued scan session from Iteration %d):\n", rec.Iterations))
	sb.WriteString(fmt.Sprintf("Target: %s\n", rec.Target))
	if len(rec.Vulns) > 0 {
		sb.WriteString(fmt.Sprintf("Confirmed Vulnerabilities Reported So Far (%d):\n", len(rec.Vulns)))
		for _, v := range rec.Vulns {
			sb.WriteString(fmt.Sprintf(" - [%s] %s (%s)\n", strings.ToUpper(v.Severity), v.Title, v.Endpoint))
		}
	} else {
		sb.WriteString("No vulnerabilities reported yet.\n")
	}

	notesData := notes.FormatForContextID(contextID)
	if notesData != "" {
		sb.WriteString("\nDiscovered Endpoints & Target Notes:\n")
		sb.WriteString(notesData)
		sb.WriteString("\n")
	}

	var lastEvents []string
	if len(rec.Events) > 0 {
		for i := len(rec.Events) - 1; i >= 0 && len(lastEvents) < 6; i-- {
			e := rec.Events[i]
			switch e.Type {
			case "tool_call":
				lastEvents = append([]string{fmt.Sprintf("Executed tool %s with args: %v", e.ToolName, e.ToolArgs)}, lastEvents...)
			case "tool_result":
				out := e.Output
				errStr := e.Error
				if strings.Contains(out, "missing required parameter") || strings.Contains(errStr, "missing required parameter") {
					continue
				}
				if len(out) > 300 {
					out = out[:300] + "... (truncated)"
				}
				lastEvents = append([]string{fmt.Sprintf("Tool result (%s): %s", e.ToolName, out)}, lastEvents...)
			}
		}
	}
	if len(lastEvents) > 0 {
		sb.WriteString("\nRecent Execution Events Prior To Restart:\n")
		for _, te := range lastEvents {
			sb.WriteString(" • " + te + "\n")
		}
	}

	sb.WriteString("\nCONTINUE ASSESSMENT: Resume deep penetration testing from where you left off. Do not re-run basic recon steps already documented above. Target new endpoints or unverified attack vectors now.")
	return sb.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
