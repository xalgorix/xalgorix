package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// ────────────────────────────────────────────────────────

// isReplaceableResumePlaceholder accepts only the inert marker created by
// restart reconstruction. Auto-resume must never overwrite a newly reserved,
// queued, or live exact generation that happens to use the same ID.
func isReplaceableResumePlaceholder(inst *ScanInstance) bool {
	if inst == nil {
		return false
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.Status == "pending" && inst.agent == nil && inst.cancel == nil && inst.StopReason == "server_restart_resuming"
}

// runMultiScan processes targets sequentially, one at a time.
// Each target is scanned in a fully isolated scanSession.
func (s *Server) runMultiScan(req ScanRequest, scanCfg *config.Config, instanceIDs ...string) {
	normalizeScanRequestActivity(&req)

	// Defensively flatten req.Targets in case the frontend or API sent them as a comma-separated mega string
	var cleanTargets []string
	for _, raw := range req.Targets {
		fields := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
		})
		for _, f := range fields {
			if f != "" {
				cleanTargets = append(cleanTargets, f)
			}
		}
	}

	// Filter out local/internal targets to prevent self-scanning. A
	// "provision" code scan opts a specific loopback port into scope
	// (req.allowLoopbackPorts); isBlockedTargetForScan honors that allowlist
	// so the deliberately-provisioned 127.0.0.1:<port> target survives the
	// filter. For all other scans allowLoopbackPorts is empty and this is
	// identical to isBlockedTarget.
	var safeTargets []string
	for _, t := range cleanTargets {
		if s.isBlockedTargetForScan(t, req.allowLoopbackPorts) {
			log.Printf("[BLOCKLIST] Skipping blocked target: %s (local/internal IP or self-listener)", t)
		} else {
			safeTargets = append(safeTargets, t)
		}
	}
	if len(safeTargets) < len(cleanTargets) {
		log.Printf("[BLOCKLIST] Filtered %d blocked targets, %d remaining", len(cleanTargets)-len(safeTargets), len(safeTargets))
	}
	req.Targets = safeTargets

	// Create instance ID immediately
	var instanceID string
	if len(instanceIDs) > 0 && instanceIDs[0] != "" {
		instanceID = instanceIDs[0]
	} else {
		instanceID = randomSlug()
	}

	// Hold a stable advisory lock for the entire registration/resume/run
	// lifetime. The lockfile inode is never renamed, so another scanner process
	// sharing dataDir cannot execute the same queue instance concurrently.
	ownership := req.queueOwnership
	req.queueOwnership = nil
	if ownership == nil {
		var owned bool
		var err error
		ownership, owned, err = s.acquireQueueOwnership(instanceID)
		if err != nil {
			log.Printf("[queue] refusing instance %s: could not acquire ownership: %v", instanceID, err)
			return
		}
		if !owned {
			log.Printf("[queue] refusing instance %s: queue is owned by another process", instanceID)
			return
		}
	}
	defer ownership.release()

	// Register instance as pending initially
	instance := &ScanInstance{
		ID:                  instanceID,
		Name:                req.Name,
		Targets:             strings.Join(req.Targets, ", "),
		Status:              "pending",
		StartedAt:           time.Now().Format(time.RFC3339Nano),
		ScanMode:            req.ScanMode,
		Instruction:         req.Instruction,
		SeverityFilter:      req.SeverityFilter,
		Phases:              req.Phases,
		ReconMode:           req.ReconMode,
		ScanIntensity:       req.ScanIntensity,
		CurrentPhase:        firstSelectedPhase(req.Phases),
		CompanyName:         req.CompanyName,
		LogoPath:            req.LogoPath,
		DiscordWebhook:      req.DiscordWebhook,
		TargetAuth:          req.TargetAuth,
		TargetAuthSecondary: req.TargetAuthSecondary,
		SourceRepo:          req.SourceRepo,
		ScanContext:         req.ScanContext,
		SubScans:            make([]SubScanSummary, 0),
		snapshotFinalizing:  true,
		Iterations:          req.ResumeIterations,
		TotalTokens:         req.ResumeTotalTokens,
		ToolCalls:           req.ResumeToolCalls,
	}
	s.seedResumeInstanceFromRecord(instance, req)
	// Disk discovery is intentionally outside the global instance-map lock.
	// The dispatch mutex below is the serialization point that revalidates the
	// durable tombstone before any map entry can be installed.
	legacyClaimed := false
	if !req.IsResume {
		if _, err := s.loadExactDispatchSnapshot(instanceID); errors.Is(err, errDispatchSnapshotNotFound) {
			_, legacyClaimed = s.persistedInstanceIDClaim(instanceID)
		}
	}
	s.dispatchMu.Lock()
	durable, durErr := s.loadExactDispatchSnapshot(instanceID)
	if durErr == nil &&
		(isTerminalScanStatus(durable.Status) || strings.EqualFold(durable.Status, "stopping")) {
		// A durable terminal snapshot normally tombstones this id so a stale
		// dispatch can't resurrect a stopped scan. BUT a graceful shutdown
		// persists interrupted scans as "stopped" + "signal_..." while
		// deliberately PRESERVING their queue_state for resume. Those must be
		// allowed to auto-resume — otherwise the exact-snapshot tombstone
		// silently blocks every restart resume and the scans sit at "pending"
		// forever (they were dispatched but refused here).
		//
		// Only an auto-resume (req.IsResume, set exclusively by the boot
		// queue-state resumer) of a RECOVERABLE interruption may pass. A
		// user/terminal stop clears queue_state (so it's never auto-resumed)
		// and its stop reason is not signal_/panic_/restart, so it stays
		// refused on both counts.
		if req.IsResume && isInterruptedRecoverableRecord(durable.Status, durable.StopReason) {
			log.Printf("[scan] resume dispatch %q proceeding past durable %q/%q (recoverable interruption)",
				instanceID, durable.Status, durable.StopReason)
		} else {
			delete(s.dispatchReservations, instanceID)
			s.dispatchMu.Unlock()
			log.Printf("[scan] refusing dispatch %q after durable exact stop/status %q", instanceID, durable.Status)
			return
		}
	} else if durErr != nil && !errors.Is(durErr, errDispatchSnapshotNotFound) {
		delete(s.dispatchReservations, instanceID)
		s.dispatchMu.Unlock()
		log.Printf("[scan] refusing dispatch %q with unreadable durable state: %v", instanceID, durErr)
		return
	}
	s.instancesMu.Lock()
	if existing := s.instances[instanceID]; existing != nil {
		replaceableResumePlaceholder := req.IsResume && isReplaceableResumePlaceholder(existing)
		if !replaceableResumePlaceholder {
			s.instancesMu.Unlock()
			delete(s.dispatchReservations, instanceID)
			s.dispatchMu.Unlock()
			log.Printf("[scan] refusing live instance id collision for %q", instanceID)
			return
		}
		existing.mu.RLock()
		if existing.Iterations > instance.Iterations {
			instance.Iterations = existing.Iterations
		}
		if existing.TotalTokens > instance.TotalTokens {
			instance.TotalTokens = existing.TotalTokens
		}
		if existing.ToolCalls > instance.ToolCalls {
			instance.ToolCalls = existing.ToolCalls
		}
		if len(existing.Vulns) > len(instance.Vulns) {
			instance.Vulns = append([]VulnSummary(nil), existing.Vulns...)
			instance.VulnCount = len(instance.Vulns)
		}
		if len(existing.SubScans) > len(instance.SubScans) {
			instance.SubScans = cloneSubScanSummaries(existing.SubScans)
			instance.SubScanTotal = existing.SubScanTotal
			instance.SubScanCompleted = existing.SubScanCompleted
			instance.SubScanRunning = existing.SubScanRunning
			instance.SubScanRemaining = existing.SubScanRemaining
		}
		existing.mu.RUnlock()
	}
	if !req.IsResume && legacyClaimed {
		s.instancesMu.Unlock()
		delete(s.dispatchReservations, instanceID)
		s.dispatchMu.Unlock()
		log.Printf("[scan] refusing legacy persisted instance id collision for %q", instanceID)
		return
	}
	s.instances[instanceID] = instance
	delete(s.dispatchReservations, instanceID)
	s.instancesMu.Unlock()
	s.dispatchMu.Unlock()

	// Persist the queue state immediately, BEFORE the admission wait loop.
	// Previously the first saveQueueState ran only after admission (well past
	// the wait loop), so an instance parked at "pending" left ZERO disk trace.
	// On server restart both rebuildInstancesFromDisk (scan.json) and the
	// auto-resume goroutine (queue_state_*.json) found nothing → pending scans
	// were silently dropped instead of re-queued. Writing it here at CurrentIdx=0
	// means the existing auto-resume path (scanRequestFromQueueState →
	// runMultiScan) re-enters the admission loop after a restart. Thread the
	// instance ID onto the request now so the file lands at the right path.
	req.InstanceID = instanceID
	s.saveQueueState(0, req)

	// Broadcast to dashboard
	s.broadcastDashboard(WSEvent{Type: "instance_started", Content: instanceID})

	// Register cleanup before the queue wait loop so pending instances that
	// are stopped early still release server-side references.
	ranScan := false
	panicRecovered := false
	defer func() {
		if r := recover(); r != nil {
			panicRecovered = true
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v\n%s", r, debug.Stack())
			s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}

		// Mark instance as finished (if still running)
		instance.mu.Lock()
		if instance.Status == "running" {
			if panicRecovered {
				instance.Status = "stopped"
				instance.StopReason = "panic_recovered"
			} else if s.stopReq.Load() {
				instance.Status = "stopped"
				instance.StopReason = "server_shutdown"
			} else {
				instance.Status = "finished"
			}
		}
		instance.FinishedAt = time.Now().Format(time.RFC3339)
		normalizeTerminalWildcardInstanceLocked(instance)
		instance.agent = nil
		instance.cancel = nil
		instance.sctx = nil
		instance.mu.Unlock()

		// Decide queue retention now, but do not unlink anything until the exact
		// terminal aggregate has been durably committed below. A failed snapshot
		// must leave enough state for a later GET retry or process restart.
		instance.mu.RLock()
		finalStatus := instance.Status
		finalStopReason := instance.StopReason
		instance.mu.RUnlock()
		preserveQueue := shouldPreserveQueueStateOnExit(finalStatus, finalStopReason, panicRecovered)
		if !ranScan {
			preserveQueue = finalStopReason == "server_shutdown" || panicRecovered
		}
		if preserveQueue {
			log.Printf("[AUTO-RESUME] Preserving queue state after interrupted scan %s", instanceID)
		}

		// Always clean up server references (safe even if never set)
		s.mu.Lock()
		if s.currentScanID == instanceID {
			s.cancelScan = nil
			delete(s.currentAgents, instanceID)
		}
		s.mu.Unlock()

		if finalStatus == "paused" {
			s.markQueueStatePaused(instanceID)
		}
		queueDoneEvt := WSEvent{Type: "queue_finished", Content: "Scan queue ended"}
		switch finalStatus {
		case "paused":
			queueDoneEvt = WSEvent{Type: "paused", Content: "Scan queue paused"}
		case "stopped":
			if strings.HasPrefix(finalStopReason, "signal_") || finalStopReason == "panic_recovered" {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue interrupted; resume state saved"}
			} else {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue stopped"}
			}
		default:
			if phaseAllowed(req.Phases, 22) {
				queueDoneEvt.CurrentPhase = 22
			}
		}
		if finalStatus != "stopped" || !instanceHasExactStopEvent(instance) {
			s.broadcastToInstance(instanceID, queueDoneEvt)
		}
		// The final event is buffered and every session cleanup has run, so a
		// later exact-stop request may safely retry terminal persistence if the
		// writes below encounter a transient disk failure.
		instance.mu.Lock()
		instance.snapshotReady = true
		instance.mu.Unlock()
		// Persist the coherent terminal aggregate before exposing it through the live API.
		// A transient disk error keeps snapshotFinalizing true and is retried;
		// terminal visibility never outruns durable findings/events.
		var snapshotErr error
		for attempt := 0; attempt < 3; attempt++ {
			snapshotErr = s.persistExactInstanceSnapshot(instance)
			if snapshotErr == nil {
				break
			}
			log.Printf("[scan] failed to persist exact terminal snapshot for %s (attempt %d/3): %v", instanceID, attempt+1, snapshotErr)
			time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
		}
		if snapshotErr == nil {
			instance.mu.Lock()
			instance.snapshotFinalizing = false
			instance.mu.Unlock()
			if !preserveQueue {
				if err := s.clearQueueStateDurable(instanceID); err != nil {
					log.Printf("[queue] exact snapshot for %s is durable but queue deletion failed: %v", instanceID, err)
				}
			}
		} else {
			log.Printf("[queue] preserving queue state for %s because exact terminal persistence failed", instanceID)
		}
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		time.Sleep(500 * time.Millisecond)

		// Only set running=false if no other instances are running
		s.instancesMu.RLock()
		stillRunning := false
		for _, inst := range s.instances {
			inst.mu.RLock()
			isRunning := inst.Status == "running" && inst.ID != instanceID
			inst.mu.RUnlock()
			if isRunning {
				stillRunning = true
				break
			}
		}
		s.instancesMu.RUnlock()
		if !stillRunning {
			s.running.Store(false)
		}
		// Wake exactly one admission waiter (if any) now that this
		// instance has finished and a slot is free. Non-blocking send:
		// the channel is buffered to len=1 so a single pending wake is
		// always queued; additional terminate signals while a wake is
		// already pending are intentionally collapsed (the recipient
		// will re-check via runningCount and either admit or wait
		// again on the safety-net ticker). This wake fires regardless
		// of whether the scan finished, errored, was stopped, or
		// panicked, because it lives in the unconditional defer.
		s.notifyAdmissionWake()
		log.Printf("[INFO] runMultiScan instance %s exited (ranScan=%v)", instanceID, ranScan)
	}()

	// Wait in queue until slot is available.
	// CRITICAL: The slot check + status transition MUST be atomic under a single
	// Lock to prevent a TOCTOU race where two goroutines both see runningCount=0
	// and start simultaneously, causing mutual process kills.
	//
	// Wakeup model (Task 11.2 / R3.2, R3.6): instead of busy-sleeping for 2s
	// between admission attempts, we park on a select that wakes when
	// (a) another instance terminates and signals s.admissionWake (fair
	// wakeup — exactly one waiter per terminate), (b) the 2s ticker fires
	// as a safety-net, or (c) the server is shutting down. The top of the
	// loop re-checks per-instance and global stop flags after every wake.
	admissionTicker := time.NewTicker(2 * time.Second)
	defer admissionTicker.Stop()
	for {
		// Check if THIS instance was stopped (via per-instance stop API,
		// Stop All, pause, or delete — all of which flip instance.Status).
		// We intentionally do NOT check the global stopReq here: it is a
		// shared flag whose lifetime is decoupled from this scan (it stays
		// true after a Stop All / SIGTERM until some other scan clears it).
		// Checking it here caused pending scans to mark themselves
		// "user_stopped" with no user action against THIS scan (the
		// stopReq.Store(false) clear-at-start hack was a workaround that in
		// turn broke Stop All). The per-instance status is the authoritative
		// signal: every stop path sets it, and we observe it on every wake.
		instance.mu.RLock()
		stopped := instance.Status == "stopped"
		instance.mu.RUnlock()
		if stopped {
			// Early return — defer is already registered and will clean up
			return
		}

		// ATOMIC: Check resource availability AND transition to running under a single lock.
		// This eliminates the TOCTOU race window between resource check and status update.
		gotSlot := false
		s.instancesMu.Lock()
		runningCount := 0
		recentAdmissions := 0
		now := time.Now()
		for _, inst := range s.instances {
			inst.mu.RLock()
			if inst.Status == "running" {
				runningCount++
				if admissionMemoryUnreflected(inst.StartedAt, now) {
					recentAdmissions++
				}
			}
			inst.mu.RUnlock()
		}
		canAdmit, reason := resources.CanAdmitScanWithReservations(
			runningCount,
			recentAdmissions,
		)
		instance.mu.Lock()
		if canAdmit && instance.Status == "pending" {
			instance.Status = "running"
			instance.StartedAt = time.Now().Format(time.RFC3339)
			gotSlot = true
			log.Printf("[ADMIT] Scan %s started (running: %d) — %s", instanceID, runningCount+1, reason)
		}
		instance.mu.Unlock()
		s.instancesMu.Unlock()

		if gotSlot {
			break
		}
		// Admission refused — record the event and emit a structured INFO log.
		// Each refusal observation is a distinct event; ticker cadence keeps
		// counter growth proportional to wait time, while admissionWake
		// signals collapse multiple near-simultaneous terminates into a
		// single fair wakeup for the next waiter.
		safe.IncAdmissionRefusal()
		ceiling, _ := resources.EffectiveMaxInstancesForAdmission(
			runningCount,
			recentAdmissions,
		)
		level, _ := resources.CurrentLevel()
		log.Printf("[admission] refused level=%s reason=%q ceiling=%d running=%d recent_admissions=%d scan=%s",
			level.String(), reason, ceiling, runningCount, recentAdmissions, instanceID)

		// Park on the wake channel, the safety-net ticker, or shutdown.
		select {
		case <-s.admissionWake:
			// A peer instance freed a slot — re-check immediately.
		case <-admissionTicker.C:
			// Periodic safety-net wake; prevents indefinite waits if a
			// signal is ever missed (e.g. concurrent terminates collapse
			// onto a single buffered slot).
		case <-s.shutdownChan:
			// Server is shutting down. Mark this pending instance stopped
			// and exit; the defer will run the rest of cleanup.
			instance.mu.Lock()
			if instance.Status == "pending" {
				instance.Status = "stopped"
				instance.StopReason = "server_shutdown"
				instance.FinishedAt = time.Now().Format(time.RFC3339)
			}
			instance.mu.Unlock()
			return
		}
	}

	// Instance got a slot — mark that the scan ran for full cleanup
	ranScan = true

	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

	// ── PRE-SESSION CLEANUP ──
	// IMPORTANT: This runs AFTER the queue wait. Do not clear the queue file
	// before the refreshed state is written; resumed scans rely on it if the
	// process exits during admission/startup.
	req.InstanceID = instanceID // (re)thread instance ID; also set before the admission wait
	s.running.Store(true)
	scanDiscordWebhook := strings.TrimSpace(req.DiscordWebhook)
	if scanDiscordWebhook == "" {
		scanDiscordWebhook = s.discordWebhook
	}

	if req.IsResume {
		log.Printf("[AUTO-RESUME] Skipping state reset — preserving vulns, notes, and recon files from previous session")
		// NOTE: Do NOT call terminal.KillAllProcesses() here — it kills ALL
		// processes globally, which would destroy a running instance's tools.
		// Per-context cleanup handles process termination on session boundaries.
	} else {
		// Fresh scan — only clean per-instance state, NOT global state.
		// Global resets (reporting.ResetVulnerabilities, notes.ResetNotes,
		// terminal.KillAllProcesses) would destroy another queued instance's
		// methodology workflow. Per-context resets happen in executeScanSession.
		func() {
			defer logRecover("multiScan.cleanTmpSubdomainFiles")
			cleanTmpSubdomainFiles()
		}()
	}
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(0, req)
	if req.ResumeQueueStatePath != "" && filepath.Clean(req.ResumeQueueStatePath) != filepath.Clean(s.queueStatePathForInstance(instanceID)) {
		s.clearQueueStatePath(req.ResumeQueueStatePath)
	}

	s.broadcastToInstance(instanceID, WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	// Discord: scan started
	s.sendDiscordTo(scanDiscordWebhook, 0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	// Telegram: scan started
	if s.telegramConfigured() {
		s.sendTelegram(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	}

	interruptedQueue := false
	for i, target := range req.Targets {
		// Per-instance stop/pause: Stop All, single-stop, pause, and delete
		// all flip instance.Status, which we observe here. The global stopReq
		// is intentionally not consulted (see the admission-loop note above).
		instance.mu.RLock()
		instStatus := instance.Status
		instance.mu.RUnlock()
		if instStatus == "stopped" || instStatus == "paused" {
			interruptedQueue = true
			if instStatus == "paused" {
				s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan queue paused"})
			} else if !instanceHasExactStopEvent(instance) {
				s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			}
			break
		}

		// Update queue state after each target
		s.saveQueueState(i, req)

		// No per-target timeout — let scans run indefinitely; user uses stop button
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		// Store cancel on the instance so per-instance stop can cancel the scan context
		instance.mu.Lock()
		instance.cancel = cancel
		instance.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			// Each target gets full wildcard treatment: Phase 1 subdomain discovery + Phase 2 per-subdomain scan.
			// This applies whether the user provides 1 or 300+ root domains.
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		case "dast":
			s.runDASTTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		instance.mu.RLock()
		instStatusAfterTarget := instance.Status
		instance.mu.RUnlock()
		stopRequested := s.stopReq.Load() || s.instanceInterrupted(instanceID) || ctx.Err() != nil
		if shouldAdvanceQueueAfterTarget(stopRequested, instStatusAfterTarget) {
			s.saveQueueState(i+1, req)
		} else {
			interruptedQueue = true
		}

		cancel() // always cancel context after target is done
	}

	if interruptedQueue {
		log.Printf("[INFO] runMultiScan queue interrupted before completion")
		return
	}

	// Queue-level scan completion summary — use the instance's accumulated
	// vulnerability count (don't read from inst.sctx.ID; it may point to a
	// cleaned-up session context). The helper applies the same opt-in gate as
	// the per-report Telegram notification.
	vulnCount := 0
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.RLock()
		vulnCount = inst.VulnCount
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()
	s.sendScanCompletionSummary(scanDiscordWebhook, totalTargets, vulnCount)

	log.Printf("[INFO] runMultiScan main body complete")
}

// sendScanCompletionSummary sends the queue-level completion notification to
// the configured Discord and Telegram channels. Completion notifications are
// opt-in; per-finding alerts are sent elsewhere and are unaffected.
func (s *Server) sendScanCompletionSummary(discordWebhook string, totalTargets, vulnCount int) {
	if !s.notifyScanComplete.Load() {
		return
	}

	if vulnCount > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, vulnCount, time.Now().Format("15:04:05 MST"))
		s.sendDiscordTo(discordWebhook, 0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		}
	} else {
		s.sendDiscordTo(discordWebhook, 0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		}
	}
}

// ────────────────────────────────────────────────────────
// Mode-specific target handlers
// ────────────────────────────────────────────────────────

// makeScanDir creates a per-target scan directory with nested structure: target/date/randomslug
func (s *Server) makeScanDir(target string) string {
	dateDir := time.Now().Format("2006-01-02")
	scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
	scanDir := filepath.Join(s.dataDir, target, dateDir, scanDirName)
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		log.Printf("[ERROR] Failed to create scan directory %s: %v", scanDir, err)
	}
	return scanDir
}

func (s *Server) findLatestScanDirForTarget(target string) string {
	cleanTarget := normalizeScanTarget(target)
	if cleanTarget == "" {
		return ""
	}
	var latestDir string
	var latestTime time.Time
	for _, entry := range s.findAllScans() {
		if normalizeScanTarget(entry.rec.Target) == cleanTarget {
			t, err := time.Parse(time.RFC3339Nano, entry.rec.StartedAt)
			if err != nil {
				t, _ = time.Parse(time.RFC3339, entry.rec.StartedAt)
			}
			if t.After(latestTime) || latestDir == "" {
				latestTime = t
				latestDir = entry.dir
			}
		}
	}
	return latestDir
}

func (s *Server) scanDirForResume(req ScanRequest, target string) (string, bool) {
	if !req.IsResume {
		return s.makeScanDir(target), false
	}
	if req.ResumeScanDir != "" {
		if req.ResumeActiveTarget == "" || req.ResumeActiveTarget == target {
			if dir, ok := s.resumeScanDirOrNew(req.ResumeScanDir, target); ok {
				return dir, true
			}
		}
	}
	if latestDir := s.findLatestScanDirForTarget(target); latestDir != "" {
		log.Printf("[AUTO-RESUME] Resuming latest existing scan dir on disk: %s", latestDir)
		return latestDir, true
	}
	return s.makeScanDir(target), false
}

func (s *Server) scanDirForWildcardSubdomainResume(req ScanRequest, subdomain string, subIndex int) (string, bool) {
	if !req.IsResume || req.ResumeSubScanDir == "" {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubIndex != subIndex {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubScanTarget != "" && req.ResumeSubScanTarget != subdomain {
		return s.makeScanDir(subdomain), false
	}
	return s.resumeScanDirOrNew(req.ResumeSubScanDir, subdomain)
}

func (s *Server) resumeScanDirOrNew(scanDir, target string) (string, bool) {
	cleanDir := filepath.Clean(scanDir)
	dataDir := filepath.Clean(s.dataDir)
	rel, err := filepath.Rel(dataDir, cleanDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		log.Printf("[AUTO-RESUME] Ignoring unsafe resume scan dir %q", scanDir)
		return s.makeScanDir(target), false
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		log.Printf("[AUTO-RESUME] Failed to reuse scan dir %s: %v", cleanDir, err)
		return s.makeScanDir(target), false
	}
	return cleanDir, true
}

func loadScanRecordFromDir(scanDir string) (*ScanRecord, bool) {
	if scanDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(scanDir, "scan.json"))
	if err != nil {
		return nil, false
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

func subdomainTargetsFromRecord(rec *ScanRecord) []string {
	if rec == nil {
		return nil
	}
	seen := make(map[string]bool)
	targets := make([]string, 0, len(rec.SubScans))
	for _, child := range rec.SubScans {
		target := strings.TrimSpace(child.Target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	return targets
}

// runSingleTarget handles a single-site mode scan for one target.
func (s *Server) runSingleTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir, resumed := s.scanDirForResume(req, target)
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:  target,
		ActiveScanDir: scanDir,
		ActiveScanID:  filepath.Base(scanDir),
	})

	instruction := "This is a SINGLE TARGET scan. Do NOT enumerate subdomains or perform wildcard discovery. Only test the exact target URL provided. Focus on the main domain/IP only. " + req.Instruction
	if resumed {
		instruction += " This is an AUTO-RESUMED scan. Before doing new work, read existing notes and files in the current workspace, then continue from the last saved evidence instead of starting discovery from scratch."
	}

	// Inject phase filter if the user selected specific phases
	instruction += buildPhaseFilterInstruction(req.Phases)
	instruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("Scanning target %d/%d: %s", idx+1, total, target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	sess := &scanSession{
		id:                 filepath.Base(scanDir),
		target:             target,
		scanDir:            scanDir,
		cfg:                scanCfg,
		server:             s,
		instruction:        buildAutonomousInstruction(target, instruction, scanCfg.AllowLocalTargets),
		codeScanMode:       req.codeScanMode,
		allowLoopbackPorts: req.allowLoopbackPorts,
		name:               req.Name,
		userInstruction:    req.Instruction,
		severityFilter:     req.SeverityFilter,
		discordWebhook:     req.DiscordWebhook,
		discoveryMode:      false,
		genReport:          true,
		resetState:         !resumed,
		instanceID:         req.InstanceID,
		parentCtx:          ctx,
		scanMode:           "single",
		companyName:        req.CompanyName,
		logoPath:           req.LogoPath,
		phases:             req.Phases,
		reconMode:          req.ReconMode,
		scanIntensity:      req.ScanIntensity,
		targetAuth:         req.TargetAuth,
		targetAuthB:        req.TargetAuthSecondary,
		sourceRepo:         req.SourceRepo,
		scanContext:        req.ScanContext,
		llmClient:          s.scanLLMClientForRequest(req, scanCfg),
	}
	s.executeScanSession(sess)
	if s.instanceInterrupted(req.InstanceID) || s.stopReq.Load() || (ctx != nil && ctx.Err() != nil) {
		return
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("Target %d/%d completed: %s", idx+1, total, target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runDASTTarget handles a DAST mode scan for one target URL.
func (s *Server) runDASTTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir, resumed := s.scanDirForResume(req, target)
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:  target,
		ActiveScanDir: scanDir,
		ActiveScanID:  filepath.Base(scanDir),
	})

	dastInstruction := buildDASTInstruction(target, scanCfg.AllowLocalTargets)
	if req.Instruction != "" {
		dastInstruction += "\n\n" + req.Instruction
	}
	if resumed {
		dastInstruction += "\n\n## AUTO-RESUME\nRead existing notes and files in the current workspace first, then continue from the last saved evidence instead of starting from scratch."
	}
	dastInstruction += buildPhaseFilterInstruction(req.Phases)
	dastInstruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[DAST] Scanning URL: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	sess := &scanSession{
		id:                 filepath.Base(scanDir),
		target:             target,
		scanDir:            scanDir,
		cfg:                scanCfg,
		server:             s,
		instruction:        dastInstruction,
		codeScanMode:       req.codeScanMode,
		allowLoopbackPorts: req.allowLoopbackPorts,
		name:               req.Name,
		userInstruction:    req.Instruction,
		severityFilter:     req.SeverityFilter,
		discordWebhook:     req.DiscordWebhook,
		discoveryMode:      false,
		genReport:          true,
		resetState:         !resumed,
		instanceID:         req.InstanceID,
		parentCtx:          ctx,
		scanMode:           "dast",
		companyName:        req.CompanyName,
		logoPath:           req.LogoPath,
		phases:             req.Phases,
		reconMode:          req.ReconMode,
		scanIntensity:      req.ScanIntensity,
		targetAuth:         req.TargetAuth,
		targetAuthB:        req.TargetAuthSecondary,
		sourceRepo:         req.SourceRepo,
		scanContext:        req.ScanContext,
		llmClient:          s.scanLLMClientForRequest(req, scanCfg),
	}
	s.executeScanSession(sess)
	if s.instanceInterrupted(req.InstanceID) || s.stopReq.Load() || (ctx != nil && ctx.Err() != nil) {
		return
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[DAST] Completed: %s", target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// beginWildcardSubScan is the serialization point between per-host dispatch
// and an exact stop. If dispatch wins, the stop snapshot includes immutable
// positive evidence (ID + started_at). If stop wins, no new child can start.
func (s *Server) beginWildcardSubScan(instanceID string, index int, target, childID string) bool {
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst == nil {
		return false
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.Status != "running" || index < 0 || index >= len(inst.SubScans) {
		return false
	}
	child := inst.SubScans[index]
	child.Target = target
	child.Status = "running"
	child.ID = childID
	if child.StartedAt == "" {
		child.StartedAt = time.Now().Format(time.RFC3339Nano)
	}
	inst.SubScans[index] = child
	inst.SubScanRunning = 1
	remaining := inst.SubScanTotal - inst.SubScanCompleted - 1
	if remaining < 0 {
		remaining = 0
	}
	inst.SubScanRemaining = remaining
	return true
}

// runWildcardTarget handles wildcard mode: Phase 1 subdomain discovery, then Phase 2 per-subdomain scanning.
func (s *Server) runWildcardTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	// ── Stable parent reporting context for vuln accumulation ──
	// All subdomain sessions merge their vulns into this context.
	// It persists across the entire wildcard scan and is cleaned up at the end.
	// The wildcard input is normalized independently from discovery: the
	// registrable root drives enumeration while the exact operator-supplied
	// host remains a mandatory assessment subject (see wildcard_target.go).
	wt := parseWildcardTarget(target)
	parentReportingCtxID := fmt.Sprintf("wc-%s-%s", req.InstanceID, sanitizeTarget(target))
	if !req.IsResume {
		reporting.ResetVulnerabilitiesForContext(parentReportingCtxID) // start clean
	}
	defer func() {
		// Final cleanup of the parent reporting context
		reporting.CleanupContext(parentReportingCtxID)
		log.Printf("[wildcard] Cleaned up parent reporting context: %s", parentReportingCtxID)
	}()

	// ── PHASE 1: Subdomain Discovery ──
	scanDir, resumed := s.scanDirForResume(req, target)
	subdomains := append([]string(nil), req.ResumeSubdomains...)
	resumeFromSubIndex := 0
	var parentRecord *ScanRecord
	if resumed && req.ResumeDiscoveryDone {
		resumeFromSubIndex = req.ResumeSubIndex
		if len(subdomains) == 0 {
			if rec, ok := loadScanRecordFromDir(scanDir); ok {
				parentRecord = rec
				subdomains = subdomainTargetsFromRecord(rec)
			}
		}
		if len(subdomains) == 0 {
			subdomains = s.collectSubdomains(scanDir, wt.Root, "")
		}
		log.Printf("[AUTO-RESUME] Resuming wildcard scan for %s at subdomain index %d/%d (scanDir=%s)", target, resumeFromSubIndex, len(subdomains), scanDir)
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:           "target_started",
			Content:        fmt.Sprintf("[AUTO-RESUME] Resuming wildcard scan for %s at subdomain %d/%d", target, minInt(resumeFromSubIndex+1, len(subdomains)), len(subdomains)),
			Target:         target,
			AgentID:        filepath.Base(scanDir),
			TargetIndex:    idx + 1,
			TotalTargets:   total,
			SubTargetTotal: len(subdomains),
			ParentTarget:   target,
			CurrentPhase:   firstSelectedPhase(req.Phases),
		})
	} else {
		s.saveQueueState(idx, req, queueProgress{
			ActiveTarget:  target,
			ActiveScanDir: scanDir,
			ActiveScanID:  filepath.Base(scanDir),
		})

		discoveryRatePolicy := agent.EffectiveRequestRatePolicy(scanCfg, req.Instruction)
		// Organization-wide enumeration runs against the registrable root
		// (www.example.com -> example.com), never the raw input string.
		discoveryInstruction := buildDiscoveryInstruction(wt.Root, req.ReconMode, discoveryRatePolicy)
		if req.Instruction != "" {
			discoveryInstruction += "\n\n" + req.Instruction
		}
		discoveryInstruction += buildActivityPolicyInstruction(req.ReconMode, req.ScanIntensity)

		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_started",
			Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
			Target:       target,
			AgentID:      filepath.Base(scanDir),
			TargetIndex:  idx + 1,
			TotalTargets: total,
			CurrentPhase: 1,
		})

		// Save the discovery session's context ID so we can read notes after cleanup.
		// skipNotesCleanup=true prevents cleanup() from deleting the notes store,
		// keeping them available for collectSubdomains' Layer 3 (notes fallback).
		discoverySess := &scanSession{
			id:                 filepath.Base(scanDir),
			target:             target,
			scanDir:            scanDir,
			cfg:                scanCfg,
			server:             s,
			instruction:        discoveryInstruction,
			codeScanMode:       req.codeScanMode,
			allowLoopbackPorts: req.allowLoopbackPorts,
			name:               req.Name,
			userInstruction:    req.Instruction,
			severityFilter:     req.SeverityFilter,
			discordWebhook:     req.DiscordWebhook,
			discoveryMode:      true,
			genReport:          false,
			resetState:         true,
			instanceID:         req.InstanceID,
			parentCtx:          ctx,
			scanMode:           "wildcard",
			skipNotesCleanup:   true, // preserve notes for subdomain collection
			companyName:        req.CompanyName,
			logoPath:           req.LogoPath,
			phases:             req.Phases,
			reconMode:          req.ReconMode,
			scanIntensity:      req.ScanIntensity,
			targetAuth:         req.TargetAuth,
			targetAuthB:        req.TargetAuthSecondary,
			sourceRepo:         req.SourceRepo,
			scanContext:        req.ScanContext,
			llmClient:          s.scanLLMClientForRequest(req, scanCfg),
		}
		s.executeScanSession(discoverySess)
		if s.instanceInterrupted(req.InstanceID) {
			return
		}
		parentRecord = discoverySess.record

		// Capture the discovery session's context ID for notes lookup.
		// The sctx was set during executeScanSession and its notes were preserved.
		discoveryCtxID := ""
		if discoverySess.sctx != nil {
			discoveryCtxID = discoverySess.sctx.ID
		}

		// Read discovered subdomains — use discovery context ID for notes fallback
		subdomains = s.collectSubdomains(scanDir, wt.Root, discoveryCtxID)

		// Now clean up the discovery notes (deferred from skipNotesCleanup)
		if discoveryCtxID != "" {
			notes.CleanupContext(discoveryCtxID)
			log.Printf("[wildcard] Cleaned up discovery notes context: %s", discoveryCtxID)
		}
	}

	// Mandatory inventory merge: the exact operator-supplied target (with its
	// original scheme/port/path context when provided) and the authorized
	// registrable root are ALWAYS assessment subjects. An empty or filtered
	// discovery result can never remove them - this merge is the last word
	// on inventory membership. It is order-stable, so resume indexes that
	// were persisted against the earlier inventory remain valid.
	subdomains = mergeWildcardInventory(subdomains, wt)

	if req.IsResume {
		// Rebuild the parent accumulation context from the durable child
		// records: previously verified findings must not disappear (nor be
		// re-attributed to the first resumed child) after a restart.
		if parentRecord == nil {
			parentRecord, _ = loadScanRecordFromDir(scanDir)
		}
		if n := s.reseedWildcardParentVulnerabilities(parentReportingCtxID, req.InstanceID, parentRecord); n > 0 {
			log.Printf("[AUTO-RESUME] Restored %d previously verified findings into parent reporting context for %s", n, target)
			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:    "message",
				Target:  target,
				Content: fmt.Sprintf("[AUTO-RESUME] Restored %d previously verified findings from completed host assessments.", n),
			})
		}
	}

	log.Printf("[INFO] Assessment inventory for %s: %d host(s) (supplied target %q, discovery root %q)", target, len(subdomains), wt.Assessment, wt.Root)
	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[PHASE 1] Discovery complete: %d host(s) in the assessment inventory for %s (supplied target and authorized root domain always included). Now scanning each individually.", len(subdomains), target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	// A wildcard target is one user-visible scan, but every discovered live
	// subdomain is intentionally expanded into a full agent session: coverage
	// takes priority over an arbitrary fan-out limit. A positive limit remains
	// available as an explicit emergency control, but the default is unlimited.
	wildcardLimit := 0
	if scanCfg != nil {
		wildcardLimit = scanCfg.MaxWildcardSubdomains
	}
	if wildcardLimit > 0 && len(subdomains) > wildcardLimit {
		// The cap applies to DISCOVERED candidates. Mandatory subjects (the
		// exact operator-supplied target and the authorized root) always
		// survive it - an explicit resource limit must never drop the host
		// the operator actually asked for. Order-stable and idempotent
		// across a resume rebuild.
		kept := subdomains[:wildcardLimit:wildcardLimit]
		for _, entry := range subdomains[wildcardLimit:] {
			if isMandatoryWildcardEntry(entry, wt) {
				kept = append(kept, entry)
			}
		}
		skipped := len(subdomains) - len(kept)
		subdomains = kept
		log.Printf("[wildcard] Explicitly capped full subdomain scans at %d; skipping %d discovered candidates (XALGORIX_MAX_WILDCARD_SUBDOMAINS); mandatory targets retained", len(kept), skipped)
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:    "message",
			Target:  target,
			Content: fmt.Sprintf("⚠️ Explicit wildcard scan resource cap: scanning %d host(s) (mandatory targets retained); %d additional discovered candidates were not expanded into full LLM sessions.", len(subdomains), skipped),
		})
	}
	// Preserve per-child metadata (scan id, lifecycle timestamps, vuln/token
	// counters, and any pre-restart "failed" outcome) when rebuilding the
	// pending list: a resume rebuild that reset these would orphan the child
	// scan records on disk, break a later vuln reseed, and re-brand a failed
	// host assessment as finished.
	existingChildren := make(map[string]SubScanSummary)
	if parentRecord != nil {
		for _, child := range parentRecord.SubScans {
			if prev, ok := existingChildren[child.Target]; !ok || (child.ID != "" && prev.ID == "") {
				existingChildren[child.Target] = child
			}
		}
	}
	pendingSubScans := make([]SubScanSummary, 0, len(subdomains))
	resumeFromSubIndex = clampInt(resumeFromSubIndex, 0, len(subdomains))
	for i, subdomain := range subdomains {
		child := existingChildren[subdomain]
		child.Target = subdomain
		child.Status = "pending"
		if i < resumeFromSubIndex {
			child.Status = "finished"
			if strings.EqualFold(strings.TrimSpace(existingChildren[subdomain].Status), "failed") {
				child.Status = "failed"
			}
		}
		pendingSubScans = append(pendingSubScans, child)
	}
	if parentRecord == nil {
		parentRecord, _ = loadScanRecordFromDir(scanDir)
	}
	if parentRecord != nil {
		parentRecord.SubScans = pendingSubScans
		parentRecord.SubScanTotal = len(subdomains)
		parentRecord.SubScanCompleted = resumeFromSubIndex
		parentRecord.SubScanRunning = 0
		parentRecord.SubScanRemaining = len(subdomains) - resumeFromSubIndex
		parentRecord.Status = "running"
		s.saveScanRecordTo(parentRecord, scanDir)
		s.mirrorWildcardProgress(req.InstanceID, parentRecord)
	}
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:          target,
		ActiveScanDir:         scanDir,
		ActiveScanID:          filepath.Base(scanDir),
		WildcardDiscoveryDone: true,
		WildcardSubdomains:    subdomains,
		WildcardSubIndex:      resumeFromSubIndex,
	})
	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:           "subdomains_discovered",
		Content:        fmt.Sprintf("Discovered %d subdomains for %s", len(subdomains), target),
		Target:         target,
		Output:         strings.Join(subdomains, "\n"),
		TargetIndex:    idx + 1,
		TotalTargets:   total,
		SubTargetTotal: len(subdomains),
		ParentTarget:   target,
		CurrentPhase:   firstSelectedPhase(req.Phases),
	})

	// lastOutcome is the outcome of the child dispatch just moved past ("" when
	// not applicable). A failed or crashed host assessment must never be
	// recorded as "finished": unfinished work stays identifiable in the
	// parent inventory while the loop continues to the remaining hosts.
	saveWildcardProgress := func(nextIndex, runningIndex int, activeSubTarget, activeSubScanDir, lastOutcome string) {
		nextIndex = clampInt(nextIndex, 0, len(subdomains))
		if parentRecord == nil {
			parentRecord, _ = loadScanRecordFromDir(scanDir)
		}
		if parentRecord != nil {
			existing := make(map[string]SubScanSummary)
			for _, child := range parentRecord.SubScans {
				existing[child.Target] = child
			}
			children := make([]SubScanSummary, 0, len(subdomains))
			completed := 0
			running := 0
			for i, childTarget := range subdomains {
				child := existing[childTarget]
				child.Target = childTarget
				switch {
				case i == runningIndex:
					child.Status = "running"
					if activeSubScanDir != "" && childTarget == activeSubTarget {
						child.ID = filepath.Base(activeSubScanDir)
						if child.StartedAt == "" {
							child.StartedAt = time.Now().Format(time.RFC3339)
						}
					}
					running++
				case i < nextIndex:
					if child.Status == "" || child.Status == "pending" || child.Status == "running" {
						child.Status = "finished"
						if i == nextIndex-1 && lastOutcome != "" {
							child.Status = lastOutcome
						}
					}
					if child.FinishedAt == "" {
						child.FinishedAt = time.Now().Format(time.RFC3339)
					}
					completed++
				default:
					if child.Status == "" || child.Status == "running" {
						child.Status = "pending"
					}
				}
				children = append(children, child)
			}
			parentRecord.SubScans = children
			parentRecord.SubScanTotal = len(subdomains)
			parentRecord.SubScanCompleted = completed
			parentRecord.SubScanRunning = running
			parentRecord.SubScanRemaining = len(subdomains) - completed - running
			parentRecord.Status = "running"
			s.instancesMu.RLock()
			inst := s.instances[req.InstanceID]
			s.instancesMu.RUnlock()
			if inst != nil {
				inst.mu.RLock()
				if inst.TotalTokens > parentRecord.TotalTokens {
					parentRecord.TotalTokens = inst.TotalTokens
				}
				if inst.Iterations > parentRecord.Iterations {
					parentRecord.Iterations = inst.Iterations
				}
				if inst.ToolCalls > parentRecord.ToolCalls {
					parentRecord.ToolCalls = inst.ToolCalls
				}
				inst.mu.RUnlock()
			}
			s.saveScanRecordTo(parentRecord, scanDir)
			s.mirrorWildcardProgress(req.InstanceID, parentRecord)
		}
		activeSubScanID := ""
		if activeSubScanDir != "" {
			activeSubScanID = filepath.Base(activeSubScanDir)
		}
		s.saveQueueState(idx, req, queueProgress{
			ActiveTarget:          target,
			ActiveScanDir:         scanDir,
			ActiveScanID:          filepath.Base(scanDir),
			WildcardActiveTarget:  activeSubTarget,
			WildcardActiveScanDir: activeSubScanDir,
			WildcardActiveScanID:  activeSubScanID,
			WildcardDiscoveryDone: true,
			WildcardSubdomains:    subdomains,
			WildcardSubIndex:      nextIndex,
		})
	}

	// ── PHASE 2: Scan each subdomain individually ──
	wildcardStopped := false
	for j := resumeFromSubIndex; j < len(subdomains); j++ {
		subdomain := subdomains[j]
		// Per-instance stop only (Stop All / single-stop / pause / delete all
		// flip the instance status, which instanceInterrupted observes).
		if s.instanceInterrupted(req.InstanceID) {
			log.Printf("[INFO] Subdomain loop stopped by user at %d/%d for %s", j+1, len(subdomains), target)
			if !serverInstanceHasExactStopEvent(s, req.InstanceID) {
				s.broadcastToInstance(req.InstanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			}
			wildcardStopped = true
			break
		}

		// Note: No parent context timeout check here. Each subdomain scan has its own
		// agent-level timeout (2h). We let the stop button handle manual cancellation.

		// ── Memory & goroutine health check between subdomain scans ──
		logMemStats(fmt.Sprintf("Before subdomain %d/%d: %s", j+1, len(subdomains), subdomain))

		// Force GC between subdomain scans to free accumulated memory
		runtime.GC()
		debug.FreeOSMemory()

		subScanDir, subResumed := s.scanDirForWildcardSubdomainResume(req, subdomain, j)
		if subResumed {
			log.Printf("[AUTO-RESUME] Reusing interrupted subdomain scan dir for %s: %s", subdomain, subScanDir)
		}
		if !s.beginWildcardSubScan(req.InstanceID, j, subdomain, filepath.Base(subScanDir)) {
			log.Printf("[INFO] Subdomain dispatch stopped before %d/%d for %s", j+1, len(subdomains), target)
			wildcardStopped = true
			break
		}
		log.Printf("[INFO] Starting subdomain %d/%d: %s (parent: %s)", j+1, len(subdomains), subdomain, target)
		saveWildcardProgress(j, j, subdomain, subScanDir, "")

		// childOutcome starts pessimistic: a session that panics or bails is
		// recorded "failed" (identifiable, never "finished") and never
		// terminates its siblings; a normal completion upgrades it.
		childOutcome := "failed"
		// Each subdomain gets its own isolated session wrapped in a panic guard
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Subdomain %d/%d crashed (%s): %v — skipping to next\n%s", j+1, len(subdomains), subdomain, r, debug.Stack())
					s.broadcastToInstance(req.InstanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Subdomain %s crashed: %v — skipping", subdomain, r)})
				}
			}()

			scanInstruction := composeWildcardChildInstruction(subdomain, target, req.Instruction, scanCfg != nil && scanCfg.AllowLocalTargets, subResumed, req.Phases, req.ReconMode, req.ScanIntensity)

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_started",
				Content:        fmt.Sprintf("[PHASE 2] Scanning subdomain %d/%d: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				AgentID:        filepath.Base(subScanDir),
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
				CurrentPhase:   firstSelectedPhase(req.Phases),
			})

			// Track vulns BEFORE this subdomain scan using the stable parent context
			vulnCountBefore := len(reporting.GetVulnerabilitiesForContext(parentReportingCtxID))

			subSess := &scanSession{
				id:                   filepath.Base(subScanDir),
				target:               subdomain,
				parentTarget:         target,
				scanDir:              subScanDir,
				cfg:                  scanCfg,
				server:               s,
				instruction:          scanInstruction,
				codeScanMode:         req.codeScanMode,
				allowLoopbackPorts:   req.allowLoopbackPorts,
				name:                 req.Name,
				userInstruction:      req.Instruction,
				severityFilter:       req.SeverityFilter,
				discordWebhook:       req.DiscordWebhook,
				discoveryMode:        false,
				genReport:            false,
				resetState:           false, // accumulate vulns across subdomains
				instanceID:           req.InstanceID,
				parentCtx:            ctx,
				scanMode:             "wildcard",
				parentReportingCtxID: parentReportingCtxID, // merge vulns into parent on cleanup
				companyName:          req.CompanyName,
				logoPath:             req.LogoPath,
				phases:               req.Phases,
				reconMode:            req.ReconMode,
				scanIntensity:        req.ScanIntensity,
				targetAuth:           req.TargetAuth,
				targetAuthB:          req.TargetAuthSecondary,
				sourceRepo:           req.SourceRepo,
				scanContext:          req.ScanContext,
				llmClient:            s.scanLLMClientForRequest(req, scanCfg),
			}
			s.executeScanSession(subSess)
			if s.instanceInterrupted(req.InstanceID) {
				wildcardStopped = true
				return
			}
			// Propagate the child real outcome and per-host counters into the
			// parent inventory so the record reflects what each host assessment
			// actually produced. A session recorded "failed" by the engine
			// stays "failed"; anything else counts as a completed assessment.
			childOutcome = wildcardChildOutcome(subSess.record)
			if subSess.record != nil && parentRecord != nil && j < len(parentRecord.SubScans) {
				parentRecord.SubScans[j].VulnCount = len(subSess.record.Vulns)
				parentRecord.SubScans[j].TotalTokens = subSess.record.TotalTokens
			}

			// Generate PDF for this subdomain if NEW vulnerabilities found
			// Read from the stable parent context — guaranteed to have all accumulated vulns
			allVulns := reporting.GetVulnerabilitiesForContext(parentReportingCtxID)
			if vulnCountBefore <= len(allVulns) {
				newVulns := allVulns[vulnCountBefore:]
				if len(newVulns) > 0 {
					subScanRecord := ScanRecord{
						ID:                       filepath.Base(subScanDir),
						InstanceID:               req.InstanceID,
						Name:                     req.Name,
						Target:                   subdomain,
						ParentTarget:             target,
						ScanMode:                 "wildcard",
						Instruction:              req.Instruction,
						SeverityFilter:           append([]string(nil), req.SeverityFilter...),
						DiscordWebhook:           req.DiscordWebhook,
						DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
						TelegramConfigured:       s.telegramConfigured(),
						ReconMode:                req.ReconMode,
						ScanIntensity:            req.ScanIntensity,
						StartedAt:                time.Now().Format(time.RFC3339),
						Status:                   "finished",
						FinishedAt:               time.Now().Format(time.RFC3339),
						Vulns:                    []VulnSummary{},
						CompanyName:              req.CompanyName,
						LogoPath:                 req.LogoPath,
						Phases:                   append([]int(nil), req.Phases...),
						CurrentPhase:             22,
					}
					for _, v := range newVulns {
						summary := vulnToSummary(v)
						summary.SourceScanID = subScanRecord.ID
						subScanRecord.Vulns = append(subScanRecord.Vulns, summary)
					}
					reportPath, err := s.generateReportAt(&subScanRecord, subScanDir)
					if err == nil {
						desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found", subdomain, len(newVulns))
						s.sendDiscordWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
						if s.telegramConfigured() {
							s.sendTelegramWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
						}
					}
				}
			}

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_completed",
				Content:        fmt.Sprintf("[PHASE 2] Subdomain %d/%d completed: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})
		}()
		if wildcardStopped {
			break
		}
		saveWildcardProgress(j+1, -1, "", "", childOutcome)

		// ── Cooldown between subdomain scans ──
		// Prevents LLM API rate-limiting and gives GC time to reclaim memory.
		// instanceInterrupted covers per-instance stop/pause/delete.
		if j < len(subdomains)-1 && !s.instanceInterrupted(req.InstanceID) {
			log.Printf("[INFO] Cooldown: 10s pause before next subdomain (memory recovery + rate limit prevention)")
			time.Sleep(10 * time.Second)
		}
	}
	if parentRecord == nil {
		parentRecord, _ = loadScanRecordFromDir(scanDir)
	}
	if parentRecord != nil {
		// wildcardStopped already incorporates instanceInterrupted (set when
		// the per-instance stop is observed in the subdomain loop above).
		if wildcardStopped {
			if status, stopReason := s.instanceRunStatus(req.InstanceID); isInterruptedInstanceStatus(status) {
				parentRecord.Status = status
				parentRecord.StopReason = stopReason
			} else {
				parentRecord.Status = "stopped"
				parentRecord.StopReason = "user_stopped"
			}
		} else {
			saveWildcardProgress(len(subdomains), -1, "", "", "")
			parentRecord.Status = "finished"
		}
		parentRecord.FinishedAt = time.Now().Format(time.RFC3339)
		normalizeTerminalWildcardProgress(parentRecord)
		s.instancesMu.RLock()
		inst := s.instances[req.InstanceID]
		s.instancesMu.RUnlock()
		if inst != nil {
			inst.mu.RLock()
			if inst.TotalTokens > parentRecord.TotalTokens {
				parentRecord.TotalTokens = inst.TotalTokens
			}
			if inst.Iterations > parentRecord.Iterations {
				parentRecord.Iterations = inst.Iterations
			}
			if inst.ToolCalls > parentRecord.ToolCalls {
				parentRecord.ToolCalls = inst.ToolCalls
			}
			inst.mu.RUnlock()
		}
		s.saveScanRecordTo(parentRecord, scanDir)
		s.mirrorWildcardProgress(req.InstanceID, parentRecord)
	}

	log.Printf("[INFO] Wildcard scan complete for %s: scanned %d subdomains", target, len(subdomains))
	logMemStats(fmt.Sprintf("Wildcard scan complete for %s", target))
	debug.FreeOSMemory()
	// Clean up processes before next target — use instance's terminal if available
	s.instancesMu.RLock()
	if inst, ok := s.instances[req.InstanceID]; ok {
		inst.mu.RLock()
		if inst.sctx != nil && inst.sctx.Terminal != nil {
			inst.sctx.Terminal.KillAll()
		} else {
			terminal.KillAllProcesses() // fallback
		}
		inst.mu.RUnlock()
	} else {
		terminal.KillAllProcesses() // fallback
	}
	s.instancesMu.RUnlock()
}

func commandRateForPolicy(policy scanctx.RequestRatePolicy) int {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS}
		}
	}
	if rate := policy.CommandRPS(); rate > 0 {
		return rate
	}
	return 1
}

func commandDelayForPolicy(policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS}
		}
	}
	delay := policy.Delay()
	if delay <= 0 {
		return "1s"
	}
	if delay%time.Second == 0 {
		return strconv.Itoa(int(delay/time.Second)) + "s"
	}
	return strconv.Itoa(int(delay/time.Millisecond)) + "ms"
}

// buildDiscoveryInstruction creates the Phase 1 subdomain enumeration instruction.
func buildDiscoveryInstruction(target, reconMode string, ratePolicy scanctx.RequestRatePolicy) string {
	if normalizeActivityMode(reconMode) == activityModePassive {
		return buildPassiveDiscoveryInstruction(target)
	}
	rate := commandRateForPolicy(ratePolicy)
	delay := commandDelayForPolicy(ratePolicy)

	instruction := `# PHASE 1: SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find ALL subdomains of TARGET — NOTHING ELSE.

## STRICT RULES:
- You are ONLY allowed to enumerate subdomains in this phase.
- DO NOT run any vulnerability scanners (nuclei, sqlmap, ffuf, gobuster, nikto, etc.).
- DO NOT test for XSS, SQLi, SSRF, IDOR, or any other vulnerability.
- DO NOT analyze JavaScript files, test authentication, or probe endpoints.
- After collecting subdomains, you MUST call finish IMMEDIATELY.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory (not subdirectories).

## SUBDOMAIN ENUMERATION COMMANDS - RUN ALL:

## REQUEST RATE LIMIT
All target-touching commands must stay at or below RATE_LIMIT requests/sec. Use RATE_DELAY or slower when a tool needs an explicit delay.

# 1. subfinder (passive)
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt

# 2. Certificate Transparency (curl)
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt

# 3. findomain
findomain -t TARGET --unique-output ./passive_findomain.txt 2>/dev/null || true

# 4. assetfinder
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 5. DNS Bufferover
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt

# 6. Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt

# 7. Active enumeration
subfinder -d TARGET -all -recursive -rl RATE_LIMIT -t RATE_LIMIT -o ./active_subfinder.txt

# 8. MERGE ALL RESULTS
cat ./passive_*.txt ./active_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total unique subdomains found:"
wc -l ./all_subdomains.txt

# 9. RESOLVE TO FIND LIVE HOSTS
cat ./all_subdomains.txt | dnsx -silent -a -resp -rl RATE_LIMIT -threads RATE_LIMIT -o ./live_resolved.txt 2>/dev/null || true
cat ./live_resolved.txt | cut -d' ' -f1 | grep -v '^$' | sort -u > ./live_subdomains.txt
echo "Live subdomains:"
wc -l ./live_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete list of live subdomains from ./live_subdomains.txt
2. Call finish IMMEDIATELY after. The system will handle vulnerability scanning of each subdomain separately.

DO NOT continue past this point. DO NOT scan for vulnerabilities. Call finish NOW.`

	// Replace TARGET placeholder with actual target
	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	instruction = strings.ReplaceAll(instruction, "RATE_LIMIT", strconv.Itoa(rate))
	instruction = strings.ReplaceAll(instruction, "RATE_DELAY", delay)
	return instruction
}

func buildPassiveDiscoveryInstruction(target string) string {
	instruction := `# PHASE 1: PASSIVE SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find subdomains of TARGET without direct target contact.

## STRICT PASSIVE RULES:
- Do NOT send HTTP requests, browser traffic, port scans, DNS brute force, crawlers, fingerprinting probes, or payloads to TARGET or discovered subdomains.
- Do NOT run dnsx, httpx, nmap, naabu, masscan, ffuf, gobuster, dirsearch, feroxbuster, katana, gospider, nuclei, sqlmap, dalfox, nikto, wpscan, whatweb, ping, dig, host, or nslookup against the target.
- Use passive sources only: web_search, certificate transparency, public archives, search engines, third-party intel datasets, existing notes, and already collected files.
- After collecting passive names, call finish IMMEDIATELY. The system will handle the selected scanning policy separately.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory.

## PASSIVE ENUMERATION COMMANDS:

# 1. Passive provider tools when available
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt 2>/dev/null || true
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt 2>/dev/null || true
findomain -t TARGET --unique-output ./passive_findomain.txt 2>/dev/null || true
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 2. Public third-party datasets
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt || true
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]?' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt || true
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]?' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt || true
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt || true

# 3. Merge passive names only. Do not resolve or probe them.
cat ./passive_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total passive subdomains found:"
wc -l ./all_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete passive subdomain list from ./all_subdomains.txt.
2. Call finish IMMEDIATELY after.

DO NOT resolve hosts. DO NOT verify liveness. DO NOT scan for vulnerabilities. Call finish NOW.`

	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	return instruction
}

// collectSubdomains reads discovered subdomains from all known file locations and agent notes.
// contextID is used for context-aware notes lookup; if empty, falls back to global notes.
// collectSubdomains reads discovered subdomains from all known file locations
// and agent notes, AGGREGATING every source instead of letting one preferred
// file mask the others: a dnsx "live" list can be a strict subset of the
// passive lists when resolution flakes, so stopping at the first non-empty
// file silently dropped candidates. root is the registrable discovery domain
// (public-suffix aware, from parseWildcardTarget); contextID is used for
// context-aware notes lookup, falling back to global notes when empty.
func (s *Server) collectSubdomains(scanDir, root, contextID string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// The discovery root arrives pre-normalized (www.example.com ->
	// example.com; www.example.co.uk -> example.co.uk). No www-prefix or
	// first-label trimming happens here.
	rootTarget := strings.ToLower(strings.TrimSpace(root))
	if rootTarget == "" {
		return nil
	}

	// ansiRegex strips ANSI escape codes (color, cursor, etc.) from tool output.
	// Tools like dnsx emit sequences like \x1b[35m that corrupt domain matching.
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

	// Helper: extract valid subdomains from a file (must be subdomains of the root)
	extractFromFile := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Strip all ANSI escape codes before parsing
		clean := ansiRegex.ReplaceAllString(string(data), "")
		var found []string
		for _, line := range strings.Split(clean, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Total") || strings.HasPrefix(line, "wc") {
				continue
			}
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			line = strings.TrimPrefix(line, "http[s]://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				domain = strings.ToLower(domain)
				// Accept: exact root domain OR any subdomain of the root domain
				if strings.Contains(domain, ".") && (domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	// stripMarkdown removes common markdown formatting from a token
	stripMarkdown := func(s string) string {
		s = strings.ReplaceAll(s, "**", "") // bold
		s = strings.ReplaceAll(s, "__", "") // bold alt
		s = strings.ReplaceAll(s, "`", "")  // code
		s = strings.ReplaceAll(s, "*", "")  // italic
		s = strings.TrimRight(s, "/.,;:()[]{}\"'")
		s = strings.TrimLeft(s, "/.,;:()[]{}\"'")
		return s
	}

	// isDomainMatch checks if a cleaned string is a valid subdomain of rootTarget
	isDomainMatch := func(domain string) bool {
		domain = strings.ToLower(domain)
		return strings.Contains(domain, ".") &&
			(domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) &&
			!seen[domain]
	}

	// domainRegex matches potential domain names in free-form text
	domainRegex := regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+` + regexp.QuoteMeta(rootTarget) + `\b`)

	// Helper: extract subdomains from a text blob (e.g., agent notes)
	// Handles: plain lines, markdown lists (- , * , 1. ), bold (**...**), URLs, etc.
	extractFromText := func(text string) []string {
		// Strip ANSI escape codes from text blobs too (terminal captures may contain them)
		text = ansiRegex.ReplaceAllString(text, "")
		var found []string

		// Pass 1: line-by-line parsing (handles structured lists)
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Strip common list prefixes: "- ", "* ", "1. ", "2) ", etc.
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimPrefix(line, "* ")
			// Strip numbered list prefixes: "1. ", "2. ", "10. ", etc.
			if len(line) > 2 {
				dotIdx := strings.Index(line, ". ")
				if dotIdx > 0 && dotIdx <= 4 {
					prefix := line[:dotIdx]
					allDigits := true
					for _, c := range prefix {
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if allDigits {
						line = strings.TrimSpace(line[dotIdx+2:])
					}
				}
			}

			// Try each whitespace-delimited token in the line
			for _, token := range strings.Fields(line) {
				token = strings.TrimPrefix(token, "http://")
				token = strings.TrimPrefix(token, "https://")
				token = strings.TrimPrefix(token, "http[s]://")
				// Strip path component
				if idx := strings.Index(token, "/"); idx > 0 {
					token = token[:idx]
				}
				domain := strings.ToLower(stripMarkdown(token))
				if isDomainMatch(domain) {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}

		// Pass 2: regex fallback — catches domains embedded in any format
		if len(found) == 0 {
			lowerText := strings.ToLower(text)
			if strings.Contains(lowerText, rootTarget) {
				// Try regex extraction for subdomains
				matches := domainRegex.FindAllString(lowerText, -1)
				for _, m := range matches {
					m = strings.TrimRight(m, "/.,;:")
					if isDomainMatch(m) {
						seen[m] = true
						found = append(found, m)
					}
				}
				// Also check bare rootTarget (e.g., "example.com" itself)
				if !seen[rootTarget] {
					seen[rootTarget] = true
					found = append(found, rootTarget)
				}
			}
		}

		return found
	}

	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Layer 1: exact files in the scan directory — ALL of them, aggregated.
	// A preferred "live" file must not mask other valid discovery sources.
	for _, name := range subdomainFileNames {
		path := filepath.Join(scanDir, name)
		if found := extractFromFile(path); len(found) > 0 {
			subdomains = append(subdomains, found...)
		}
	}

	// Layer 1.25: workspace and terminal workdir — agents run commands here,
	// so ./passive_subfinder.txt etc. land in these directories, NOT scanDir.
	// Aggregated in addition to Layer 1 (never masked by it).
	{
		checkDirs := []string{}
		if wd := terminal.GetWorkDir(); wd != "" && wd != scanDir {
			checkDirs = append(checkDirs, wd)
		}
		if s.cfg.Workspace != "" && s.cfg.Workspace != scanDir {
			checkDirs = append(checkDirs, s.cfg.Workspace)
		}
		for _, dir := range checkDirs {
			for _, name := range subdomainFileNames {
				path := filepath.Join(dir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (agent workdir)", len(found), dir, name)
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	// Layer 2: walk the scan directory tree for nested matching files. The
	// callback continues after every match, so every matching file
	// contributes candidates.
	_ = filepath.WalkDir(scanDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		for _, name := range subdomainFileNames {
			if base == name {
				if found := extractFromFile(path); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
		return nil
	})

	// Layers 3+ are last-resort fallbacks, intentionally guarded: /tmp and the
	// home directory can hold leftovers from unrelated scans, and global
	// notes span sessions. They only contribute when nothing else did.
	if len(subdomains) == 0 {
		// Layer 2.5: /tmp — agents sometimes save recon files here
		for _, name := range subdomainFileNames {
			path := filepath.Join("/tmp", name)
			if found := extractFromFile(path); len(found) > 0 {
				log.Printf("[INFO] Found %d subdomains from /tmp/%s", len(found), name)
				subdomains = append(subdomains, found...)
			}
		}
	}

	if len(subdomains) == 0 {
		// Layer 2.75: home directory — some agents write to ~/
		if homeDir, err := os.UserHomeDir(); err == nil && homeDir != scanDir {
			for _, name := range subdomainFileNames {
				path := filepath.Join(homeDir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (home dir)", len(found), homeDir, name)
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	if len(subdomains) == 0 {
		// Layer 3: parse agent notes for subdomain data (context-aware)
		var allNotes map[string]string
		if contextID != "" {
			allNotes = notes.GetAllNotesForContext(contextID)
		} else {
			allNotes = notes.GetAllNotes()
		}
		for key, value := range allNotes {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "subdomain") || strings.Contains(lowerKey, "live") || strings.Contains(lowerKey, "discovered") || strings.Contains(lowerKey, "domain") {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
		if len(subdomains) == 0 {
			for _, value := range allNotes {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	if len(subdomains) == 0 {
		log.Printf("[WARN] No subdomains found after all fallback layers for discovery root: %s", rootTarget)
	}

	// Shuffle so scan order is randomized — avoids predictable patterns
	mathrand.Shuffle(len(subdomains), func(i, j int) {
		subdomains[i], subdomains[j] = subdomains[j], subdomains[i]
	})

	return subdomains
}

// cleanTmpSubdomainFiles removes stale subdomain-related files from /tmp
// that could contaminate subsequent scans with targets from previous runs.
func cleanTmpSubdomainFiles() {
	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Remove known subdomain file names from /tmp
	for _, name := range subdomainFileNames {
		path := filepath.Join("/tmp", name)
		if err := os.Remove(path); err == nil {
			log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
		}
	}

	// Also remove any .txt files in /tmp that contain "subdomain" or "live" in the name
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		log.Printf("[CLEANUP] Failed to read /tmp for cleanup: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".txt") && (strings.Contains(name, "subdomain") || strings.Contains(name, "live_") || strings.Contains(name, "passive_") || strings.Contains(name, "active_")) {
			path := filepath.Join("/tmp", name)
			if err := os.Remove(path); err == nil {
				log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
			}
		}
	}
}

func (s *Server) notifyAdmissionWake() {
	select {
	case s.admissionWake <- struct{}{}:
	default:
	}
}
