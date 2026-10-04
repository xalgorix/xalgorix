package agent

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
)

// maxToolResultBytes caps how much of a single tool result is fed into the LLM
// context. A raw `cat`/`strings`/`curl` of a large asset (a 500 KB minified JS
// bundle, a big HTML page, a huge JSON) would otherwise flood the context in
// one shot — the model then degrades into empty/reasoning-only responses with
// no tool calls and the scan force-stops. We keep the head and tail (the useful
// parts of most outputs) and drop the middle, telling the model to re-extract
// what it needs with grep/head/jq. On-disk files written by the tool are
// untouched, so subdomain collection etc. still see the full data.
const maxToolResultBytes = 16000

func capToolOutputForLLM(output string) string {
	if len(output) <= maxToolResultBytes {
		return output
	}
	const headBytes = 12000
	const tailBytes = 3000
	head := output[:headBytes]
	tail := output[len(output)-tailBytes:]
	return fmt.Sprintf(
		"%s\n\n… [TOOL OUTPUT TRUNCATED — showed %d of %d bytes to fit the context window. Do NOT dump whole files/pages again; re-run with grep/head/jq/rg to extract only the specific lines, endpoints, or fields you need.] …\n\n%s",
		head, headBytes+tailBytes, len(output), tail,
	)
}

// formatToolResult formats tool execution results with helpful suggestions
func formatToolResult(toolName string, result tools.Result) string {
	output := capToolOutputForLLM(result.Output)
	errorMsg := result.Error

	var msg string
	if errorMsg != "" {
		msg = fmt.Sprintf("Tool '%s' error: %s\n", toolName, errorMsg)
		msg += getToolSuggestion(toolName, errorMsg)
	} else if output != "" {
		msg = fmt.Sprintf("Tool '%s' result:\n%s", toolName, output)
	} else {
		msg = fmt.Sprintf("Tool '%s' completed successfully (no output)", toolName)
	}

	return msg
}

var planBriefTaskIDRe = regexp.MustCompile(`(?m)^  ▶ \[Phase [0-9]+\] ([^ \n]+) —`)

// removeSupersededPlanBrief removes an older generated snapshot only when
// every task it highlighted has either settled or remains visible in the new
// brief. That retains methodology hints for active work which the planner's
// next-pending-task view may otherwise omit. Other guidance stays untouched.
func (a *Agent) removeSupersededPlanBrief(previous, current string) {
	if a == nil || a.state == nil || a.state.Plan == nil || previous == "" ||
		!strings.HasPrefix(previous, "## Active Plan —") || current == "" {
		return
	}
	currentTasks := make(map[string]bool)
	for _, match := range planBriefTaskIDRe.FindAllStringSubmatch(current, -1) {
		currentTasks[match[1]] = true
	}
	for _, match := range planBriefTaskIDRe.FindAllStringSubmatch(previous, -1) {
		id := match[1]
		task := a.state.Plan.Get(id)
		if task != nil && (task.Status == TaskPending || task.Status == TaskActive) && !currentTasks[id] {
			return
		}
	}
	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	for i := len(a.messages) - 1; i >= 0; i-- {
		if a.messages[i].Role != "user" || !strings.Contains(a.messages[i].Content, previous) {
			continue
		}
		remaining := strings.TrimSpace(strings.Replace(a.messages[i].Content, previous, "", 1))
		if remaining == "" {
			a.messages = append(a.messages[:i], a.messages[i+1:]...)
		} else {
			a.messages[i].Content = remaining
		}
		return
	}
}

// getToolSuggestion provides helpful suggestions when a tool fails
func getToolSuggestion(toolName, errorMsg string) string {
	lower := strings.ToLower(errorMsg)

	switch {
	case strings.Contains(toolName, "terminal") || strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such file") {
			return "Suggestion: The command or tool was not found. Try using a different approach or check if the tool is installed.\n"
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access denied") {
			return "Suggestion: Permission denied. Try running with elevated privileges or use a different method.\n"
		}
		if strings.Contains(lower, "cancel") {
			return "Suggestion: Command was canceled. The agent may have been stopped or the command was taking too long.\n"
		}
		if strings.Contains(lower, "connection") || strings.Contains(lower, "network") {
			return "Suggestion: Network error. Check the target URL and try again.\n"
		}

	case strings.Contains(toolName, "python"):
		if strings.Contains(lower, "no module") || strings.Contains(lower, "import error") {
			return "Suggestion: Missing Python module. Try installing the required package or use an alternative approach.\n"
		}
		if strings.Contains(lower, "syntax") {
			return "Suggestion: Python syntax error. Check the script for errors.\n"
		}

	case strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "chrome") || strings.Contains(lower, "chromium") {
			return "Suggestion: Browser automation issue. Try using send_request instead for HTTP interactions.\n"
		}

	case strings.Contains(toolName, "proxy"):
		if strings.Contains(lower, "connection refused") {
			return "Suggestion: Proxy connection failed. Make sure Caido is running or use direct HTTP requests.\n"
		}
	}

	return ""
}

// pruneMessages trims the message history to prevent context window overflow.
// Strategy: keep system prompt (msg[0]), keep last N messages, and re-inject
// all saved notes so the agent retains accumulated knowledge.
// alignPruneCutoff returns an index >= start such that messages[idx:]
// begins with an "assistant" message (or, if no assistant message remains
// after start, the last message). pruneMessages inserts a synthetic "user"
// message right before the kept tail; advancing the cutoff to an assistant
// boundary preserves user/assistant alternation, which Anthropic enforces
// strictly. Pure function so it's straightforward to regression-test.
func alignPruneCutoff(messages []llm.Message, start int) int {
	if start < 1 {
		start = 1
	}
	cutoff := start
	for cutoff < len(messages) && messages[cutoff].Role != "assistant" {
		cutoff++
	}
	if cutoff >= len(messages) {
		// No assistant message remains after `start`. Keep at least the
		// last message rather than pruning everything below the system
		// prompt.
		cutoff = len(messages) - 1
		if cutoff < 1 {
			cutoff = 1
		}
	}
	return cutoff
}

// pruneThresholdBytes is the serialized message-buffer ceiling used by
// shouldPruneBeforeLLM. ~500 KiB ≈ ~125K tokens at ~4 bytes per token. Kept
// well below the 200K-token mark on purpose: models lose focus and STOP
// CALLING TOOLS long before they hit their hard context limit (the recurring
// llm_no_tool_calls stall at phase 22), and many providers ship 128K windows.
// Compaction preserves a structured digest + saved notes, so lowering this only
// discards raw tool-output bytes the agent no longer needs.
const pruneThresholdBytes = 500 * 1024

// maxMessagesBeforePrune is a second safety boundary independent of byte
// size. A long run of short tool calls can still make the model resend a very
// large number of message envelopes on every iteration, especially after a
// provider rate-limit retry. Keep the old proven message-count guard alongside
// the window-relative byte ceiling.
const maxMessagesBeforePrune = 100

// maxRecentMsgBytes caps EACH kept-recent message during pruning. Compaction
// summarizes OLD messages, but the recent window was kept verbatim — a run of
// large tool outputs (even after the per-call cap) could still balloon the
// context right back up. Truncating each recent message here bounds the whole
// buffer so raw output never accumulates across phases.
const maxRecentMsgBytes = 8000

// perMessageOverheadBytes accounts for role tags, JSON delimiters, and
// per-message structural overhead added by the provider serializer that
// is not visible in Message.Content alone.
const perMessageOverheadBytes = 50

// bytesPerTokenEstimate converts the operator's token budget
// (XALGORIX_CONTEXT_COMPACT_TOKENS) into the byte ceiling used by the cheap
// no-tokenizer heuristic. ~4 bytes/token is a conservative average for the
// English + JSON + code text that dominates scan transcripts.
const bytesPerTokenEstimate = 4

// defaultCompactRatio is the fraction of the model's context window at which
// window-relative auto-compaction fires when the operator hasn't set an
// explicit token budget. Kept in the 0.7–0.8 band on purpose: compacting much
// earlier throws away useful working context and degrades outcome quality,
// while going higher risks hitting the provider's hard limit before we prune.
const defaultCompactRatio = 0.75

// compactThresholdBytes resolves the effective byte ceiling for auto-compaction
// (token budget × ~4 bytes/token). Resolution order:
//
//   - cfg absent (tests/CLI):     built-in pruneThresholdBytes default.
//   - ContextCompactTokens == 0:  disabled (0) — only the last-resort
//     forcePruneMessages on a hard context overflow still applies.
//   - ContextCompactTokens  > 0:  explicit absolute token-budget override.
//   - ContextCompactTokens  < 0:  AUTO (default) — a fraction
//     (ContextCompactRatio, ~0.75) of the model's configured context window
//     (LLMContextWindow). This is the intended behavior: we only compact once
//     the window is genuinely filling up, not at an arbitrary fixed budget, so
//     large-context models keep their full working context for longer.
func (a *Agent) compactThresholdBytes() int {
	if a.cfg == nil {
		return pruneThresholdBytes
	}
	if a.cfg.ContextCompactTokens == 0 {
		return 0 // disabled
	}
	if a.cfg.ContextCompactTokens > 0 {
		return a.cfg.ContextCompactTokens * bytesPerTokenEstimate
	}
	// Auto / window-relative mode.
	window := a.cfg.LLMContextWindow
	if window <= 0 {
		return pruneThresholdBytes
	}
	ratio := a.cfg.ContextCompactRatio
	if ratio < 0.5 || ratio > 0.9 {
		ratio = defaultCompactRatio
	}
	return int(float64(window)*ratio) * bytesPerTokenEstimate
}

// shouldPruneBeforeLLM reports whether the agent's current message buffer
// would serialize larger than the configured compaction ceiling and therefore
// should be pruned before the next outbound LLM call. Cheap byte-count
// heuristic: no tokenizer dependency and no allocations beyond the message
// slice.
//
// Implements Requirement 2.3 (bounded message history before LLM calls)
// and underwrites Property P2.3.
func (a *Agent) shouldPruneBeforeLLM() bool {
	threshold := a.compactThresholdBytes()
	if threshold <= 0 {
		return false // auto-compaction disabled
	}
	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	if len(a.messages) > maxMessagesBeforePrune {
		return true
	}

	size := 0
	for i := range a.messages {
		size += len(a.messages[i].Content) + perMessageOverheadBytes
		if size > threshold {
			return true
		}
	}
	return false
}

func (a *Agent) pruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	// Compact when either the serialized buffer has grown past the configured
	// ceiling or the message-count safety boundary is reached. The size scan
	// mirrors shouldPruneBeforeLLM but is inlined here because msgMu is already
	// held (shouldPruneBeforeLLM would re-lock and deadlock).
	threshold := a.compactThresholdBytes()
	if threshold <= 0 {
		return // auto-compaction disabled
	}
	size := 0
	for i := range a.messages {
		size += len(a.messages[i].Content) + perMessageOverheadBytes
	}
	if size <= threshold && len(a.messages) <= maxMessagesBeforePrune {
		return
	}

	// Keep system prompt (index 0) + the most recent keepRecent messages
	keepRecent := 40
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}
	// Nothing older than the recent window to compact — bail rather than
	// rebuild an identical buffer.
	if len(a.messages)-keepRecent <= 1 {
		return
	}

	originalLen := len(a.messages)

	// Build pruned list: system prompt + compacted history + recent messages
	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// Compact the pruned messages into a structured digest
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, len(a.messages)-cutoff+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation message with compacted history + notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT PRUNED: %d older messages were compacted to save context space.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{
		Role:    "user",
		Content: sb.String(),
	})

	// Keep recent messages, but truncate any oversized raw tool output so the
	// recent window itself can't re-flood the context (the digest above already
	// preserves the structured takeaways of anything trimmed here).
	for _, msg := range a.messages[cutoff:] {
		if len(msg.Content) > maxRecentMsgBytes {
			msg.Content = msg.Content[:maxRecentMsgBytes] + "\n\n[OUTPUT TRUNCATED TO FIT CONTEXT WINDOW — re-run with grep/head/jq to re-extract specific data if needed]"
		}
		pruned = append(pruned, msg)
	}
	a.messages = pruned
	a.compactionCount++
	if a.state != nil {
		a.state.LastPlanBrief = ""
	}
	if a.hooks != nil {
		a.hooks.Fire(OnContextPrune, a.state, nil)
	}

	log.Printf("[agent] Pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// forcePruneMessages aggressively trims the conversation to recover from
// context window overflow. Instead of silently dropping old messages, it
// compacts them into a structured digest that preserves the agent's working
// memory (tools run, findings, endpoints tested).
func (a *Agent) forcePruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	if len(a.messages) <= 3 {
		// Nothing meaningful to prune — truncate the system prompt if huge
		if len(a.messages) > 0 && len(a.messages[0].Content) > 8000 {
			a.messages[0].Content = a.messages[0].Content[:8000] + "\n\n[SYSTEM PROMPT TRUNCATED TO FIT CONTEXT WINDOW]"
			log.Printf("[agent] Force-pruned: truncated oversized system prompt")
		}
		return
	}

	originalLen := len(a.messages)

	// Aggressive: keep system prompt + last 20 messages (or fewer if small)
	keepRecent := 20
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}

	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// ── Compact the pruned messages into a structured digest ──
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, keepRecent+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation with compacted history + saved notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT COMPACTED: %d older messages were summarized to fit context window.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{Role: "user", Content: sb.String()})

	// Keep recent messages, but truncate any that are excessively long.
	for _, msg := range a.messages[cutoff:] {
		if len(msg.Content) > maxRecentMsgBytes {
			msg.Content = msg.Content[:maxRecentMsgBytes] + "\n\n[OUTPUT TRUNCATED TO FIT CONTEXT WINDOW]"
		}
		pruned = append(pruned, msg)
	}

	a.messages = pruned
	a.compactionCount++
	if a.state != nil {
		a.state.LastPlanBrief = ""
	}
	if a.hooks != nil {
		a.hooks.Fire(OnContextPrune, a.state, nil)
	}

	log.Printf("[agent] Force-pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// compactMessages extracts a structured digest from a slice of messages.
// Parses tool calls/results, findings, and endpoints to preserve the agent's
// working memory without consuming excessive tokens.
func compactMessages(msgs []llm.Message) string {
	var sb strings.Builder
	toolsRun := make(map[string]int)   // tool_name -> count
	endpoints := make(map[string]bool) // unique endpoints/URLs seen
	var findings []string              // key findings extracted
	var errors []string                // errors encountered

	for _, msg := range msgs {
		content := msg.Content

		// Extract tool calls and counts
		if msg.Role == "assistant" {
			// Count tool call patterns: <function=tool_name>
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "<function=") {
					name := strings.TrimPrefix(strings.TrimSpace(line), "<function=")
					name = strings.TrimSuffix(name, ">")
					if name != "" {
						toolsRun[name]++
					}
				}
			}
		}

		// Extract tool results with findings
		if msg.Role == "user" {
			// Look for vulnerability/finding indicators in tool results
			lower := strings.ToLower(content)
			if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "injection") ||
				strings.Contains(lower, "xss") || strings.Contains(lower, "sqli") ||
				strings.Contains(lower, "rce") || strings.Contains(lower, "ssrf") ||
				strings.Contains(lower, "idor") || strings.Contains(lower, "bypass") ||
				strings.Contains(lower, "leak") || strings.Contains(lower, "exposed") {
				// Extract first meaningful line as finding summary
				for _, line := range strings.Split(content, "\n") {
					line = strings.TrimSpace(line)
					if len(line) > 20 && len(line) < 200 {
						findings = append(findings, line)
						break
					}
				}
			}

			// Extract error patterns
			if strings.Contains(content, "error:") || strings.Contains(content, "Error:") {
				for _, line := range strings.Split(content, "\n") {
					if strings.Contains(line, "error") || strings.Contains(line, "Error") {
						line = strings.TrimSpace(line)
						if len(line) > 10 && len(line) < 150 {
							errors = append(errors, line)
							break
						}
					}
				}
			}
		}

		// Extract URLs/endpoints from any message
		for _, word := range strings.Fields(content) {
			if (strings.HasPrefix(word, "http://") || strings.HasPrefix(word, "https://")) && len(word) < 200 {
				// Clean trailing punctuation
				word = strings.TrimRight(word, ".,;:)\"'`")
				endpoints[word] = true
			}
		}
	}

	// Format the digest
	if len(toolsRun) > 0 {
		sb.WriteString("### Tools Executed\n")
		for tool, count := range toolsRun {
			sb.WriteString(fmt.Sprintf("- %s (×%d)\n", tool, count))
		}
	}

	if len(endpoints) > 0 {
		// "Tested" overstated what this digest establishes: it is a lossy inventory
		// of URL mentions in the conversation, not an execution ledger — a mention
		// does not prove a request was made, succeeded, or was conclusively
		// assessed. Consumers must read it as mentions only.
		sb.WriteString("\n### URLs Mentioned (lossy summary — a mention is not evidence of testing)\n")
		count := 0
		for ep := range endpoints {
			if count >= 30 { // cap to avoid bloat
				sb.WriteString(fmt.Sprintf("- ... and %d more\n", len(endpoints)-30))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s\n", ep))
			count++
		}
	}

	if len(findings) > 0 {
		sb.WriteString("\n### Key Findings\n")
		seen := make(map[string]bool)
		for _, f := range findings {
			if !seen[f] && len(seen) < 15 {
				sb.WriteString(fmt.Sprintf("- %s\n", f))
				seen[f] = true
			}
		}
	}

	if len(errors) > 0 {
		sb.WriteString("\n### Errors Encountered\n")
		seen := make(map[string]bool)
		for _, e := range errors {
			if !seen[e] && len(seen) < 5 {
				sb.WriteString(fmt.Sprintf("- %s\n", e))
				seen[e] = true
			}
		}
	}

	if sb.Len() == 0 {
		sb.WriteString("(No structured data could be extracted from pruned messages)\n")
	}

	return sb.String()
}

// hasActiveContent reports whether snippet (or its truncated version as produced by
// capToolOutputForLLM) is still present in the agent's active LLM message history.
func (a *Agent) hasActiveContent(snippet string) bool {
	if a == nil || snippet == "" {
		return false
	}
	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	capped := capToolOutputForLLM(snippet)
	for _, m := range a.messages {
		if strings.Contains(m.Content, capped) || strings.Contains(m.Content, snippet) {
			return true
		}
	}
	return false
}

// ── Bounded working context (information-complete) ──────────────────────────
//
// Measured on production (scanner2 fleet diagnostics): accumulated tool-result
// history resent on every iteration dominates token consumption (37–49x resend
// amplification; 99.3% of all tokens are prompt tokens). The mechanism below
// keeps every byte reachable — it only changes eager resend into lazy fetch:
//
//   1. At tool-result append time the COMPLETE raw output (pre-truncation) is
//      archived to <ScanDir>/tool-outputs/<id> and the message carries a
//      small marker naming the archive id.
//   2. Tool-result messages older than the active window are replaced by a
//      compact stub. The stub keeps the message's first line and a short head
//      snippet, and names the archive id.
//   3. The read_tool_output tool returns the byte-identical archived original
//      on demand (and the file is also directly readable from the scan
//      workdir via terminal tools).
//
// The recent window stays verbatim, the archive is byte-identical, and the
// existing compaction digest keeps working unchanged. Gated by
// XALGORIX_BOUNDED_CONTEXT (default off).

const (
	// archiveMarkerPrefix marks a tool-result message whose full raw output
	// was archived at append time.
	archiveMarkerPrefix = "[full raw output saved as "
	// archiveStubPrefix marks a message already replaced by a retrieval stub.
	archiveStubPrefix = "[ARCHIVED as "
	// archiveHeadBytes is the byte length of the head snippet kept in a stub.
	archiveHeadBytes = 300
)

var archiveIDRe = regexp.MustCompile(`to_[0-9]{6,12}`)

// boundedContextEnabled reports whether information-complete bounded context
// is active for this agent (flag on, scan archive wired).
func (a *Agent) boundedContextEnabled() bool {
	return a != nil && a.cfg != nil && a.cfg.BoundedContext &&
		a.scanCtx != nil && a.scanCtx.ToolOutputs != nil
}

// toolArchiveMinBytes resolves the archive-size threshold with a sane floor.
func (a *Agent) toolArchiveMinBytes() int {
	if a == nil || a.cfg == nil || a.cfg.ToolArchiveMinBytes <= 0 {
		return 1500
	}
	return a.cfg.ToolArchiveMinBytes
}

// toolArchiveActiveWindow resolves how many recent tool-result messages stay
// verbatim before older ones are stubbed.
func (a *Agent) toolArchiveActiveWindow() int {
	if a == nil || a.cfg == nil || a.cfg.ToolArchiveActiveWindow <= 0 {
		return 8
	}
	return a.cfg.ToolArchiveActiveWindow
}

// isToolResultMessage identifies tool-result conversation messages produced by
// formatToolResult (root and delegated agents). Verifier messages
// ("[tool output]") and other user turns are not tool-result messages.
func isToolResultMessage(content string) bool {
	return strings.HasPrefix(content, "Tool '")
}

// archiveIDFromMessage extracts the archive id from a tool-result message
// that was annotated at append time.
func archiveIDFromMessage(content string) (string, bool) {
	if !strings.Contains(content, archiveMarkerPrefix) {
		return "", false
	}
	id := archiveIDRe.FindString(content)
	if id == "" {
		return "", false
	}
	return id, true
}

// archiveToolResultMarker annotates a fresh tool-result message with the id of
// its archived raw output so the aging pass can stub it later.
func archiveToolResultMarker(id string) string {
	return fmt.Sprintf("%s%s — call read_tool_output(id=\"%s\") for the untruncated original]", archiveMarkerPrefix, id, id)
}

// trimToValidUTF8 cuts s to at most maxBytes on a rune boundary.
func trimToValidUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := s[:maxBytes]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// ageOutToolOutputs replaces tool-result messages older than the active window
// with compact retrieval stubs. Idempotent; never touches messages that were
// not archived (e.g. produced before the flag was enabled); keeps the active
// window verbatim. Caller: agent main loop, before the LLM call.
func (a *Agent) ageOutToolOutputs() {
	if !a.boundedContextEnabled() {
		return
	}
	window := a.toolArchiveActiveWindow()

	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	// Collect tool-result message indices, newest first.
	toolIdx := make([]int, 0, window+8)
	for i := len(a.messages) - 1; i >= 0; i-- {
		if isToolResultMessage(a.messages[i].Content) {
			toolIdx = append(toolIdx, i)
		}
	}

	stubbed := 0
	for k, idx := range toolIdx {
		if k < window {
			continue // inside the active window → keep verbatim
		}
		content := a.messages[idx].Content
		if strings.Contains(content, archiveStubPrefix) {
			continue // already stubbed
		}
		id, ok := archiveIDFromMessage(content)
		if !ok {
			continue // never archived → leave verbatim (no information may be dropped)
		}
		firstLine := content
		if i := strings.IndexByte(content, '\n'); i >= 0 {
			firstLine = content[:i]
		}
		head := trimToValidUTF8(content, archiveHeadBytes)
		a.messages[idx].Content = fmt.Sprintf(
			"%s %s%s — full original retrievable]\nHead: %s\n…[archived head only — use read_tool_output(id=\"%s\") to view the complete output]\n",
			firstLine, archiveStubPrefix, id, head, id,
		)
		stubbed++
	}
	if stubbed > 0 {
		log.Printf("[agent] %s: bounded context stubbed %d aged tool-result message(s) (window=%d, archive=%d entries)",
			a.Name, stubbed, window, a.scanCtx.ToolOutputs.Count())
	}
}
