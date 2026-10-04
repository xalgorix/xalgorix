package scanctx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RequestCategory identifies the purpose or phase of an LLM request.
const (
	CategoryNormalReasoning         = "normal"
	CategoryVerifier                = "verifier"
	CategoryRetry                   = "retry"
	CategoryMalformedToolRecovery   = "malformed-tool"
	CategoryNoToolRecovery          = "no-tool"
	CategoryFinishRejectionRecovery = "finish-rejection"
)

// AgentType defines the canonical role of an agent in a scan.
const (
	AgentTypeRoot            = "coordinator/root"
	AgentTypeAuthzLogic      = "authz-logic"
	AgentTypeInjectionServer = "injection-serverside"
	AgentTypeClientSource    = "client-source"
	AgentTypeVerifier        = "verifier"
	AgentTypeOther           = "other"
)

// Persistence file names inside the scan directory.
const (
	tokenRecordsFile = "token-usage.jsonl"
	tokenSummaryFile = "token-usage.json"
	// persistSummaryEveryRecords controls how often the aggregate summary is
	// rewritten while the scan is still running, so a server restart never
	// loses more than a bounded amount of aggregate context.
	persistSummaryEveryRecords = 20
)

// TokenAttribution records detailed metrics for a single outbound LLM request.
// Metadata only — never prompt or message content.
type TokenAttribution struct {
	ScanID string `json:"scan_id"`
	// Sequence is the per-scan monotonic request index assigned by the tracker.
	Sequence int    `json:"sequence"`
	AgentID  string `json:"agent_id"`
	// AgentType is the canonical role: coordinator/root, authz-logic,
	// injection-serverside, client-source, verifier, other.
	AgentType string    `json:"agent_type"`
	Iteration int       `json:"iteration"`
	Model     string    `json:"model"`
	Provider  string    `json:"provider"`
	Timestamp time.Time `json:"timestamp"`
	// RequestCategory: normal, verifier, retry, malformed-tool, no-tool, finish-rejection.
	RequestCategory string `json:"request_category"`
	RetryAttempt    int    `json:"retry_attempt"`

	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	// CachedInputTokens is provider-reported cache-read tokens for THIS request.
	// CacheReported distinguishes "provider reported 0" from "provider did not
	// report any cached-token field" so aggregates never fabricate cache numbers.
	CachedInputTokens   int  `json:"cached_input_tokens"`
	CacheReported       bool `json:"cache_reported"`
	UncachedInputTokens int  `json:"uncached_input_tokens"`

	MessageCount           int `json:"message_count"`
	SerializedMessageBytes int `json:"serialized_message_bytes"`
	SystemMessageBytes     int `json:"system_message_bytes"`
	UserMessageBytes       int `json:"user_message_bytes"`
	AssistantMessageBytes  int `json:"assistant_message_bytes"`
	ToolResultCount        int `json:"tool_result_count"`
	ToolResultBytes        int `json:"tool_result_bytes"`
	// SkillResultCount/Bytes are a subset of ToolResultCount/Bytes (skill
	// results arrive as tool results).
	SkillResultCount        int `json:"skill_result_count"`
	SkillResultBytes        int `json:"skill_result_bytes"`
	ConversationBufferBytes int `json:"conversation_buffer_bytes"`
	// CompactionCount is the agent's context-compaction count at request time.
	CompactionCount int `json:"compaction_count"`
	// AgentCumulativePrompt/Output are the calling agent's own cumulative
	// counters (per cloned client), not scan-wide totals.
	AgentCumulativePrompt int `json:"agent_cumulative_prompt"`
	AgentCumulativeOutput int `json:"agent_cumulative_output"`
}

// TokenSummary provides aggregated post-scan metrics (legacy shape, kept for
// existing callers and tests).
type TokenSummary struct {
	TotalTokens         int            `json:"total_tokens"`
	PromptTokens        int            `json:"prompt_tokens"`
	CompletionTokens    int            `json:"completion_tokens"`
	CachedInputTokens   int            `json:"cached_input_tokens"`
	UncachedInputTokens int            `json:"uncached_input_tokens"`
	RootTokens          int            `json:"root_tokens"`
	VerifierTokens      int            `json:"verifier_tokens"`
	SpecialistTokens    map[string]int `json:"specialist_tokens"` // role -> total tokens
	AgentTypeTokens     map[string]int `json:"agent_type_tokens"`
	CategoryTokens      map[string]int `json:"category_tokens"` // request_category -> total tokens
	ToolOutputBytes     int            `json:"tool_output_bytes"`
	SkillResultBytes    int            `json:"skill_result_bytes"`
	ToolResultMessages  int            `json:"tool_result_messages"`
	SkillResultMessages int            `json:"skill_result_messages"`
	RetryLoopTokens     int            `json:"retry_loop_tokens"`
	TotalRequests       int            `json:"total_requests"`
}

// PromptGrowthStats proves or disproves runaway context growth: if the agent
// resends its growing conversation on every iteration, LastPromptTokens grows
// roughly linearly with the iteration count and PromptGrowthRatio is large.
type PromptGrowthStats struct {
	FirstPromptTokens      int     `json:"first_prompt_tokens"`
	LastPromptTokens       int     `json:"last_prompt_tokens"`
	MedianPromptTokens     float64 `json:"median_prompt_tokens"`
	P95PromptTokens        int     `json:"p95_prompt_tokens"`
	MaxPromptTokens        int     `json:"max_prompt_tokens"`
	PromptGrowthRatio      float64 `json:"prompt_growth_ratio"` // last / first; 0 when first == 0
	CumulativePromptTokens int     `json:"cumulative_prompt_tokens"`
}

// ContextGrowthHeuristics compares how many context bytes were newly produced
// against how many were actually sent. This is an observability heuristic —
// NOT an exact token-duplication measure. A ratio far above 1.0 shows how
// repeatedly resending the accumulated history amplifies input volume.
type ContextGrowthHeuristics struct {
	// CumulativeContextBytesSent sums the serialized message bytes of every
	// outbound LLM request.
	CumulativeContextBytesSent int `json:"cumulative_context_bytes_sent"`
	// UniqueContextBytesAdded sums only positive per-agent buffer growth
	// between consecutive requests (first request counts fully). Compaction
	// resets make later re-growth count again, so this slightly overcounts —
	// which makes the ratio conservative, not inflated.
	UniqueContextBytesAdded int `json:"unique_context_bytes_added"`
	// ResendAmplificationRatio = cumulative / unique; 0 when unique == 0.
	ResendAmplificationRatio float64 `json:"resend_amplification_ratio"`
}

// AgentTokenBreakdown breaks token usage down by agent role.
type AgentTokenBreakdown struct {
	AgentType           string   `json:"agent_type"`
	AgentIDs            []string `json:"agent_ids"`
	Requests            int      `json:"requests"`
	PromptTokens        int      `json:"prompt_tokens"`
	CompletionTokens    int      `json:"completion_tokens"`
	TotalTokens         int      `json:"total_tokens"`
	CachedInputTokens   int      `json:"cached_input_tokens"`
	UncachedInputTokens int      `json:"uncached_input_tokens"`
	AveragePromptTokens float64  `json:"average_prompt_tokens"`
	MaxPromptTokens     int      `json:"max_prompt_tokens"`
	ToolResultBytes     int      `json:"tool_result_bytes"`
	SkillResultBytes    int      `json:"skill_result_bytes"`
	Iterations          int      `json:"iterations"`  // highest iteration observed
	Compactions         int      `json:"compactions"` // highest compaction count observed
	FirstPromptTokens   int      `json:"first_prompt_tokens"`
	LastPromptTokens    int      `json:"last_prompt_tokens"`
}

// AgentContextComposition is the approximate active-context composition of one
// agent's most recent outbound request (observation only; no message changes).
type AgentContextComposition struct {
	AgentType      string `json:"agent_type"`
	AgentID        string `json:"agent_id"`
	Iteration      int    `json:"iteration"`
	MessageCount   int    `json:"message_count"`
	SystemBytes    int    `json:"system_bytes"`
	AssistantBytes int    `json:"assistant_bytes"`
	// UserOtherBytes is user-message bytes NOT attributable to tool results.
	UserOtherBytes  int `json:"user_other_bytes"`
	ToolResultBytes int `json:"tool_result_bytes"`
	// SkillResultBytes is a subset of ToolResultBytes.
	SkillResultBytes int `json:"skill_result_bytes"`
	TotalBytes       int `json:"total_bytes"`
}

// ContextSourceBreakdown approximates what the active context is made of.
type ContextSourceBreakdown struct {
	// Aggregate sums across every outbound request (approximate total context
	// volume sent, dominated by resent history).
	Aggregate struct {
		SystemBytes      int `json:"system_bytes"`
		AssistantBytes   int `json:"assistant_bytes"`
		UserOtherBytes   int `json:"user_other_bytes"`
		ToolResultBytes  int `json:"tool_result_bytes"`
		SkillResultBytes int `json:"skill_result_bytes"`
	} `json:"aggregate"`
	// Latest is the active-context composition of each agent's last request.
	Latest []AgentContextComposition `json:"latest"`
}

// RecoveryTokenStats isolates the token cost of failure/recovery loops.
type RecoveryTokenStats struct {
	RetryRequests           int `json:"retry_requests"`
	RetryTokens             int `json:"retry_tokens"`
	NoToolRequests          int `json:"no_tool_requests"`
	NoToolTokens            int `json:"no_tool_tokens"`
	MalformedToolRequests   int `json:"malformed_tool_requests"`
	MalformedToolTokens     int `json:"malformed_tool_tokens"`
	FinishRejectionRequests int `json:"finish_rejection_requests"`
	FinishRejectionTokens   int `json:"finish_rejection_tokens"`
}

// TokenRequestPoint is a slim per-request point for charting and export.
type TokenRequestPoint struct {
	Sequence    int       `json:"seq"`
	Timestamp   time.Time `json:"ts"`
	AgentType   string    `json:"agent_type"`
	AgentID     string    `json:"agent_id"`
	Iteration   int       `json:"iter"`
	Category    string    `json:"category"`
	Retry       int       `json:"retry"`
	Prompt      int       `json:"prompt"`
	Completion  int       `json:"completion"`
	Cached      int       `json:"cached"`
	ConvBytes   int       `json:"conv_bytes"`
	ToolBytes   int       `json:"tool_bytes"`
	SkillBytes  int       `json:"skill_bytes"`
	Compactions int       `json:"compactions"`
}

// TokenDiagnostics is the full production diagnostics document.
// Cache metrics are nil when the provider did not report them.
type TokenDiagnostics struct {
	GeneratedAt time.Time `json:"generated_at"`
	ScanID      string    `json:"scan_id"`

	TotalTokens      int `json:"total_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`

	CachedInputTokens   *int     `json:"cached_input_tokens"`
	UncachedInputTokens *int     `json:"uncached_input_tokens"`
	CacheHitRate        *float64 `json:"cache_hit_rate"`
	// CacheReportedRequests counts requests for which the provider reported a
	// cached-token field at all, so partial coverage is visible.
	CacheReportedRequests int `json:"cache_reported_requests"`

	TotalLLMRequests int `json:"total_llm_requests"`

	RootTokens       int            `json:"root_tokens"`
	VerifierTokens   int            `json:"verifier_tokens"`
	SpecialistTokens map[string]int `json:"specialist_tokens"`
	AgentTypeTokens  map[string]int `json:"agent_type_tokens"`
	CategoryTokens   map[string]int `json:"category_tokens"`

	ToolResultBytes     int `json:"tool_result_bytes"`
	SkillResultBytes    int `json:"skill_result_bytes"`
	ToolResultMessages  int `json:"tool_result_messages"`
	SkillResultMessages int `json:"skill_result_messages"`

	AveragePromptTokensPerRequest     *float64 `json:"average_prompt_tokens_per_request"`
	AverageCompletionTokensPerRequest *float64 `json:"average_completion_tokens_per_request"`
	LargestPromptTokens               int      `json:"largest_prompt_tokens"`
	LargestConversationBytes          int      `json:"largest_conversation_bytes"`

	Growth   PromptGrowthStats       `json:"growth"`
	Context  ContextGrowthHeuristics `json:"context"`
	Agents   []AgentTokenBreakdown   `json:"agents"`
	Sources  ContextSourceBreakdown  `json:"sources"`
	Recovery RecoveryTokenStats      `json:"recovery"`
}

// TokenTracker collects and aggregates TokenAttribution records across a scan
// session, persists compact per-request records, and computes the production
// diagnostics document.
type TokenTracker struct {
	mu          sync.RWMutex
	records     []TokenAttribution
	seq         int
	persistDir  string
	persistFile *os.File
	sinceFlush  int
	closed      bool
}

// NewTokenTracker initializes a new TokenTracker.
func NewTokenTracker() *TokenTracker {
	return &TokenTracker{
		records: make([]TokenAttribution, 0, 64),
	}
}

// SetPersistDir wires compact per-request persistence to <dir>/token-usage.jsonl.
// Safe to call multiple times; later calls with the same dir are no-ops.
func (t *TokenTracker) SetPersistDir(dir string) {
	if t == nil || dir == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.persistDir == dir {
		return
	}
	t.persistDir = dir
	if t.persistFile != nil {
		_ = t.persistFile.Close()
		t.persistFile = nil
	}
}

// Record appends a new token attribution event under lock, persists the
// compact record, and periodically flushes the aggregate summary.
func (t *TokenTracker) Record(rec TokenAttribution) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	if rec.UncachedInputTokens == 0 && rec.PromptTokens > 0 && rec.CachedInputTokens >= 0 {
		rec.UncachedInputTokens = rec.PromptTokens - rec.CachedInputTokens
		if rec.UncachedInputTokens < 0 {
			rec.UncachedInputTokens = 0
		}
	}
	t.seq++
	rec.Sequence = t.seq
	t.records = append(t.records, rec)
	t.sinceFlush++
	t.appendPersistedLocked(rec)
	if t.closed {
		// A canceled child may return after the bounded shutdown wait. Keep the
		// durable summary in step with any such late attribution record.
		t.writeSummaryLocked()
		if t.persistFile != nil {
			_ = t.persistFile.Close()
			t.persistFile = nil
		}
		return
	}
	if t.sinceFlush >= persistSummaryEveryRecords {
		t.sinceFlush = 0
		t.writeSummaryLocked()
	}
}

// Records returns a shallow copy of all recorded attributions in sequence order.
func (t *TokenTracker) Records() []TokenAttribution {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]TokenAttribution, len(t.records))
	copy(out, t.records)
	return out
}

// Series returns slim per-request chart points, capped to the most recent limit.
func (t *TokenTracker) Series(limit int) []TokenRequestPoint {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	records := t.records
	if limit > 0 && len(records) > limit {
		records = records[len(records)-limit:]
	}
	out := make([]TokenRequestPoint, 0, len(records))
	for _, r := range records {
		out = append(out, TokenRequestPoint{
			Sequence:    r.Sequence,
			Timestamp:   r.Timestamp,
			AgentType:   r.AgentType,
			AgentID:     r.AgentID,
			Iteration:   r.Iteration,
			Category:    r.RequestCategory,
			Retry:       r.RetryAttempt,
			Prompt:      r.PromptTokens,
			Completion:  r.CompletionTokens,
			Cached:      r.CachedInputTokens,
			ConvBytes:   r.ConversationBufferBytes,
			ToolBytes:   r.ToolResultBytes,
			SkillBytes:  r.SkillResultBytes,
			Compactions: r.CompactionCount,
		})
	}
	return out
}

// LoadPersisted re-loads compact records from <dir>/token-usage.jsonl so a
// resumed scan continues with its pre-restart attribution history.
func (t *TokenTracker) LoadPersisted() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.persistDir == "" || len(t.records) > 0 {
		return 0
	}
	f, err := os.Open(filepath.Join(t.persistDir, tokenRecordsFile))
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var p persistedAttribution
		if json.Unmarshal(line, &p) != nil {
			continue
		}
		t.records = append(t.records, p.toAttribution())
		t.seq = p.Q
	}
	return len(t.records)
}

// PersistSummary writes the aggregate summary document to
// <dir>/token-usage.json (best effort).
func (t *TokenTracker) PersistSummary() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeSummaryLocked()
}

// Close flushes the summary one last time and releases the records file
// handle. Safe to call multiple times.
func (t *TokenTracker) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.writeSummaryLocked()
	if t.persistFile != nil {
		_ = t.persistFile.Close()
		t.persistFile = nil
	}
}

// Summary calculates the aggregated metrics across all recorded requests.
func (t *TokenTracker) Summary() TokenSummary {
	if t == nil {
		return TokenSummary{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.summaryLocked()
}

func (t *TokenTracker) summaryLocked() TokenSummary {
	s := TokenSummary{
		SpecialistTokens: make(map[string]int),
		AgentTypeTokens:  make(map[string]int),
		CategoryTokens:   make(map[string]int),
		TotalRequests:    len(t.records),
	}
	for _, r := range t.records {
		s.TotalTokens += r.TotalTokens
		s.PromptTokens += r.PromptTokens
		s.CompletionTokens += r.CompletionTokens
		s.CachedInputTokens += r.CachedInputTokens
		s.UncachedInputTokens += r.UncachedInputTokens

		s.AgentTypeTokens[r.AgentType] += r.TotalTokens
		s.CategoryTokens[r.RequestCategory] += r.TotalTokens

		switch r.AgentType {
		case AgentTypeRoot:
			s.RootTokens += r.TotalTokens
		case AgentTypeVerifier:
			s.VerifierTokens += r.TotalTokens
		default:
			s.SpecialistTokens[r.AgentType] += r.TotalTokens
		}

		if r.RequestCategory == CategoryRetry ||
			r.RequestCategory == CategoryMalformedToolRecovery ||
			r.RequestCategory == CategoryNoToolRecovery ||
			r.RetryAttempt > 0 {
			s.RetryLoopTokens += r.TotalTokens
		}

		s.ToolOutputBytes += r.ToolResultBytes
		s.SkillResultBytes += r.SkillResultBytes
		s.ToolResultMessages += r.ToolResultCount
		s.SkillResultMessages += r.SkillResultCount
	}
	return s
}

// Diagnostics computes the full production diagnostics document from all
// recorded requests.
func (t *TokenTracker) Diagnostics() TokenDiagnostics {
	if t == nil {
		return TokenDiagnostics{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.diagnosticsLocked()
}

func (t *TokenTracker) diagnosticsLocked() TokenDiagnostics {
	d := TokenDiagnostics{
		GeneratedAt:      time.Now(),
		ScanID:           t.scanIDLocked(),
		SpecialistTokens: make(map[string]int),
		AgentTypeTokens:  make(map[string]int),
		CategoryTokens:   make(map[string]int),
		TotalLLMRequests: len(t.records),
	}
	if len(t.records) == 0 {
		return d
	}

	agents := map[string]*agentAgg{}
	agentOrder := []string{}
	agentSeen := map[string]map[string]bool{}
	latestByAgent := map[string]TokenAttribution{}

	var sortedPrompts []int
	cacheReportedCount := 0

	for _, r := range t.records {
		d.TotalTokens += r.TotalTokens
		d.PromptTokens += r.PromptTokens
		d.CompletionTokens += r.CompletionTokens
		if r.CacheReported {
			cacheReportedCount++
			d.CachedInputTokens = intPtr(ptrVal(d.CachedInputTokens) + r.CachedInputTokens)
		}
		d.AgentTypeTokens[r.AgentType] += r.TotalTokens
		d.CategoryTokens[r.RequestCategory] += r.TotalTokens

		switch r.AgentType {
		case AgentTypeRoot:
			d.RootTokens += r.TotalTokens
		case AgentTypeVerifier:
			d.VerifierTokens += r.TotalTokens
		default:
			d.SpecialistTokens[r.AgentType] += r.TotalTokens
		}

		d.ToolResultBytes += r.ToolResultBytes
		d.SkillResultBytes += r.SkillResultBytes
		d.ToolResultMessages += r.ToolResultCount
		d.SkillResultMessages += r.SkillResultCount

		if r.PromptTokens > d.LargestPromptTokens {
			d.LargestPromptTokens = r.PromptTokens
		}
		if r.ConversationBufferBytes > d.LargestConversationBytes {
			d.LargestConversationBytes = r.ConversationBufferBytes
		}

		// Recovery buckets. Each request is counted in exactly one bucket:
		// its request category wins; RetryAttempt>0 only counts when the
		// category itself is not already a recovery category.
		switch r.RequestCategory {
		case CategoryRetry:
			d.Recovery.RetryRequests++
			d.Recovery.RetryTokens += r.TotalTokens
		case CategoryNoToolRecovery:
			d.Recovery.NoToolRequests++
			d.Recovery.NoToolTokens += r.TotalTokens
		case CategoryMalformedToolRecovery:
			d.Recovery.MalformedToolRequests++
			d.Recovery.MalformedToolTokens += r.TotalTokens
		case CategoryFinishRejectionRecovery:
			d.Recovery.FinishRejectionRequests++
			d.Recovery.FinishRejectionTokens += r.TotalTokens
		case CategoryVerifier, CategoryNormalReasoning:
			if r.RetryAttempt > 0 {
				d.Recovery.RetryRequests++
			}
		default:
			if r.RetryAttempt > 0 {
				d.Recovery.RetryRequests++
			}
		}

		sortedPrompts = append(sortedPrompts, r.PromptTokens)

		// Sources aggregate.
		d.Sources.Aggregate.SystemBytes += r.SystemMessageBytes
		d.Sources.Aggregate.AssistantBytes += r.AssistantMessageBytes
		d.Sources.Aggregate.ToolResultBytes += r.ToolResultBytes
		d.Sources.Aggregate.SkillResultBytes += r.SkillResultBytes
		other := r.UserMessageBytes - r.ToolResultBytes
		if other < 0 {
			other = 0
		}
		d.Sources.Aggregate.UserOtherBytes += other

		// Per-agent context growth heuristic (computed after the loop; see
		// uniqueBytesAdded).

		// Per-agent aggregation.
		agg, ok := agents[r.AgentType]
		if !ok {
			agg = &agentAgg{}
			agents[r.AgentType] = agg
			agentOrder = append(agentOrder, r.AgentType)
			agentSeen[r.AgentType] = map[string]bool{}
		}
		if !agentSeen[r.AgentType][r.AgentID] {
			agentSeen[r.AgentType][r.AgentID] = true
			agg.ids = append(agg.ids, r.AgentID)
		}
		agg.requests++
		agg.prompt += r.PromptTokens
		agg.completion += r.CompletionTokens
		agg.total += r.TotalTokens
		if r.CacheReported {
			agg.cacheReported = true
			agg.cached += r.CachedInputTokens
		}
		if r.PromptTokens > agg.maxPrompt {
			agg.maxPrompt = r.PromptTokens
		}
		if r.Iteration > agg.iterations {
			agg.iterations = r.Iteration
		}
		if r.CompactionCount > agg.compactions {
			agg.compactions = r.CompactionCount
		}
		agg.toolBytes += r.ToolResultBytes
		agg.skillBytes += r.SkillResultBytes
		if agg.firstPrompt == 0 {
			agg.firstPrompt = r.PromptTokens
		}
		agg.lastPrompt = r.PromptTokens

		latestByAgent[r.AgentType] = r
	}

	// Cache nullability + hit rate.
	if d.CachedInputTokens != nil {
		unc := d.PromptTokens - *d.CachedInputTokens
		if unc < 0 {
			unc = 0
		}
		d.UncachedInputTokens = &unc
		if d.PromptTokens > 0 {
			rate := float64(*d.CachedInputTokens) / float64(d.PromptTokens)
			d.CacheHitRate = &rate
		}
	}
	d.CacheReportedRequests = cacheReportedCount

	if d.TotalLLMRequests > 0 {
		avg := float64(d.PromptTokens) / float64(d.TotalLLMRequests)
		avgOut := float64(d.CompletionTokens) / float64(d.TotalLLMRequests)
		d.AveragePromptTokensPerRequest = &avg
		d.AverageCompletionTokensPerRequest = &avgOut
	}

	// Prompt growth stats (prompt sizes across requests in arrival order).
	first := t.records[0].PromptTokens
	last := t.records[len(t.records)-1].PromptTokens
	d.Growth.FirstPromptTokens = first
	d.Growth.LastPromptTokens = last
	d.Growth.MedianPromptTokens = median(sortedPrompts)
	d.Growth.P95PromptTokens = percentile(sortedPrompts, 95)
	d.Growth.MaxPromptTokens = d.LargestPromptTokens
	d.Growth.CumulativePromptTokens = d.PromptTokens
	if first > 0 {
		d.Growth.PromptGrowthRatio = float64(last) / float64(first)
	}

	// Context growth heuristic: cumulative bytes sent across all requests vs
	// per-agent new-bytes heuristic.
	d.Context.CumulativeContextBytesSent = cumulativeContextBytes(t.records)
	d.Context.UniqueContextBytesAdded = uniqueBytesAdded(t.records)
	if d.Context.UniqueContextBytesAdded > 0 {
		d.Context.ResendAmplificationRatio =
			float64(d.Context.CumulativeContextBytesSent) / float64(d.Context.UniqueContextBytesAdded)
	}

	// Agents in stable first-seen order.
	for _, at := range agentOrder {
		agg := agents[at]
		b := AgentTokenBreakdown{
			AgentType:           at,
			AgentIDs:            agg.ids,
			Requests:            agg.requests,
			PromptTokens:        agg.prompt,
			CompletionTokens:    agg.completion,
			TotalTokens:         agg.total,
			AveragePromptTokens: float64(agg.prompt) / float64(agg.requests),
			MaxPromptTokens:     agg.maxPrompt,
			ToolResultBytes:     agg.toolBytes,
			SkillResultBytes:    agg.skillBytes,
			Iterations:          agg.iterations,
			Compactions:         agg.compactions,
			FirstPromptTokens:   agg.firstPrompt,
			LastPromptTokens:    agg.lastPrompt,
		}
		if agg.cacheReported {
			b.CachedInputTokens = agg.cached
			b.UncachedInputTokens = agg.prompt - agg.cached
			if b.UncachedInputTokens < 0 {
				b.UncachedInputTokens = 0
			}
		}
		d.Agents = append(d.Agents, b)
	}

	// Latest active-context composition per agent, deterministic order.
	for _, at := range agentOrder {
		r := latestByAgent[at]
		other := r.UserMessageBytes - r.ToolResultBytes
		if other < 0 {
			other = 0
		}
		d.Sources.Latest = append(d.Sources.Latest, AgentContextComposition{
			AgentType:        r.AgentType,
			AgentID:          r.AgentID,
			Iteration:        r.Iteration,
			MessageCount:     r.MessageCount,
			SystemBytes:      r.SystemMessageBytes,
			AssistantBytes:   r.AssistantMessageBytes,
			UserOtherBytes:   other,
			ToolResultBytes:  r.ToolResultBytes,
			SkillResultBytes: r.SkillResultBytes,
			TotalBytes:       r.SerializedMessageBytes,
		})
	}

	return d
}

type agentAgg struct {
	ids           []string
	requests      int
	prompt        int
	completion    int
	total         int
	cached        int
	cacheReported bool
	maxPrompt     int
	iterations    int
	compactions   int
	toolBytes     int
	skillBytes    int
	firstPrompt   int
	lastPrompt    int
}

func (t *TokenTracker) scanIDLocked() string {
	if len(t.records) == 0 {
		return ""
	}
	return t.records[len(t.records)-1].ScanID
}

// uniqueBytesAdded computes the context-growth heuristic per agent: the sum of
// positive deltas between consecutive serialized buffer sizes.
func uniqueBytesAdded(records []TokenAttribution) int {
	last := map[string]int{}
	total := 0
	for _, r := range records {
		prev, seen := last[r.AgentID]
		delta := r.SerializedMessageBytes
		if seen {
			delta = r.SerializedMessageBytes - prev
		}
		if delta > 0 {
			total += delta
		}
		last[r.AgentID] = r.SerializedMessageBytes
	}
	return total
}

// cumulativeContextBytes sums serialized message bytes of every request.
func cumulativeContextBytes(records []TokenAttribution) int {
	total := 0
	for _, r := range records {
		total += r.SerializedMessageBytes
	}
	return total
}

func median(vals []int) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]int(nil), vals...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2])
	}
	return float64(s[n/2-1]+s[n/2]) / 2
}

// percentile uses nearest-rank on the sorted values.
func percentile(vals []int, p int) int {
	if len(vals) == 0 {
		return 0
	}
	s := append([]int(nil), vals...)
	sort.Ints(s)
	idx := (p*len(s) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(s) {
		idx = len(s)
	}
	return s[idx-1]
}

func intPtr(v int) *int { return &v }
func ptrVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// FormatLog returns the [token-analysis] scan-completion summary line.
// Numbers are formatted with K/M suffixes; no sensitive content is included.
func (t *TokenTracker) FormatLog() string {
	d := t.Diagnostics()
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "[token-analysis] scan=%s total=%s prompt=%s output=%s cached=%s uncached=%s requests=%d avg_prompt=%s max_prompt=%s prompt_growth=%.1fx root=%s specialists=%s verifier=%s recovery=%s",
		d.ScanID,
		humanTokens(d.TotalTokens),
		humanTokens(d.PromptTokens),
		humanTokens(d.CompletionTokens),
		humanCache(d.CachedInputTokens),
		humanCache(d.UncachedInputTokens),
		d.TotalLLMRequests,
		humanFloat(d.AveragePromptTokensPerRequest),
		humanTokens(d.LargestPromptTokens),
		d.Growth.PromptGrowthRatio,
		humanTokens(d.RootTokens),
		humanTokens(sumMap(d.SpecialistTokens)),
		humanTokens(d.VerifierTokens),
		humanTokens(d.Recovery.RetryTokens+d.Recovery.NoToolTokens+d.Recovery.MalformedToolTokens+d.Recovery.FinishRejectionTokens),
	)
	return sb.String()
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func humanTokens(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.0fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func humanCache(p *int) string {
	if p == nil {
		return "unknown"
	}
	return humanTokens(*p)
}

func humanFloat(p *float64) string {
	if p == nil {
		return "unknown"
	}
	return humanTokens(int(*p))
}

// ── Compact persistence ─────────────────────────────────────────────────────

// persistedAttribution is the compact on-disk per-request record (short keys).
type persistedAttribution struct {
	S  int64  `json:"s"`  // unix millis
	Q  int    `json:"q"`  // sequence
	A  string `json:"a"`  // agent id
	T  string `json:"t"`  // agent type
	I  int    `json:"i"`  // iteration
	C  string `json:"c"`  // category
	R  int    `json:"r"`  // retry attempt
	M  string `json:"m"`  // model
	P  string `json:"p"`  // provider
	PT int    `json:"pt"` // prompt tokens
	CT int    `json:"ct"` // completion tokens
	TT int    `json:"tt"` // total tokens
	CD int    `json:"cd"` // cached input tokens
	CR bool   `json:"cr"` // cache reported
	N  int    `json:"n"`  // message count
	MB int    `json:"mb"` // serialized message bytes
	SY int    `json:"sy"` // system bytes
	US int    `json:"us"` // user bytes
	AS int    `json:"as"` // assistant bytes
	TN int    `json:"tn"` // tool result count
	TB int    `json:"tb"` // tool result bytes
	SN int    `json:"sn"` // skill result count
	SB int    `json:"sb"` // skill result bytes
	X  int    `json:"x"`  // compaction count
	AP int    `json:"ap"` // agent cumulative prompt
	AO int    `json:"ao"` // agent cumulative output
	SD string `json:"sd"` // scan id
}

func toPersisted(r TokenAttribution) persistedAttribution {
	return persistedAttribution{
		S:  r.Timestamp.UnixMilli(),
		Q:  r.Sequence,
		A:  r.AgentID,
		T:  r.AgentType,
		I:  r.Iteration,
		C:  r.RequestCategory,
		R:  r.RetryAttempt,
		M:  r.Model,
		P:  r.Provider,
		PT: r.PromptTokens,
		CT: r.CompletionTokens,
		TT: r.TotalTokens,
		CD: r.CachedInputTokens,
		CR: r.CacheReported,
		N:  r.MessageCount,
		MB: r.SerializedMessageBytes,
		SY: r.SystemMessageBytes,
		US: r.UserMessageBytes,
		AS: r.AssistantMessageBytes,
		TN: r.ToolResultCount,
		TB: r.ToolResultBytes,
		SN: r.SkillResultCount,
		SB: r.SkillResultBytes,
		X:  r.CompactionCount,
		AP: r.AgentCumulativePrompt,
		AO: r.AgentCumulativeOutput,
		SD: r.ScanID,
	}
}

func (p persistedAttribution) toAttribution() TokenAttribution {
	// Never fabricate: uncached is only derivable when the provider actually
	// reported a cached-token count for this request.
	uncached := 0
	if p.CR {
		uncached = p.PT - p.CD
		if uncached < 0 {
			uncached = 0
		}
	}
	return TokenAttribution{
		ScanID:                  p.SD,
		Sequence:                p.Q,
		AgentID:                 p.A,
		AgentType:               p.T,
		Iteration:               p.I,
		Model:                   p.M,
		Provider:                p.P,
		PromptTokens:            p.PT,
		CompletionTokens:        p.CT,
		TotalTokens:             p.TT,
		CachedInputTokens:       p.CD,
		CacheReported:           p.CR,
		UncachedInputTokens:     uncached,
		MessageCount:            p.N,
		SerializedMessageBytes:  p.MB,
		SystemMessageBytes:      p.SY,
		UserMessageBytes:        p.US,
		AssistantMessageBytes:   p.AS,
		ToolResultCount:         p.TN,
		ToolResultBytes:         p.TB,
		SkillResultCount:        p.SN,
		SkillResultBytes:        p.SB,
		ConversationBufferBytes: p.MB,
		CompactionCount:         p.X,
		AgentCumulativePrompt:   p.AP,
		AgentCumulativeOutput:   p.AO,
		RequestCategory:         p.C,
		RetryAttempt:            p.R,
		Timestamp:               time.UnixMilli(p.S),
	}
}

// appendPersistedLocked appends one compact JSON line. Caller holds t.mu.
func (t *TokenTracker) appendPersistedLocked(rec TokenAttribution) {
	if t.persistDir == "" {
		return
	}
	if t.persistFile == nil {
		if err := os.MkdirAll(t.persistDir, 0o700); err != nil {
			return
		}
		f, err := os.OpenFile(filepath.Join(t.persistDir, tokenRecordsFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("[token-analysis] persist open failed: %v", err)
			return
		}
		t.persistFile = f
	}
	line, err := json.Marshal(toPersisted(rec))
	if err != nil {
		return
	}
	line = append(line, '\n')
	if _, err := t.persistFile.Write(line); err != nil {
		log.Printf("[token-analysis] persist append failed: %v", err)
	}
}

// writeSummaryLocked writes the aggregate summary doc atomically. Caller holds t.mu.
func (t *TokenTracker) writeSummaryLocked() {
	if t.persistDir == "" {
		return
	}
	if err := os.MkdirAll(t.persistDir, 0o700); err != nil {
		return
	}
	d := t.diagnosticsLocked()
	data, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return
	}
	target := filepath.Join(t.persistDir, tokenSummaryFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[token-analysis] summary write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, target); err != nil {
		log.Printf("[token-analysis] summary rename failed: %v", err)
	}
}
