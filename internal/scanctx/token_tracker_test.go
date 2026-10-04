package scanctx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleRecord(agentType, agentID string, iter int, prompt, cached int, convBytes int, category string) TokenAttribution {
	return TokenAttribution{
		ScanID:                  "scan-1",
		AgentID:                 agentID,
		AgentType:               agentType,
		Iteration:               iter,
		Model:                   "MiniMax-M3",
		Provider:                "minimax",
		PromptTokens:            prompt,
		CompletionTokens:        100,
		TotalTokens:             prompt + 100,
		CachedInputTokens:       cached,
		CacheReported:           cached > 0,
		UncachedInputTokens:     prompt - cached,
		MessageCount:            10,
		SerializedMessageBytes:  convBytes,
		ConversationBufferBytes: convBytes,
		RequestCategory:         category,
		Timestamp:               time.Now(),
	}
}

func TestDiagnosticsComputesGrowthAndAgents(t *testing.T) {
	tr := NewTokenTracker()
	tr.Record(sampleRecord(AgentTypeRoot, "root", 1, 28000, 24000, 105000, CategoryNormalReasoning))
	tr.Record(sampleRecord(AgentTypeRoot, "root", 10, 91000, 80000, 355000, CategoryNormalReasoning))
	tr.Record(sampleRecord(AgentTypeRoot, "root", 20, 173000, 150000, 681000, CategoryNoToolRecovery))
	tr.Record(sampleRecord(AgentTypeInjectionServer, "sp-inj", 5, 50000, 0, 200000, CategoryNormalReasoning))
	tr.Record(sampleRecord(AgentTypeVerifier, "verifier", 2, 30000, 0, 90000, CategoryVerifier))
	tr.Record(sampleRecord(AgentTypeRoot, "root", 30, 252000, 200000, 990000, CategoryFinishRejectionRecovery))

	d := tr.Diagnostics()

	if d.TotalLLMRequests != 6 {
		t.Fatalf("TotalLLMRequests = %d, want 6", d.TotalLLMRequests)
	}
	if d.Growth.FirstPromptTokens != 28000 || d.Growth.LastPromptTokens != 252000 {
		t.Fatalf("growth first/last = %d/%d", d.Growth.FirstPromptTokens, d.Growth.LastPromptTokens)
	}
	wantRatio := float64(252000) / float64(28000)
	if diff := d.Growth.PromptGrowthRatio - wantRatio; diff < -0.001 || diff > 0.001 {
		t.Fatalf("growth ratio = %f, want %f", d.Growth.PromptGrowthRatio, wantRatio)
	}
	if d.Growth.MaxPromptTokens != 252000 {
		t.Fatalf("max prompt = %d", d.Growth.MaxPromptTokens)
	}
	// Median of sorted [28000, 30000, 50000, 91000, 173000, 252000] → avg(50000, 91000) = 70500
	if d.Growth.MedianPromptTokens != 70500 {
		t.Fatalf("median = %f, want 40000", d.Growth.MedianPromptTokens)
	}
	// Cumulative = sum of prompts.
	wantCum := 28000 + 91000 + 173000 + 252000 + 50000 + 30000
	if d.Growth.CumulativePromptTokens != wantCum {
		t.Fatalf("cumulative = %d, want %d", d.Growth.CumulativePromptTokens, wantCum)
	}

	if d.RootTokens != (28000+91000+173000+252000)+400 {
		t.Fatalf("root tokens = %d", d.RootTokens)
	}
	if d.VerifierTokens != 30100 {
		t.Fatalf("verifier tokens = %d", d.VerifierTokens)
	}
	if got := d.SpecialistTokens[AgentTypeInjectionServer]; got != 50100 {
		t.Fatalf("specialist injection tokens = %d", got)
	}
	if d.CategoryTokens[CategoryFinishRejectionRecovery] != 252100 {
		t.Fatalf("finish-rejection category tokens = %d", d.CategoryTokens[CategoryFinishRejectionRecovery])
	}
	if d.Recovery.NoToolTokens != 173100 || d.Recovery.FinishRejectionTokens != 252100 {
		t.Fatalf("recovery buckets = %+v", d.Recovery)
	}

	// Cache metrics: every record reports cache → non-nil.
	if d.CachedInputTokens == nil || *d.CachedInputTokens != 24000+80000+150000+200000 {
		t.Fatalf("cached = %v", d.CachedInputTokens)
	}
	if d.CacheReportedRequests != 4 {
		t.Fatalf("cache reported requests = %d, want 4", d.CacheReportedRequests)
	}
	if d.CacheHitRate == nil || *d.CacheHitRate <= 0 || *d.CacheHitRate >= 1 {
		t.Fatalf("cache hit rate = %v", d.CacheHitRate)
	}

	// Agents breakdown has one entry per role in first-seen order.
	if len(d.Agents) != 3 {
		t.Fatalf("agents = %d, want 3", len(d.Agents))
	}
	root := d.Agents[0]
	if root.AgentType != AgentTypeRoot || root.Requests != 4 || root.Iterations != 30 {
		t.Fatalf("root agent breakdown = %+v", root)
	}
	if root.LastPromptTokens != 252000 || root.FirstPromptTokens != 28000 {
		t.Fatalf("root first/last prompt = %d/%d", root.FirstPromptTokens, root.LastPromptTokens)
	}

	// Context heuristics: cumulative = Σ serialized bytes.
	wantSent := 105000 + 355000 + 681000 + 990000 + 200000 + 90000
	if d.Context.CumulativeContextBytesSent != wantSent {
		t.Fatalf("cumulative bytes = %d, want %d", d.Context.CumulativeContextBytesSent, wantSent)
	}
	if d.Context.UniqueContextBytesAdded <= 0 {
		t.Fatalf("unique bytes added = %d", d.Context.UniqueContextBytesAdded)
	}
	if d.Context.ResendAmplificationRatio <= 1 {
		t.Fatalf("amplification ratio = %f, want > 1", d.Context.ResendAmplificationRatio)
	}

	// Latest per-agent source composition present.
	if len(d.Sources.Latest) != 3 {
		t.Fatalf("sources latest = %d, want 3", len(d.Sources.Latest))
	}
}

func TestDiagnosticsCacheNotReportedStaysNull(t *testing.T) {
	tr := NewTokenTracker()
	r := sampleRecord(AgentTypeRoot, "root", 1, 5000, 0, 20000, CategoryNormalReasoning)
	r.CacheReported = false
	tr.Record(r)

	d := tr.Diagnostics()
	if d.CachedInputTokens != nil {
		t.Fatalf("cached should be null when provider never reported: %v", d.CachedInputTokens)
	}
	if d.UncachedInputTokens != nil {
		t.Fatalf("uncached should be null when cache was never reported: %v", d.UncachedInputTokens)
	}
	if d.CacheHitRate != nil {
		t.Fatalf("cache hit rate should be null: %v", d.CacheHitRate)
	}
}

func TestSeriesAndSequence(t *testing.T) {
	tr := NewTokenTracker()
	for i := 0; i < 5; i++ {
		tr.Record(sampleRecord(AgentTypeRoot, "root", i+1, 1000*(i+1), 0, 5000, CategoryNormalReasoning))
	}
	series := tr.Series(3)
	if len(series) != 3 {
		t.Fatalf("series length = %d, want 3", len(series))
	}
	if series[0].Prompt != 3000 || series[0].Sequence != 3 {
		t.Fatalf("series[0] = %+v", series[0])
	}
	all := tr.Series(0)
	if len(all) != 5 || all[4].Sequence != 5 {
		t.Fatalf("full series broken: %+v", all)
	}
}

func TestPersistenceRoundTripAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	tr := NewTokenTracker()
	tr.SetPersistDir(dir)
	tr.Record(sampleRecord(AgentTypeRoot, "root", 1, 28000, 24000, 105000, CategoryNormalReasoning))
	tr.Record(sampleRecord(AgentTypeInjectionServer, "sp", 2, 50000, 0, 200000, CategoryNormalReasoning))

	// Compact records file exists and contains no message content.
	raw, err := os.ReadFile(filepath.Join(dir, tokenRecordsFile))
	if err != nil {
		t.Fatalf("records file: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("bad persisted line: %s", line)
		}
		// Only numeric/short-key metadata is persisted.
		for k := range m {
			if len(k) > 3 {
				t.Fatalf("unexpected long key %q in compact record", k)
			}
		}
	}

	// Summary written on flush interval (2 records < 20 → not yet), force it.
	tr.PersistSummary()
	if _, err := os.Stat(filepath.Join(dir, tokenSummaryFile)); err != nil {
		t.Fatalf("summary file: %v", err)
	}

	// Simulate restart: fresh tracker loads persisted records.
	tr.Close()
	restarted := NewTokenTracker()
	restarted.SetPersistDir(dir)
	if n := restarted.LoadPersisted(); n != 2 {
		t.Fatalf("loaded %d records, want 2", n)
	}
	d := restarted.Diagnostics()
	if d.TotalLLMRequests != 2 {
		t.Fatalf("restarted requests = %d", d.TotalLLMRequests)
	}
	if d.Growth.FirstPromptTokens != 28000 || d.Growth.LastPromptTokens != 50000 {
		t.Fatalf("restarted growth = %+v", d.Growth)
	}
	if d.Agents[0].AgentType != AgentTypeRoot {
		t.Fatalf("restarted agents = %+v", d.Agents)
	}

	// Sequence continues after restart.
	restarted.Record(sampleRecord(AgentTypeRoot, "root", 3, 91000, 0, 355000, CategoryNormalReasoning))
	recs := restarted.Records()
	if recs[2].Sequence != 3 {
		t.Fatalf("sequence after restart = %d, want 3", recs[2].Sequence)
	}
}

func TestUniqueBytesAddedHeuristic(t *testing.T) {
	recs := []TokenAttribution{
		{AgentID: "a", SerializedMessageBytes: 100},
		{AgentID: "a", SerializedMessageBytes: 150},
		{AgentID: "a", SerializedMessageBytes: 130}, // compaction shrink: no positive delta
		{AgentID: "a", SerializedMessageBytes: 200},
		{AgentID: "b", SerializedMessageBytes: 40},
	}
	if got := uniqueBytesAdded(recs); got != 100+50+70+40 {
		t.Fatalf("uniqueBytesAdded = %d, want %d", got, 100+50+70+40)
	}
}

func TestRecordAfterCloseKeepsSummaryAlignedWithLedger(t *testing.T) {
	dir := t.TempDir()
	tr := NewTokenTracker()
	tr.SetPersistDir(dir)
	tr.Record(TokenAttribution{PromptTokens: 100, TotalTokens: 100})
	tr.Close()
	tr.Record(TokenAttribution{RequestCategory: CategoryVerifier})
	tr.Record(TokenAttribution{PromptTokens: 25, TotalTokens: 25})

	data, err := os.ReadFile(filepath.Join(dir, tokenSummaryFile))
	if err != nil {
		t.Fatal(err)
	}
	var summary TokenDiagnostics
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	reloaded := NewTokenTracker()
	reloaded.SetPersistDir(dir)
	if loaded := reloaded.LoadPersisted(); loaded != 3 {
		t.Fatalf("loaded %d requests, want 3", loaded)
	}
	if summary.TotalLLMRequests != 3 || summary.TotalTokens != 125 || reloaded.Summary().TotalTokens != summary.TotalTokens {
		t.Fatalf("late rows and summary disagree: requests=%d tokens=%d ledger=%d",
			summary.TotalLLMRequests, summary.TotalTokens, reloaded.Summary().TotalTokens)
	}
}

func TestFormatLogShape(t *testing.T) {
	tr := NewTokenTracker()
	tr.Record(sampleRecord(AgentTypeRoot, "root", 1, 28000, 24000, 105000, CategoryNormalReasoning))
	line := tr.FormatLog()
	for _, want := range []string{"[token-analysis]", "scan=", "total=", "prompt=", "cached=", "requests=", "prompt_growth="} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line missing %q: %s", want, line)
		}
	}
}

func TestPercentileAndMedian(t *testing.T) {
	vals := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if median(vals) != 5.5 {
		t.Fatalf("median = %f", median(vals))
	}
	if percentile(vals, 95) != 10 {
		t.Fatalf("p95 = %d, want 10", percentile(vals, 95))
	}
	if percentile([]int{7}, 95) != 7 {
		t.Fatalf("p95 single = %d", percentile([]int{7}, 95))
	}
}
