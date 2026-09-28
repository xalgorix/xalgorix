// Package agent provides the core agent loop.
package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/attacksurface"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentmail"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
	"github.com/xalgord/xalgorix/v4/internal/tools/fileedit"
	"github.com/xalgord/xalgorix/v4/internal/tools/finish"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	oobtool "github.com/xalgord/xalgorix/v4/internal/tools/oob"
	"github.com/xalgord/xalgorix/v4/internal/tools/pageagent"
	"github.com/xalgord/xalgorix/v4/internal/tools/proxy"
	"github.com/xalgord/xalgorix/v4/internal/tools/python"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	skillstool "github.com/xalgord/xalgorix/v4/internal/tools/skills"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
	"github.com/xalgord/xalgorix/v4/internal/tools/websearch"
)

var thinkRegex = regexp.MustCompile(`(?s)<think>.*?</think>`)

// toolHardTimeout maps tool names to their per-invocation hard ceiling.
// Tools not in the map fall back to defaultToolHardTimeout (15 min).
var toolHardTimeout = map[string]time.Duration{
	"terminal_execute": 65 * time.Minute,
	"browser_action":   10 * time.Minute,
}

// init injects the notes-blob accessor into the hooks package so the planner
// hook can read the saved endpoint inventory without hooks.go importing the
// notes package (which would form an import cycle: notes imports tools, and
// the agent tool registry is wired from this package). agent.go already
// imports notes for pruning, so this is the natural place to bridge it.
func init() {
	notesBlobForContext = func(scanContextID string) string {
		return notes.FormatForContextID(scanContextID)
	}
}

// defaultToolHardTimeout is the per-invocation hard ceiling applied to any
// tool not explicitly listed in toolHardTimeout.
const defaultToolHardTimeout = 15 * time.Minute

// maxCumulativeRateLimitWait is the safe fallback when a caller constructs a
// Config literal instead of loading the environment-backed configuration.
// Set to 6 hours by default so rolling 5-hour provider quota windows
// can refresh and allow scans to resume without premature termination.
const maxCumulativeRateLimitWait = 6 * time.Hour

// maxRateLimitWait returns the per-scan ceiling for provider rate-limit waits.
// A negative configured value disables the ceiling for operators who
// explicitly need the old behavior; zero means "use the safe default" for
// programmatic Config literals.
func (a *Agent) maxRateLimitWait() time.Duration {
	if a.cfg == nil || a.cfg.MaxRateLimitWaitSec == 0 {
		return maxCumulativeRateLimitWait
	}
	if a.cfg.MaxRateLimitWaitSec < 0 {
		return 0
	}
	return time.Duration(a.cfg.MaxRateLimitWaitSec) * time.Second
}

// hardTimeoutFor returns the configured hard-timeout ceiling for the given
// tool name, falling back to defaultToolHardTimeout when the tool is not
// listed in toolHardTimeout.
func (a *Agent) hardTimeoutFor(tool string) time.Duration {
	if t, ok := toolHardTimeout[tool]; ok {
		return t
	}
	return defaultToolHardTimeout
}

// Event represents an agent event (for UI updates).
type Event struct {
	Type        string // "thinking", "tool_call", "tool_result", "message", "error", "finished"
	Content     string
	ToolName    string
	ToolArgs    map[string]string
	ToolResult  tools.Result
	AgentID     string
	Timestamp   time.Time
	TotalTokens int

	// Aborted marks a "finished" event that is NOT a clean completion: the
	// agent bailed out because of an LLM-side malfunction (refused to call
	// tools, empty responses, repeated errors, provider rate-limit exhaustion).
	// Consumers use this to record the scan as failed instead of completed — a
	// forced abort produced no real result, so reporting it as "completed" is
	// misleading (and, on hosted deployments, must trigger a refund).
	// AbortReason is a short machine-readable tag (e.g. "llm_no_tool_calls").
	Aborted     bool
	AbortReason string
}

// toolExecResult holds the result of an async tool execution.
type toolExecResult struct {
	Result tools.Result
	Err    error
}

// Agent runs the LLM agent loop.
type Agent struct {
	ID                         string
	Name                       string
	cfg                        *config.Config
	client                     *llm.Client
	registry                   *tools.Registry
	scanCtx                    *scanctx.ScanContext // per-session state (vulns, notes, terminal, browser)
	messages                   []llm.Message
	msgMu                      sync.Mutex
	events                     chan Event
	maxIter                    int
	stopped                    atomic.Bool
	iterationDelayMs           atomic.Int64
	childrenMu                 sync.Mutex
	children                   map[*Agent]struct{}
	ctx                        context.Context
	cancel                     context.CancelFunc
	lastActivity               time.Time
	activityMu                 sync.Mutex
	scanStart                  time.Time // when Run() was called
	discoveryMode              bool      // When true, allow finish at any iteration (for Phase 1 enumeration)
	allowedPhases              []int     // selected methodology phases, empty means all
	reconMode                  string    // active or passive reconnaissance
	scanIntensity              string    // active or passive testing/scanning
	activityHosts              []string  // normalized target hosts used by passive policy
	targets                    []string  // raw scan targets from Run(), used to resolve a base URL for probe_hypothesis
	passiveReconGuardActive    bool      // full scans with passive recon block direct access until passive evidence is collected
	passiveReconGuardDone      bool
	passiveReconPassiveLookups int
	passiveReconBlockedActive  int
	passiveReconSourceKeys     map[string]bool
	hooks                      *HookRegistry     // extensible lifecycle hooks
	state                      *ScanState        // shared mutable scan state for hooks
	localGuard                 scopeguard.Config // operator's listener identity, consulted by shouldBlockForOutOfScope to detect Local_Or_Listener_Host references in Gated_Tool args

	// Per-scan whitebox/auth config. Default to the global cfg values but can
	// be overridden PER SCAN via SetTargetAuth/SetSourceRepo before Run() so a
	// multi-tenant host never shares one target's credentials/source with
	// another target's scan.
	targetAuth   string
	targetAuthB  string // optional SECOND account, for horizontal IDOR/BOLA proof
	sourceRepo   string
	scanContext  string       // path to OpenAPI/HAR/Postman artifact(s) seeding the attack surface
	codeScanMode CodeScanMode // code-first scan mode (source review / provision), see SetCodeScanMode
	secretValues []string     // auth values to redact from emitted telemetry

	// scanContextBriefing is built from scanContext in prepareScanEnvironment
	// and injected as a high-priority user message at the start of Run.
	scanContextBriefing string

	// initialIter and resumeBriefing preserve iteration count and previous execution
	// history when a scan is resumed/restarted across server restarts.
	initialIter    int
	resumeBriefing string

	// agentGraph is shared by every agent delegated from this root, but owned
	// by the root scan only. The graph itself is scan-scoped, so concurrent
	// scans cannot overwrite runners or consume one another's worker slots.
	agentGraph         *agentsgraph.Graph
	ownsAgentGraph     bool
	delegatedAgentID   string
	ctfMission         bool
	benchmarkIsolated  bool
	scanBudget         *scanBudget
	lastBudgetTokens   int
	compactionCount    int
	rateLimitBackoffFn func(int) time.Duration
}

// AgentOption configures optional behavior on a *Agent. The
// pattern lets callers (chiefly the per-scan code path in
// internal/web/server.go's runScanInstance) inject a pre-built
// llm.Client carrying a per-scan endpoint resolver, without
// reshuffling NewAgent's required-parameter signature.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
type AgentOption func(*Agent)

// WithLLMClient swaps the default llm.NewClient(cfg) construction
// for a caller-supplied client. The web layer uses this to inject
// a client wrapped with llm.WithResolver(NewFixedResolver(ep)) so
// the operator's resolved provider_profile actually steers the
// scan's outbound traffic. nil resets to default behavior.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func WithLLMClient(c *llm.Client) AgentOption {
	return func(a *Agent) {
		if c != nil {
			a.client = c
		}
	}
}

// WithBenchmarkIsolation constrains an agent-driven benchmark to evidence
// obtainable through the declared target interface (plus an explicitly
// attached source tree for white-box cases). It prevents a locally hosted
// fixture from being "solved" by introspecting its Docker/container runtime.
func WithBenchmarkIsolation() AgentOption {
	return func(a *Agent) {
		a.benchmarkIsolated = true
	}
}

// withRateLimitBackoff overrides the progressive rate-limit backoff policy.
// Used by tests to verify retry loops without sleeping real seconds.
func withRateLimitBackoff(fn func(int) time.Duration) AgentOption {
	return func(a *Agent) {
		a.rateLimitBackoffFn = fn
	}
}

// rateLimitBackoff calculates the progressive backoff interval for a 429 episode.
// 15s (attempt 1) -> 30s (attempt 2) -> 60s (attempt 3+).
func (a *Agent) rateLimitBackoff(consecutive int) time.Duration {
	if a.rateLimitBackoffFn != nil {
		return a.rateLimitBackoffFn(consecutive)
	}
	if consecutive <= 1 {
		return 15 * time.Second
	}
	if consecutive == 2 {
		return 30 * time.Second
	}
	return 60 * time.Second
}

// withAgentGraph makes a delegated agent join its root scan's graph. It is
// intentionally package-private: only the root runner should construct graph
// children, and delegated agents must never stop or replace the shared graph.
func withAgentGraph(graph *agentsgraph.Graph, budget *scanBudget, agentID string) AgentOption {
	return func(a *Agent) {
		a.agentGraph = graph
		a.scanBudget = budget
		a.delegatedAgentID = agentID
	}
}

// withParentContext makes a delegated agent's LLM and tool loop cancel when
// its root graph is stopped.
func withParentContext(parent context.Context) AgentOption {
	return func(a *Agent) {
		if parent != nil {
			a.ctx = parent
		}
	}
}

func delegatedAgentOptions(ctx context.Context, graph *agentsgraph.Graph, budget *scanBudget, agentID string, benchmarkIsolated bool) []AgentOption {
	opts := []AgentOption{
		withParentContext(ctx),
		withAgentGraph(graph, budget, agentID),
	}
	if benchmarkIsolated {
		opts = append(opts, WithBenchmarkIsolation())
	}
	return opts
}

// NewAgent creates a new agent.
// If sc is nil, a default ScanContext is used (CLI mode backward compatibility).
//
// localGuard carries the operator's listener identity (bind address +
// listener port) and is consulted by shouldBlockForOutOfScope to
// classify a Gated_Tool argument's host portion as a
// Local_Or_Listener_Host. Pass scopeguard.Config{BindAddr: "127.0.0.1",
// Port: 0} for callers that don't have a real listener (CLI / tests);
// the listener-port rule only fires when the test feeds a matching
// bind:port, so the default is safe.
//
// scOrOpts is a polymorphic tail used to keep the existing call
// sites compiling unchanged. Callers may pass:
//   - nothing (CLI default ScanContext, no options),
//   - a single *scanctx.ScanContext (existing web-server call site),
//   - one or more AgentOption (new B1 path), or
//   - a *scanctx.ScanContext followed by one or more AgentOption.
//
// Mixing both flavors keeps every old call site working while
// letting the per-scan resolver injection skip building a separate
// constructor.
func NewAgent(cfg *config.Config, name string, events chan Event, localGuard scopeguard.Config, scOrOpts ...any) *Agent {
	if cfg == nil {
		cfg = config.Get()
	}

	// Fix Python httpx interfering with ProjectDiscovery httpx
	fixHttpxConflict()

	// Resolve ScanContext — use provided or fall back to default.
	// Also collect any AgentOption values from the polymorphic
	// tail so callers can mix the legacy ScanContext-only call
	// shape with the new B1 option-bearing call shape without
	// either side knowing about the other.
	var sctx *scanctx.ScanContext
	var opts []AgentOption
	for _, v := range scOrOpts {
		switch t := v.(type) {
		case *scanctx.ScanContext:
			if t != nil {
				sctx = t
			}
		case AgentOption:
			if t != nil {
				opts = append(opts, t)
			}
		case nil:
			// tolerate explicit nils so callers passing a
			// (*scanctx.ScanContext)(nil) don't surprise
			// themselves
		default:
			// Unknown type — log once and skip rather than
			// panic. This branch is unreachable under
			// vet-clean callers, but keeps the function
			// robust against future drift.
			log.Printf("[agent] NewAgent: ignoring unsupported scOrOpts argument %T", v)
		}
	}
	if sctx == nil {
		sctx = scanctx.Default()
	}

	reg := tools.NewRegistry()
	reg.SetScanContextID(sctx.ID)

	terminal.Register(reg)
	fileedit.Register(reg)
	proxy.Register(reg)
	httpclient.Register(reg)
	browser.Register(reg)
	pageagent.Register(reg)
	// NOTE: playwright.Register removed — it registered the same "browser_action" name
	// and overwrote the enhanced rod browser with a weaker curl-based stub.
	notes.Register(reg)
	finish.Register(reg)
	python.Register(reg)
	websearch.Register(reg)
	agentmail.Register(reg)
	skillstool.Register(reg, cfg.SkillsDir)
	oobtool.Register(reg)
	codesearch.Register(reg)

	hookReg := NewHookRegistry()
	RegisterDefaultHooks(hookReg)

	a := &Agent{
		ID:           fmt.Sprintf("agent_%d", time.Now().UnixNano()),
		Name:         name,
		cfg:          cfg,
		client:       llm.NewClient(cfg),
		registry:     reg,
		scanCtx:      sctx,
		events:       events,
		maxIter:      cfg.MaxIterations,
		ctx:          context.Background(),
		lastActivity: time.Now(),
		hooks:        hookReg,
		state:        NewScanState(),
		localGuard:   localGuard,
		targetAuth:   cfg.TargetAuth,
		targetAuthB:  cfg.TargetAuthSecondary,
		sourceRepo:   cfg.SourceRepo,
		scanContext:  cfg.ScanContext,
		children:     make(map[*Agent]struct{}),
	}
	if cfg.IterationDelaySec > 0 {
		a.iterationDelayMs.Store(int64(cfg.IterationDelaySec * 1000))
	}

	// Apply per-call AgentOption values (e.g. WithLLMClient). Options
	// run after the default client is constructed so a nil option
	// leaves the default in place; WithLLMClient overwrites it with a
	// caller-supplied client carrying a per-scan resolver.
	for _, opt := range opts {
		opt(a)
	}
	if a.scanBudget == nil {
		a.scanBudget = newScanBudget()
	}
	if a.registry != nil {
		a.registry.SetContentChecker(a.hasActiveContent)
	}

	// Register the structural planner tools (build_plan / update_plan). These
	// mutate a.state.Plan, so they're registered after the agent exists. They
	// let the LLM author/refine the task graph with knowledge only it has
	// (live recon output the engine can't fully parse); the auto-plan + the
	// per-iteration nudge + the finish gate all consult the same plan.
	a.registerPlanTools(reg)

	// Register the durable hypothesis/evidence ledger tools (record_hypothesis,
	// add_hypothesis_evidence, update_hypothesis, read_ledger). Unlike the plan
	// (per-agent ScanState), the ledger lives on the shared ScanContext, so the
	// coordinator and every delegated specialist read/write the same graph and
	// it persists across restart/resume.
	a.registerLedgerTools(reg)

	// Register the multi-role authorization matrix (authz_matrix). It replays a
	// request as role A / role B / anonymous and records the access-control
	// differential to the ledger. Agent-bound because it needs both configured
	// account credentials, the scope config, and the ledger.
	a.registerAuthzMatrixTool(reg)

	// Register the out-of-band blind-vulnerability verifier (verify_oob). It
	// polls the OAST oracle for a planted token and records blind-execution
	// proof to the ledger. Agent-bound for ledger access; makes no outbound
	// request itself, so no scope gate is needed.
	a.registerOOBVerifyTool(reg)

	// Register the bounded timing-differential verifier (verify_timing). It is
	// the in-band fallback for blind server-side injection when reconnaissance
	// yields a safe delay primitive but OAST is unavailable or ambiguous.
	a.registerVerifyTimingTool(reg)

	// Register HAR ingestion (ingest_har): turns a logged-in HAR into live
	// authenticated scan context — registers session auth and seeds the ledger
	// with authenticated-endpoint authorization hypotheses.
	a.registerHARIngestTool(reg)

	// Register the whitebox source-to-runtime bridge (scan_source_sinks): sweeps
	// the attached source tree for dangerous sinks and seeds each as a
	// source->sink hypothesis (Endpoint=file:line, Origin=source-sink) so the
	// evidence-driven loop can trace it to a reachable route and exploit it.
	a.registerScanSourceSinksTool(reg)

	// Register the second half of the bridge (scan_source_routes): extracts HTTP
	// route declarations from the attached source and seeds each as a hypothesis
	// with a REAL reachable path (Origin=source-route), correlating a route with
	// dangerous sinks in the same handler file so the sink gets an attackable
	// endpoint.
	a.registerScanSourceRoutesTool(reg)

	// Register the third part of the bridge (probe_hypothesis): issues ONE
	// scope-gated baseline request against the live target for a ledger
	// hypothesis that carries a real HTTP path (e.g. a source-route hypothesis)
	// and records the response as evidence — turning a seeded path into a
	// confirmed-reachable (or blocked) lead. Agent-bound: needs the scope
	// config, session auth, the scan target, and the ledger.
	a.registerProbeHypothesisTool(reg)

	// Register the deterministic error-based SQL-injection confirmer
	// (verify_sqli): the SQLi counterpart of verify_xss. Given a seeded hypothesis
	// or a url + parameter, it sends a benign baseline, a single-quote payload,
	// and a doubled-quote payload, and confirms injection when a DBMS error
	// appears on the broken request but not on the baseline — recording
	// exploit-proven evidence in the ledger. Agent-bound: needs the scope config,
	// session auth, the scan target, and the ledger.
	a.registerVerifySQLiTool(reg)

	// Register the deterministic server-side template-injection confirmer
	// (verify_ssti): the SSTI sibling of verify_sqli. Given a seeded hypothesis
	// or a url + parameter, it sends a benign baseline plus {{a*b}} / ${a*b}
	// payloads with randomized operands, and confirms injection when the
	// evaluated product appears in the probe response but not the baseline —
	// recording exploit-proven evidence in the ledger. Agent-bound: needs the
	// scope config, session auth, the scan target, and the ledger.
	a.registerVerifySSTITool(reg)
	a.registerVerifyPathTraversalTool(reg)

	// Register the deterministic XML External Entity confirmer (verify_xxe): the
	// XXE sibling of verify_sqli/verify_ssti. Given a seeded hypothesis or a url,
	// it POSTs a benign baseline XML plus a DOCTYPE/external-entity payload that
	// reads a local file, and confirms injection when the file's contents appear
	// in the probe response but not the baseline — recording exploit-proven
	// evidence in the ledger. Agent-bound: needs the scope config, session auth,
	// the scan target, and the ledger.
	a.registerVerifyXXETool(reg)

	// Register the Cross-Site Request Forgery confirmer (verify_csrf): given a
	// url (or hypothesis) and the state-change body, it replays the request with
	// a forged cross-site Origin/Referer and no anti-CSRF token, and confirms
	// CSRF when the server accepts it — declining when the endpoint is protected
	// by an Authorization header or has no ambient cookie session (neither is
	// proof of CSRF). Agent-bound: needs the scope config, session auth, the scan
	// target, and the ledger.
	a.registerVerifyCSRFTool(reg)

	// Bounded working context retrieval tool: returns the byte-identical
	// archived original of any stubbed tool result (flag-gated stubs, but the
	// tool is always registered so archived outputs are reachable).
	a.registerToolArchiveTool(reg)

	// Create cancellable context
	a.ctx, a.cancel = context.WithCancel(a.ctx)
	// Wire context to LLM client so cancel interrupts pending HTTP requests
	a.client.SetContext(a.ctx)

	if a.agentGraph == nil {
		a.ownsAgentGraph = true
		// The lifetime cap must cover every engine lane plus one manual
		// model-spawned agent: the early recon-discovery lane launches before
		// the testing wave, so the old default (3) would strand the wave.
		a.agentGraph = agentsgraph.NewWithLimit(a.ctx, len(defaultSpecialistProfiles)+1, func(ctx context.Context, agentID, subName string, targets []string, task string) (string, error) {
			subEvents := make(chan Event, 256)
			// All descendants join this root's graph and inherit its cancellation
			// context. Creating a child therefore cannot overwrite another scan's
			// runner or leave an uncancellable worker behind.
			subArgs := []any{sctx}
			for _, opt := range delegatedAgentOptions(ctx, a.agentGraph, a.scanBudget, agentID, a.benchmarkIsolated) {
				subArgs = append(subArgs, opt)
			}
			if a.client != nil {
				subArgs = append(subArgs, WithLLMClient(a.client.Clone()))
			}
			subAgent := NewAgent(cfg, subName, subEvents, a.localGuard, subArgs...)
			a.registerChildAgent(subAgent)
			defer a.unregisterChildAgent(subAgent)
			subAgent.SetPhaseRestrictions(a.allowedPhases)
			subAgent.SetActivityPolicy(a.reconMode, a.scanIntensity, a.activityHosts)
			subAgent.SetTargetAuth(a.targetAuth)
			subAgent.SetTargetAuthSecondary(a.targetAuthB)
			subAgent.SetSourceRepo(a.sourceRepo)
			subAgent.SetScanContext(a.scanContext)
			subAgent.SetCodeScanMode(a.codeScanMode)
			if a.discoveryMode {
				subAgent.SetDiscoveryMode(true)
			}
			// Role-scoped tool documentation (flag-gated): withhold
			// role-foreign tool docs from this specialist's prompt. Tools stay
			// registered/callable and remain listed in a compact index line.
			subAgent.applyRoleToolScope()

			var results strings.Builder
			var delegatedErr error
			done := make(chan struct{})
			safe.Go("agent.subagent_stream", a.scanCtx.ID, func() {
				defer close(done)
				for evt := range subEvents {
					if evt.Type == "tool_result" && evt.ToolResult.Output != "" {
						partial := fmt.Sprintf("[%s] %s", evt.ToolName, truncStr(evt.ToolResult.Output, 200))
						results.WriteString(partial)
						results.WriteByte('\n')
						a.agentGraph.AddPartialResult(agentID, partial)
					}
					if evt.Type == "finished" {
						results.WriteString("\nCompleted: ")
						results.WriteString(truncStr(evt.Content, 500))
						results.WriteString("\n")
						if evt.Aborted {
							delegatedErr = fmt.Errorf("delegated agent aborted: %s", valueOr(evt.AbortReason, evt.Content))
						}
					}
					if a.events != nil {
						parentEvt := evt
						parentEvt.AgentID = agentID
						safeSend(a.events, parentEvt, 0)
					}
				}
			})
			// These defers also run if Agent.Run panics and the graph's panic
			// boundary recovers it, so the event-forwarder cannot become a zombie.
			defer subAgent.Stop()
			streamClosed := false
			defer func() {
				if !streamClosed {
					close(subEvents)
					<-done
				}
			}()
			delegatedTask := buildDelegatedTaskInstruction(task, agentID, a.ctfMission)
			subAgent.Run(targets, delegatedTask)
			close(subEvents)
			<-done
			streamClosed = true
			return results.String(), delegatedErr
		})
	}
	// Only the root coordinator can delegate. Prompt wording alone is not a
	// sufficient boundary: removing the graph tools from child registries makes
	// nested delegation impossible and keeps the one-wave lifetime budget exact.
	if a.delegatedAgentID == "" {
		a.agentGraph.Register(reg)
	}

	// A coordinator cannot silently finish while delegated evidence is still
	// running or has not been collected. Descendants skip this gate because the
	// root coordinator is responsible for collecting the whole graph.
	if a.ownsAgentGraph {
		a.hooks.Register(OnFinishAttempt, a.delegatedWorkFinishGate)
	}

	// Bind verification to THIS registry/agent. Parallel hunters can now report
	// concurrently without borrowing another agent's LLM client or overwriting a
	// scan-context-global verifier callback.
	reporting.RegisterWithVerifier(reg, a.verifyFinding)

	return a
}

func (a *Agent) delegatedWorkFinishGate(_ *ScanState, _ map[string]string) HookResult {
	if a == nil || a.agentGraph == nil {
		return HookResult{}
	}
	if running := a.agentGraph.RunningCount(); running > 0 {
		return HookResult{Block: true, BlockReason: fmt.Sprintf("%d delegated agent(s) are still running. Collect their evidence before finishing:\n%s", running, a.agentGraph.PendingSummary())}
	}
	if pending := a.agentGraph.UncollectedCount(); pending > 0 {
		return HookResult{Block: true, BlockReason: fmt.Sprintf("%d delegated result(s) have not been collected. Read them before finishing:\n%s", pending, a.agentGraph.PendingSummary())}
	}
	return HookResult{}
}

// noteDelegationDefer records why the specialist wave has not launched and
// emits a diagnostic message whenever the reason changes. Without this, a wave
// that never fired was invisible in the scan event stream and indistinguishable
// from a wave that ran and finished — production scans lost their specialist
// acceleration with no trace of why.
func (a *Agent) noteDelegationDefer(reason string) {
	if a == nil || a.state == nil {
		return
	}
	// Surface operator-disabled lanes in the defer message so the log
	// explains itself: the operator turned them off, the engine didn't lose
	// them.
	if a.cfg != nil && len(a.cfg.DisabledSpecialists) > 0 && strings.Contains(reason, "not complete") {
		reason += " (operator-disabled lanes: " + strings.Join(a.cfg.DisabledSpecialists, ", ") + ")"
	}
	if a.state.DelegationDeferReason == reason {
		return
	}
	a.state.DelegationDeferReason = reason
	a.emit(Event{Type: "message", Content: fmt.Sprintf("⏸️ Specialist wave deferred: %s. The wave launches automatically once the blocker clears (configuration blockers need an operator change).", reason)})
}

// reconPhaseComplete reports whether the comprehensive reconnaissance
// milestone is met: fingerprinting/banners, a saved endpoint inventory, real
// content discovery, and at least one detected technology. The specialist
// wave and the coordinator's hypothesis-claiming lane wait for this so every
// run partitions the SAME fully mapped surface. Launching testing earlier —
// from whatever thin inventory exists a minute into the scan — was the
// largest source of run-to-run result variance: identical targets produced
// specialist lanes grounded in 13 paths one run and 17 the next.
func (a *Agent) reconPhaseComplete() bool {
	if a == nil || a.state == nil {
		return false
	}
	s := a.state

	// Legacy booleans remain the floor: a curl, an inventory note, one
	// content-discovery pass, and at least one detected tech. The coverage
	// model adds the breadth that was previously missing.
	if !s.ReconDone || !s.EndpointInventorySaved || !s.DirBustingDone || len(s.DetectedTechs) == 0 {
		return false
	}

	// Per-dimension requirements: each must be complete or marked
	// not-applicable. Raw IP targets skip DNS/subdomain dimensions;
	// static sites skip API/JS; targets without auth skip auth mapping.
	rc := s.ReconCoverage

	// HTTP probing and tech fingerprinting are always required for web targets.
	if !rc.HTTPProbed {
		return false
	}
	if !rc.TechFingerprinted && !rc.NAMarked["tech_fingerprint"] {
		return false
	}

	// Crawling OR JS analysis must have occurred (at least one surface-
	// mapping technique beyond a single curl).
	if !rc.Crawled && !rc.JSAnalyzed && !rc.NAMarked["crawling"] {
		return false
	}

	// Content discovery: at least one host received a real wordlist pass.
	if len(rc.ContentDiscoveredHosts) == 0 && !rc.NAMarked["content_discovery"] {
		return false
	}
	// Per-application coverage: every distinct host the inventory surfaced
	// (bounded to the first maxReconHostRequirement) must have been
	// content-discovered OR carry a typed disposition (not_applicable,
	// blocked, covered-by-equivalent-app). One pass on app.example.com no
	// longer silently satisfies api/admin/files.example.com.
	for _, host := range distinctApplicationHosts(s) {
		if rc.ContentDiscoveredHosts[host] || reconHostDispositioned(s, host) {
			continue
		}
		return false
	}
	// Applicability-informed required dimensions (N/A dispositions honored):
	// API signals require API-surface discovery; an auth surface requires
	// auth mapping; input-bearing surface requires parameter discovery.
	if apiSignalsExist(s) && !rc.APISurfaceDiscovered && !rc.NAMarked["api_surface"] {
		return false
	}
	if authSurfaceExists(s) && rc.AuthMapped == "" && !rc.NAMarked["auth_mapping"] {
		return false
	}
	if parameterizedSurfaceExists(s) && !rc.ParamDiscovered && !rc.NAMarked["parameter_discovery"] {
		return false
	}

	// Deep mode expects additional breadth. Standard mode treats these
	// as recommended but not blocking.
	if a.scanIntensity == activityModeActive && a.isDeepMode() {
		// Deep: service enumeration and parameter discovery expected.
		if !rc.ServicesProbed && !rc.NAMarked["service_discovery"] {
			return false
		}
		if !rc.ParamDiscovered && !rc.NAMarked["parameter_discovery"] {
			return false
		}
	}

	return true
}

// isDeepMode reports whether the scan runs in deep-intensity mode. Deep used
// to be inferred from len(AllowedPhases) >= 20, which misread the EMPTY
// selection (meaning the full methodology is allowed) as "not deep" and
// silently disabled deep-mode recon requirements for full scans. The explicit
// ScanDepth field is now derived once at scan start; this accessor stays for
// compatibility.
func (a *Agent) isDeepMode() bool {
	if a == nil || a.state == nil {
		return false
	}
	return a.state.ScanDepth == "deep"
}

// reconIncompleteReasons lists the reconnaissance milestones still missing,
// for wave/claim block messages.
func (a *Agent) reconIncompleteReasons() []string {
	if a == nil || a.state == nil {
		return nil
	}
	s := a.state
	rc := s.ReconCoverage
	var missing []string

	if !s.ReconDone {
		missing = append(missing, "banner/technology fingerprinting (curl -sI, whatweb)")
	}
	if !s.EndpointInventorySaved {
		missing = append(missing, "an Endpoint Inventory note listing every live route")
	}
	if !s.DirBustingDone {
		missing = append(missing, "content discovery on at least one host (ffuf/gobuster/dirsearch)")
	}
	if len(s.DetectedTechs) == 0 {
		missing = append(missing, "technology stack detection (whatweb / server headers)")
	}

	// Coverage-model dimensions
	if !rc.HTTPProbed {
		missing = append(missing, "HTTP probing of the live web surface (confirm status, title, redirects)")
	}
	if !rc.TechFingerprinted && !rc.NAMarked["tech_fingerprint"] {
		missing = append(missing, "deliberate technology fingerprinting (whatweb / wappalyzer, not just a Server header)")
	}
	if !rc.Crawled && !rc.JSAnalyzed && !rc.NAMarked["crawling"] {
		missing = append(missing, "web crawling or JavaScript analysis (katana/gospider/sitemap or JS bundle routes)")
	}
	if len(rc.ContentDiscoveredHosts) == 0 && !rc.NAMarked["content_discovery"] {
		missing = append(missing, "content discovery with a real wordlist on the primary host")
	}
	if a.isDeepMode() {
		if !rc.ServicesProbed && !rc.NAMarked["service_discovery"] {
			missing = append(missing, "service/port enumeration (nmap/naabu on the target)")
		}
	}
	for _, host := range distinctApplicationHosts(s) {
		if rc.ContentDiscoveredHosts[host] || reconHostDispositioned(s, host) {
			continue
		}
		missing = append(missing, "content discovery on "+host+" (or a typed disposition via update_plan: host "+host+": blocked/na/covered_by_equivalent)")
	}
	if apiSignalsExist(s) && !rc.APISurfaceDiscovered && !rc.NAMarked["api_surface"] {
		missing = append(missing, "API-surface discovery (OpenAPI/GraphQL/route enumeration)")
	}
	if authSurfaceExists(s) && rc.AuthMapped == "" && !rc.NAMarked["auth_mapping"] {
		missing = append(missing, "auth mapping (login flows, session capture)")
	}
	if parameterizedSurfaceExists(s) && !rc.ParamDiscovered && !rc.NAMarked["parameter_discovery"] {
		missing = append(missing, "parameter/input discovery (arjun/x8, forms, query parameters)")
	}
	return missing
}

// maybeAutoDelegate launches the one deterministic specialist wave once the
// comprehensive reconnaissance milestone (reconPhaseComplete) has produced a
// final surface, grounded plan, and shared ledger. Requiring the coordinator LLM
// to remember spawn_agent proved nondeterministic in real runs: it could ignore
// several explicit nudges and continue serial work until the scan deadline.
// Engine-owned launch makes coverage parallel by construction while the graph's
// lifetime cap and child tool registry still make additional/nested waves
// impossible. Roles with hard prerequisites are filtered deterministically:
// authorization work is not launched without a configured or ingested
// authenticated identity, because an anonymous-only specialist otherwise
// degenerates into password spraying and disabled-signup probing.
func (a *Agent) maybeAutoDelegate(targets []string) string {
	if a == nil || a.state == nil || a.registry == nil || a.agentGraph == nil ||
		a.delegatedAgentID != "" || a.ctfMission || a.state.DiscoveryMode ||
		a.state.ReconOnlyMode || a.state.DelegationAttempted {
		return ""
	}
	// XALGORIX_DISABLE_AUTO_DELEGATE=true: skip the specialist wave entirely,
	// restoring pre-v4.6.93 behavior where the root agent does all the work
	// itself. Some operators prefer the deeper single-threaded methodology.
	if a.cfg != nil && a.cfg.DisableAutoDelegate {
		a.noteDelegationDefer("disabled by configuration (XALGORIX_DISABLE_AUTO_DELEGATE=true)")
		a.state.DelegationAttempted = true
		return ""
	}
	if _, ok := a.registry.Get("spawn_agent"); !ok {
		a.noteDelegationDefer("spawn_agent tool is not available in this agent's registry")
		return ""
	}

	// ── Stage E: early discovery lane ──
	// The recon-discovery specialist launches as soon as the plan + ledger
	// exist — in PARALLEL with the root's remaining baseline recon (bounded
	// dirbust, tech detection). Deep enumeration beyond the baseline is the
	// highest-leverage coverage lever: undiscovered surface is silently
	// untested surface. Its discoveries flow back through the shared
	// Discovery Manifest note, which the root's planner re-extracts into the
	// plan's endpoint set every iteration. Skipped when the model already
	// spawned anything itself (manual delegation disables engine launches).
	if !a.state.ReconLaneLaunched && a.state.Plan != nil && a.state.PlanBuilt &&
		a.state.LedgerSeeded && a.state.EndpointInventorySaved && a.state.Iteration >= 5 &&
		a.agentGraph.DelegationCount() == 0 {
		for _, profile := range defaultSpecialistProfiles {
			if profile.Role != "recon-discovery" || a.specialistDisabled(profile.Role) {
				continue
			}
			if id := a.spawnSpecialistProfile(profile, targets); id != "" {
				a.state.ReconLaneLaunched = true
				a.state.DelegationNudgeFired = true
				a.state.DelegationDeferReason = ""
				return fmt.Sprintf("🔭 ENGINE DISCOVERY LANE STARTED: launched the recon-discovery specialist (%s). It enumerates BEYOND your baseline — extensions, params, JS routes, backups, source files — and folds live-verified routes into the 'Discovery Manifest' note; your plan absorbs them automatically. YOU continue the baseline recon NOW (bounded wordlist pass + tech detection): the testing wave still waits for YOUR recon milestones. Do not spawn another discovery agent.", id)
			}
		}
	}

	// ── Stage W: the testing wave ──
	// One wave over the testing lanes, gated on comprehensive recon as before.
	// DelegationCount is compared against the engine's own launches: if the
	// model manually spawned anything beyond the discovery lane, the engine
	// stays out of delegation entirely (the manual wave owns the graph).
	engineLaunched := 0
	if a.state.ReconLaneLaunched {
		engineLaunched++
	}
	if a.state.WaveLaunched || !a.reconPhaseComplete() || a.state.Iteration < 5 || a.state.Plan == nil ||
		!a.state.PlanBuilt || !a.state.LedgerSeeded || a.agentGraph.DelegationCount() > engineLaunched {
		if a.state.Iteration >= 5 && !a.state.WaveLaunched {
			a.noteDelegationDefer("comprehensive recon not complete (missing: " + strings.Join(a.reconIncompleteReasons(), ", ") + ")")
		}
		return ""
	}

	// Ground the wave in the FINAL mapped surface. The auto plan is built as
	// soon as an inventory note exists; dirbusting and client-route discovery
	// surface more endpoints afterwards, so that early plan goes stale. Rebuild
	// the engine-owned plan from the completed surface (reconcilePlan restores
	// task completion from the coverage matrix) so every run partitions the
	// same fully mapped endpoint set instead of whatever a one-minute
	// inventory happened to contain. An LLM-authored plan is never clobbered.
	if planIsEngineAuthored(a.state.Plan) && len(a.state.DiscoveredEndpoints) > 0 {
		a.state.Plan = AutoPlanFromState(a.state)
		a.state.PlanBuilt = true
		reconcilePlan(a.state)
	}

	profiles := a.eligibleSpecialistProfiles()
	spawned := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		if a.specialistDisabled(profile.Role) {
			continue
		}
		if id := a.spawnSpecialistProfile(profile, targets); id != "" {
			spawned = append(spawned, id)
		}
	}
	if len(spawned) == 0 {
		return ""
	}
	a.state.DelegationAttempted = true
	a.state.WaveLaunched = true
	a.state.DelegationNudgeFired = true
	a.state.DelegationDeferReason = ""
	return fmt.Sprintf("🚀 ENGINE DELEGATION STARTED: launched %d non-overlapping specialists (%s). "+
		"Continue the root's highest-value remaining work NOW — the specialist wave is a parallel "+
		"accelerator, not a substitute for your own testing. While they run: (1) test endpoint/class "+
		"pairs they do NOT cover, (2) do your own deep payload work on high-value routes, (3) "+
		"periodically collect results with check_agent/wait_agent, and (4) after ALL specialists are "+
		"collected, independently verify every claimed finding and CONTINUE TESTING uncovered surface — "+
		"specialist completion is NOT a finish signal. Do not launch another wave.",
		len(spawned), strings.Join(spawned, ", "))
}

func (a *Agent) eligibleSpecialistProfiles() []specialistProfile {
	profiles := make([]specialistProfile, 0, len(defaultSpecialistProfiles))
	for _, profile := range defaultSpecialistProfiles {
		// The discovery lane launches EARLY (stage E), not with the testing
		// wave — its work is the wave's prerequisite, not a testing lane.
		if profile.Role == "recon-discovery" {
			continue
		}
		if profile.Role == "authz-logic" && len(a.authzIdentities()) <= 1 {
			continue
		}
		// Operator-toggled lanes are excluded from the wave entirely.
		if a.specialistDisabled(profile.Role) {
			continue
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

// spawnSpecialistProfile launches one specialist with the standard lane
// contract and returns its agent id ("" when the spawn was rejected).
func (a *Agent) spawnSpecialistProfile(profile specialistProfile, targets []string) string {
	target := ""
	if len(targets) > 0 {
		target = strings.TrimSpace(targets[0])
	}
	brief, laneHypothesisIDs := a.specialistLaneBrief(profile)
	task := fmt.Sprintf(`Own ONLY the %q lane against %s.
Assigned vulnerability classes: %s.
Start with read_ledger(filter=schedulable), then claim_next_hypothesis separately for every assigned class. Do not repeat root reconnaissance or work outside this lane.
Local workspace: create and use tmp/%s/ for every scanner-side artifact. Never use host /tmp and never read or overwrite another lane's scratch files.
Required proof: %s.
Stopping rule: %s.%s`, profile.Role, target, strings.Join(profile.VulnClasses, ", "), profile.Role, profile.EvidenceContract, profile.StoppingRule, brief)
	args := map[string]string{
		"name": profile.Role,
		"task": task,
	}
	if target != "" {
		args["target"] = target
	}
	a.emit(Event{Type: "tool_call", ToolName: "spawn_agent", ToolArgs: args})
	result, err := a.registry.Execute("spawn_agent", args)
	if err != nil {
		result = tools.Result{Error: err.Error()}
	}
	a.emit(Event{Type: "tool_result", ToolName: "spawn_agent", ToolResult: result})
	if result.Metadata == nil || result.Metadata["spawned"] != true {
		return ""
	}
	id, _ := result.Metadata["agent_id"].(string)
	if id != "" && len(laneHypothesisIDs) > 0 {
		if l := a.ledger(); l != nil {
			for _, h := range laneHypothesisIDs {
				// Soft lane ownership: the hypotheses stay queued and
				// claimable, but the child's finish gate can now see
				// assigned-but-never-claimed work instead of an empty lane
				// looking exhausted.
				l.MarkAssigned(h, id)
			}
		}
	}
	return id
}

// specialistLaneBrief grounds a specialist's spawn task in CONCRETE schedulable
// work: the live ledger's queued hypotheses for its assigned classes, plus the
// resolved methodology skills for those classes. "Test business logic
// everywhere" becomes "H-18 business-logic POST /api/checkout", and the class
// knowledge loads deterministically instead of hoping the child remembers the
// catalog.
func (a *Agent) specialistLaneBrief(profile specialistProfile) (string, []string) {
	var b strings.Builder
	l := a.ledger()

	// Concrete hypotheses per assigned class (bounded).
	var lines []string
	var ids []string
	if l != nil {
		for _, class := range profile.VulnClasses {
			count := 0
			for _, h := range l.All() {
				if count >= 3 {
					break
				}
				if h.Status != scanctx.HypothesisQueued && h.Status != scanctx.HypothesisBlocked {
					continue
				}
				if !vulnClassMatches(h.VulnClass, class) {
					continue
				}
				if strings.TrimSpace(h.AssignedTo) != "" {
					continue // already owned by another lane
				}
				loc := strings.TrimSpace(h.VulnClass + " " + h.Endpoint)
				if h.Parameter != "" {
					loc += " [" + h.Parameter + "]"
				}
				lines = append(lines, fmt.Sprintf("  • %s: %s", h.ID, loc))
				ids = append(ids, h.ID)
				count++
			}
		}
	}
	if len(lines) > 0 {
		sort.Strings(lines)
		b.WriteString("\nAssigned concrete hypotheses (claim these FIRST, one per class, until the lane is exhausted):\n")
		b.WriteString(strings.Join(lines, "\n"))
	}

	// Resolved lane methodology (1-3 skills).
	var skills []string
	for _, class := range profile.VulnClasses {
		if name, ok := VulnClassSkill(class); ok && name != "" {
			dup := false
			for _, s := range skills {
				if s == name {
					dup = true
					break
				}
			}
			if !dup {
				skills = append(skills, name)
			}
		}
		if len(skills) >= 3 {
			break
		}
	}
	if len(skills) > 0 {
		quoted := make([]string, 0, len(skills))
		for _, s := range skills {
			quoted = append(quoted, strconv.Quote(s))
		}
		b.WriteString("\nLane methodology: load read_skill(name=" + strings.Join(quoted, "), then read_skill(name=") + ") before your first probe.")
	}
	return b.String(), ids
}

// vulnClassMatches compares a ledger hypothesis class with a lane class,
// normalizing both through the canonical registry so "bola" matches "idor" and
// "race-condition" matches "race-conditions".
func vulnClassMatches(have, want string) bool {
	have, want = strings.TrimSpace(have), strings.TrimSpace(want)
	if have == "" || want == "" {
		return false
	}
	if strings.EqualFold(have, want) {
		return true
	}
	hc, wc := CanonicalVulnClassID(have), CanonicalVulnClassID(want)
	return hc != "" && hc == wc
}

// specialistDisabled reports whether the named specialist lane is turned off
// via XALGORIX_DISABLED_SPECIALISTS (comma-separated lane names). Names match
// the profile Role exactly and are matched case-insensitively.
func (a *Agent) specialistDisabled(role string) bool {
	if a == nil || a.cfg == nil || len(a.cfg.DisabledSpecialists) == 0 {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(role))
	for _, d := range a.cfg.DisabledSpecialists {
		if d == want {
			return true
		}
	}
	return false
}

// PlanDisposition returns the root plan's final task dispositions for
// reporting: total tasks, completed, skipped, and unfinished (pending+active).
// Completed-vs-skipped is the honest coverage distinction (skips are not
// executed coverage), and unfinished work at terminal time is the visible
// signal of an incomplete assessment.
func (a *Agent) PlanDisposition() (total, completed, skipped, unfinished int) {
	if a == nil || a.state == nil || a.state.Plan == nil {
		return 0, 0, 0, 0
	}
	pending, active, completed, skipped := a.state.Plan.Counts()
	return len(a.state.Plan.Tasks), completed, skipped, pending + active
}

// dedupeBatchCalls drops byte-identical (tool, args) repeats from a single
// model response. The model cannot have seen the first call's result when it
// emits the duplicate, so re-executing it is pure waste — and the stuck-call
// tracker previously counted those in-batch duplicates toward the loop-limit
// kill. Cross-turn repetition (the model saw the result and re-issued anyway)
// is unaffected and still guarded.
func dedupeBatchCalls(calls []llm.ToolCall) []llm.ToolCall {
	if len(calls) < 2 {
		return calls
	}
	seen := make(map[string]bool, len(calls))
	kept := calls[:0]
	for _, tc := range calls {
		key := tc.Name + "\x00" + hashToolArgs(tc.Name, tc.Args)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, tc)
	}
	return kept
}

// PlanWorkedPhases returns the phases of plan tasks that were COMPLETED.
// The plan's own phase attribution is the richest per-phase work signal:
// AutoPlan and model-authored tasks both carry explicit phase numbers, so a
// completed auth-session task marks phase 5 worked, a completed business-
// logic task marks phase 12, and so on - classes the command heuristics and
// phase-mention parsing cannot see. Only completed tasks count; skips are
// dispositions, not work.
func (a *Agent) PlanWorkedPhases() []int {
	if a == nil || a.state == nil || a.state.Plan == nil {
		return nil
	}
	var phases []int
	seen := map[int]bool{}
	for _, t := range a.state.Plan.Tasks {
		if t.Status != TaskCompleted || t.Phase <= 0 || seen[t.Phase] {
			continue
		}
		seen[t.Phase] = true
		phases = append(phases, t.Phase)
	}
	return phases
}

// SetDiscoveryMode configures the agent to skip minimum iteration checks on finish.
// Used for Phase 1 subdomain enumeration where we want the agent to exit immediately.
func (a *Agent) SetDiscoveryMode(enabled bool) {
	a.discoveryMode = enabled
	a.refreshPassiveReconGuard()
}

// SetPhaseRestrictions configures the selected methodology phases for policy hooks.
// An empty slice means the full methodology is allowed.
func (a *Agent) SetPhaseRestrictions(phases []int) {
	a.allowedPhases = append([]int(nil), phases...)
	a.refreshPassiveReconGuard()
}

const (
	activityModeActive  = "active"
	activityModePassive = "passive"

	passiveReconMinLookups      = 2
	passiveReconMinSourceKinds  = 2
	passiveReconFallbackLookups = 3
)

// SetActivityPolicy configures passive/active access controls for recon and testing.
func (a *Agent) SetActivityPolicy(reconMode, scanIntensity string, targets []string) {
	a.reconMode = normalizeActivityMode(reconMode)
	a.scanIntensity = normalizeActivityMode(scanIntensity)
	if a.scanIntensity == activityModePassive {
		a.reconMode = activityModePassive
	}
	a.activityHosts = normalizeActivityHosts(targets)
	a.refreshPassiveReconGuard()
}

// canonicalizeAssistantTurn renders an assistant turn in the canonical tool-
// call format: the model's clean prose (tool XML already stripped) followed by
// one well-formed <function=NAME>…</function> block per parsed/recovered call.
// Persisting this instead of the model's raw (possibly malformed) output keeps
// the conversation self-consistent, so the model — which few-shot-mimics its
// own prior turns — stays on-format instead of drifting into dropped-tag
// malformations that eventually become unrecoverable and stall the scan.
func canonicalizeAssistantTurn(cleanText string, toolCalls []llm.ToolCall) string {
	var b strings.Builder
	// Strip any malformed tool-call residue (orphaned <parameter> blocks, a
	// bare `name>` line, stray </function>) so the rebuilt turn is clean prose
	// only — otherwise the very malformation we're canonicalizing away leaks
	// back in via the prose.
	if prose := llm.StripToolResidue(cleanText); prose != "" {
		b.WriteString(prose)
		b.WriteString("\n")
	}
	for _, tc := range toolCalls {
		b.WriteString(llm.FormatToolCall(tc.Name, tc.Args))
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

// authoritativeFinishSummary keeps the deterministic vulnerability store as
// the source of truth. Agent-written summaries are useful narrative, but the
// model may miscount duplicated IDs (the production pentest-ground run claimed
// 24 while the store held 23). Prefixing the exact persisted count makes that
// mismatch visible and prevents downstream UIs from treating model arithmetic
// as authoritative.
func authoritativeFinishSummary(summary string, findingCount int) string {
	prefix := fmt.Sprintf("Authoritative verified finding count: %d", findingCount)
	if strings.TrimSpace(summary) == "" {
		return prefix
	}
	return prefix + "\n\nAgent narrative:\n" + strings.TrimSpace(summary)
}

// stripThink removes <think>...</think> blocks from the response.
func stripThink(s string) string {
	return thinkRegex.ReplaceAllString(s, "")
}

// touchActivity updates the last activity timestamp (thread-safe).
func (a *Agent) touchActivity() {
	a.activityMu.Lock()
	a.lastActivity = time.Now()
	a.activityMu.Unlock()
}

// sinceActivity returns how long since last activity (thread-safe).
func (a *Agent) sinceActivity() time.Duration {
	a.activityMu.Lock()
	defer a.activityMu.Unlock()
	return time.Since(a.lastActivity)
}

// startWatchdog starts a background monitor that enforces:
// 1. Per-process timeout: kills individual commands running > 30 minutes
// 2. Scan-level timeout: force-stops entire scan after scanMaxDuration (0 = infinite)
// 3. Idle detection: kills agent stuck with no processes and no LLM response (0 = disabled)
func (a *Agent) startWatchdog() func() {
	stopChan := make(chan struct{})

	const (
		processMaxDuration = 30 * time.Minute // kill single process after this
		scanMaxDuration    = 0                // 0 = infinite (no scan-level timeout — needed for 300+ domain scans)
		idleKillThreshold  = 0 * time.Minute  // 0 = disabled (stuck-loop detection handles per-target stalls)
	)

	// Watchdog is a long-running background monitor; wrap with safe.Go
	// so a panic inside the tick loop (e.g. from terminal/scancontext
	// state mutation) is logged and counted instead of crashing the
	// process.
	safe.Go("agent.watchdog", a.scanCtx.ID, func() {
		// Check every 30 seconds
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		var lastStatusMsg string
		var lastStatusTime time.Time

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				if a.stopped.Load() {
					return
				}

				// ── Check 1: Scan-level timeout (0 = infinite/disabled) ──
				if scanMaxDuration > 0 {
					scanDuration := time.Since(a.scanStart)
					if scanDuration > time.Duration(scanMaxDuration)*time.Hour {
						a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Scan timeout: scan has been running for %s (max %s). Force stopping.", scanDuration.Round(time.Minute), time.Duration(scanMaxDuration)*time.Hour)})
						a.stopped.Store(true)
						if a.cancel != nil {
							a.cancel()
						}
						activeCmd, _ := a.scanCtx.Terminal.GetActiveCommand()
						safe.IncWatchdogKill()
						log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=scan_max_duration",
							activeCmd, scanDuration.Round(time.Second), a.scanCtx.ID)
						a.scanCtx.Terminal.KillAll()
						return
					}
				}

				// ── Reap dead processes that weren't properly untracked ──
				reaped := a.scanCtx.Terminal.ReapDead()
				if reaped > 0 {
					a.emit(Event{Type: "message", Content: fmt.Sprintf("🧹 Watchdog: reaped %d dead process(es) from tracker", reaped)})
				}

				activeProcs := a.scanCtx.Terminal.ActiveProcessCount()
				activeCmd, cmdDuration := a.scanCtx.Terminal.GetActiveCommand()

				// ── Check 2: Per-process timeout ──
				// If a single process has been running too long, kill it
				if activeProcs > 0 && cmdDuration > processMaxDuration {
					a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Watchdog: Process running for %s (limit: %s), killing it: %s", cmdDuration.Round(time.Minute), processMaxDuration, activeCmd)})
					safe.IncWatchdogKill()
					log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=process_max_duration",
						activeCmd, cmdDuration.Round(time.Second), a.scanCtx.ID)
					a.scanCtx.Terminal.KillAll()
					a.touchActivity() // reset idle timer since we just intervened
					continue
				}

				// ── If processes are actually running and within limits, update activity ──
				if activeProcs > 0 {
					a.touchActivity()

					// Emit status about what's running (every 5 minutes, deduplicated)
					if cmdDuration > 5*time.Minute && time.Since(lastStatusTime) > 5*time.Minute {
						statusMsg := fmt.Sprintf("⏳ Active: %d process(es)", activeProcs)
						if activeCmd != "" {
							cmdPreview := activeCmd
							if len(cmdPreview) > 100 {
								cmdPreview = cmdPreview[:100] + "..."
							}
							statusMsg += fmt.Sprintf(" | Running: %s (%s)", cmdPreview, cmdDuration.Round(time.Minute))
						}
						if statusMsg != lastStatusMsg {
							a.emit(Event{Type: "message", Content: statusMsg})
							lastStatusMsg = statusMsg
							lastStatusTime = time.Now()
						}
					}
					continue
				}

				// ── Check 3: Idle detection (idleKillThreshold = 0 means disabled) ──
				if idleKillThreshold > 0 {
					idleTime := a.sinceActivity()
					if idleTime > 5*time.Minute && idleTime <= 10*time.Minute {
						a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ Watchdog: No activity for %s. No active processes.", idleTime.Round(time.Second))})
					}

					if idleTime > 10*time.Minute && idleTime <= idleKillThreshold {
						a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ Watchdog: Idle for %s. Will force-stop at %s.", idleTime.Round(time.Second), idleKillThreshold)})
					}

					if idleTime > idleKillThreshold {
						a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Watchdog: Agent truly stuck for %s (no active processes, no LLM response). Force stopping.", idleTime.Round(time.Second))})
						a.stopped.Store(true)
						if a.cancel != nil {
							a.cancel()
						}
						idleCmd, _ := a.scanCtx.Terminal.GetActiveCommand()
						safe.IncWatchdogKill()
						log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=idle_timeout",
							idleCmd, idleTime.Round(time.Second), a.scanCtx.ID)
						a.scanCtx.Terminal.KillAll()
						return
					}
				}
			}
		}
	})

	return func() {
		close(stopChan)
	}
}

// executeToolAsync runs a tool in a goroutine with heartbeat monitoring.
// It keeps the watchdog alive by updating lastActivity while the tool runs,
// and streams partial output from long-running terminal commands.
//
// The function body is guarded by safe.Recover so any panic in the tool
// invocation, heartbeat plumbing, or watchdog hooks is converted into a
// typed error rather than crashing the agent loop. The tool invocation is
// additionally bounded by a context.WithTimeout derived from
// hardTimeoutFor(toolName) plus a 30-second grace window so even tools
// that ignore their own context still terminate within the ceiling.
func (a *Agent) executeToolAsync(toolName string, toolArgs map[string]string) (result tools.Result, returnErr error) {
	defer safe.Recover("agent.tool_exec", a.scanCtx.ID, &returnErr)

	// Set up streaming callback for terminal commands
	var lastPartialOutput string
	a.scanCtx.Terminal.SetStreamCallback(func(partial string) {
		a.touchActivity()
		// Only emit if output changed
		if partial != lastPartialOutput {
			lastPartialOutput = partial
			// Trim to last 500 chars for the UI
			preview := partial
			if len(preview) > 500 {
				preview = "..." + preview[len(preview)-500:]
			}
			a.emit(Event{
				Type:    "message",
				Content: fmt.Sprintf("⏳ [%s] partial output:\n%s", toolName, preview),
			})
		}
	})
	defer a.scanCtx.Terminal.ClearStreamCallback()

	// Execute in goroutine with panic recovery.
	//
	// NOTE (Task 6.3): this goroutine is intentionally NOT wrapped with
	// safe.Go. The inner `defer recover()` here has bespoke behavior the
	// generic safe.Recover cannot replicate: on panic it must construct
	// a tools.Result{Error: "tool panicked: …"} and push it on resultCh
	// so the agent loop can surface a tool result (with the typed err)
	// to the LLM instead of bubbling the panic up. The enclosing
	// executeToolAsync function body is already wrapped by
	// `defer safe.Recover("agent.tool_exec", …)` (Task 6.2), which
	// catches any panic that escapes this defer (e.g. a panic in the
	// recover branch itself). Wrapping with safe.Go in addition would
	// duplicate counter increments and log lines without adding safety.
	resultCh := make(chan toolExecResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ERROR] [PANIC] Tool '%s' panicked: %v\n%s", toolName, r, debug.Stack())
				resultCh <- toolExecResult{
					Result: tools.Result{Error: fmt.Sprintf("tool panicked: %v", r)},
					Err:    fmt.Errorf("tool '%s' panicked: %v", toolName, r),
				}
			}
		}()
		res, err := a.registry.Execute(toolName, toolArgs)
		resultCh <- toolExecResult{Result: res, Err: err}
	}()

	// Heartbeat loop while waiting for tool to complete
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// Hard timeout safety net (P2.1): bound the tool invocation by the
	// per-tool ceiling plus a 30-second grace so even tools that ignore
	// their own ctx still terminate. We derive from a.ctx so parent
	// cancellation propagates as well.
	hardTimeoutDuration := a.hardTimeoutFor(toolName)
	tcCtx, tcCancel := context.WithTimeout(a.ctx, hardTimeoutDuration+30*time.Second)
	defer tcCancel()

	for {
		select {
		case res := <-resultCh:
			// Tool completed — update activity and return immediately
			a.touchActivity()
			return res.Result, res.Err

		case <-heartbeat.C:
			// Keep watchdog alive while tool is running
			a.touchActivity()

		case <-tcCtx.Done():
			// Distinguish hard-timeout from parent cancellation. When the
			// parent (a.ctx) is canceled, tcCtx.Err() is context.Canceled;
			// when our own deadline elapses it is context.DeadlineExceeded.
			if tcCtx.Err() == context.DeadlineExceeded {
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Tool '%s' timed out after %s. Force-returning to prevent infinite hang.", toolName, hardTimeoutDuration)})
				switch toolName {
				case "terminal_execute", "python_action":
					a.scanCtx.Terminal.KillAll()
				case "browser_action":
					browser.CleanupContext(a.scanCtx.ID)
				}
				return tools.Result{Error: fmt.Sprintf("[TIMEOUT exceeded %s]", hardTimeoutDuration)}, nil
			}
			// Parent canceled (agent stopped).
			return tools.Result{Error: "Agent stopped during tool execution"}, fmt.Errorf("agent canceled")
		}
	}
}

// Run starts the agent loop with the given targets and instructions.
func (a *Agent) Run(targets []string, instruction string) {
	// Stop-before-Run is a valid lifecycle outcome when exact cancellation wins
	// the session admission race. Do not clone source, initialize browsers, or
	// touch the target after that stop has become authoritative.
	if a.stopped.Load() {
		return
	}
	a.targets = targets // remember the scan targets so probe_hypothesis can resolve a base URL for a bare path
	if a.scanCtx != nil && a.delegatedAgentID == "" {
		a.scanCtx.SetTargets(targets)
	}
	a.ctfMission = isExplicitCTFMission(instruction)
	a.scanStart = time.Now()
	if a.scanBudget != nil {
		a.scanBudget.start()
	}
	// Wire per-scan auth + whitebox source here (in the scan goroutine) so a
	// slow git clone never blocks scan creation or the HTTP handler.
	a.prepareScanEnvironment()
	ratePolicy := EffectiveRequestRatePolicy(a.cfg, instruction)
	if a.scanCtx != nil {
		a.scanCtx.SetRequestRatePolicy(ratePolicy)
	}

	// Start watchdog
	stopWatchdog := a.startWatchdog()
	defer stopWatchdog()

	systemPrompt := a.buildSystemPrompt(targets, instruction, ratePolicy)
	a.messages = []llm.Message{
		{Role: "system", Content: systemPrompt},
	}

	userMsg := a.buildInitialUserMessage(targets, instruction)
	a.messages = append(a.messages, llm.Message{Role: "user", Content: userMsg})

	// Inject the seeded attack surface (from OpenAPI/HAR/Postman context) as a
	// high-priority follow-up so the agent tests the target's REAL endpoints
	// instead of relying solely on crawl-based discovery.
	if a.scanContextBriefing != "" {
		a.messages = append(a.messages, llm.Message{Role: "user", Content: a.scanContextBriefing})
	}
	if a.resumeBriefing != "" {
		a.messages = append(a.messages, llm.Message{Role: "user", Content: a.resumeBriefing})
	}

	// Initialize scan state for hooks (replaces 17+ local tracking variables)
	a.state = NewScanState()
	a.state.Iteration = a.initialIter
	if a.cfg != nil {
		// Thread the configurable no-tool abort threshold (0 = never give up).
		a.state.NoToolAbortLimit = a.cfg.NoToolAbortAt
		a.state.NoToolAbortConfigured = true
		a.state.MaxFinishRejections = a.cfg.MaxFinishRejections
		a.state.MinIterations = a.cfg.MinIterations
	}
	a.state.ScanContextID = a.scanCtx.ID
	a.state.DelegatedAgent = a.delegatedAgentID != ""
	a.state.DelegatedAgentID = a.delegatedAgentID
	a.state.BenchmarkIsolated = a.benchmarkIsolated
	a.state.ProfessionalAssessment = !a.ctfMission
	a.state.AuthContextKnown = true
	a.state.AuthContextAvailable = len(httpclient.ParseAuthHeaders(a.targetAuth)) > 0
	if a.scanCtx != nil && len(httpclient.SessionAuthForContext(a.scanCtx.ID)) > 0 {
		a.state.AuthContextAvailable = true
	}
	a.state.DiscoveryMode = a.discoveryMode
	a.state.AllowedPhases = append([]int(nil), a.allowedPhases...)
	// Derive the explicit depth mode ONCE from the phase selection. Empty
	// AllowedPhases = the full methodology is allowed = deep requirements
	// apply; it must never be misread as "no phases selected = shallow".
	if len(a.allowedPhases) == 0 || len(a.allowedPhases) >= 20 {
		a.state.ScanDepth = "deep"
	} else {
		a.state.ScanDepth = "standard"
	}
	a.state.ReconOnlyMode = isReconReportOnlyPhaseSelection(a.allowedPhases)
	if a.state.ReconOnlyMode {
		a.state.DiscoveryMode = true
	}
	a.resetPassiveReconGuardForRun()

	// Helper to get current token count
	tokenCount := func() int {
		return a.syncBudgetTokens()
	}

	// Running total of tool calls, for the optional resource budget.
	toolCallsTotal := 0

	iter := a.initialIter
	for ; (a.scanBudget != nil || a.maxIter == 0 || iter < a.maxIter) && !a.stopped.Load() && (a.ctx == nil || a.ctx.Err() == nil); iter++ {
		// Reset activity watchdog on each iteration — IMMEDIATELY, no delay
		a.touchActivity()
		a.state.Iteration = iter

		// ── Resource budget / early-stopping (MAPTA §2.7/§3.3) ──
		// Halt cleanly if a configured cap is hit. Findings already reported
		// are persisted, so this is a graceful teardown, not a data loss.
		if over, why := a.overBudget(toolCallsTotal); over {
			a.emit(Event{Type: "message", Content: fmt.Sprintf("⏱️ Resource budget reached (%s) — stopping and finalizing. Findings reported so far are preserved.", why), TotalTokens: tokenCount()})
			a.emit(Event{Type: "finished", Content: fmt.Sprintf("Scan stopped: resource budget reached (%s).", why), TotalTokens: tokenCount(), Aborted: true, AbortReason: "resource_budget"})
			return
		}
		if a.scanBudget != nil && !a.scanBudget.reserveIteration(a.maxIter) {
			reason := fmt.Sprintf("%d shared agent iterations ≥ scan cap %d", a.scanBudget.iterationCount(), a.maxIter)
			a.emit(Event{Type: "message", Content: "⏱️ Resource budget reached (" + reason + ") — stopping and finalizing. Findings reported so far are preserved.", TotalTokens: tokenCount()})
			a.emit(Event{Type: "finished", Content: "Scan stopped: resource budget reached (" + reason + ").", TotalTokens: tokenCount(), Aborted: true, AbortReason: "resource_budget"})
			return
		}
		if guardMsg := a.maybeCompletePassiveReconGuardAtIterationStart(iter); guardMsg != "" {
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: guardMsg})
			a.msgMu.Unlock()
			a.emit(Event{Type: "message", Content: guardMsg, TotalTokens: tokenCount()})
		}

		if a.maxIter > 0 {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d/%d", iter+1, a.maxIter), TotalTokens: tokenCount()})
		} else {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d", iter+1), TotalTokens: tokenCount()})
		}

		// ── Hook: OnIterationStart ──
		iterResult := a.hooks.Fire(OnIterationStart, a.state, nil)
		if autoDelegation := a.maybeAutoDelegate(targets); autoDelegation != "" {
			// If the hook also produced its model-directed decomposition prompt on
			// this pass, replace it: the engine has already done that work. Keep a
			// planner/coverage nudge alongside the launch status when applicable.
			if strings.Contains(iterResult.Nudge, "MULTI-AGENT DECOMPOSITION") || iterResult.Nudge == "" {
				iterResult.Nudge = autoDelegation
			} else {
				iterResult.Nudge = autoDelegation + "\n\n" + iterResult.Nudge
			}
		}
		if iterResult.Nudge != "" {
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: iterResult.Nudge})
			a.msgMu.Unlock()
		}
		if iterResult.EmitMessage != "" {
			a.emit(Event{Type: "message", Content: iterResult.EmitMessage, TotalTokens: tokenCount()})
		}

		// Proactively prune before the LLM call when the accumulated
		// message buffer has grown past pruneThresholdBytes. This is the
		// pre-LLM pruning gate (Requirement 2.3 / Property P2.3) — it
		// supplements the existing post-iteration prune at the end of
		// the loop and the context-overflow recovery branch below, so
		// the serialized buffer is bounded before every outbound call,
		// not only after a 413 from the provider.
		// Bounded working context (information-complete): replace tool-result
		// messages older than the active window with retrieval stubs BEFORE
		// the snapshot is taken, so aged raw output is not resent on every
		// iteration. Every stubbed byte stays retrievable via read_tool_output.
		if a.boundedContextEnabled() {
			a.ageOutToolOutputs()
		}
		if a.shouldPruneBeforeLLM() {
			a.pruneMessages()
		}

		// Snapshot the message buffer under msgMu before handing it to the
		// LLM client. Chat() ranges over the slice to serialize the request
		// while SendMessage() (called from the web chat handler on another
		// goroutine) may append concurrently. Reading a.messages directly
		// here is a data race: a concurrent append can reallocate the backing
		// array mid-serialization. Copying under the lock gives Chat a stable
		// view; messages that arrive during the call are picked up next iter.
		a.msgMu.Lock()
		msgsSnapshot := make([]llm.Message, len(a.messages))
		copy(msgsSnapshot, a.messages)
		a.msgMu.Unlock()

		// Adaptive Temperature Control:
		// Default to TempScanner (0.0) for 100% deterministic, consistent scan behavior.
		// Dynamically boost to 0.2 when stuck or retrying failed calls to allow creative payload variation.
		scannerTemp := 0.0
		if a.state.ConsecutiveSameCall >= 2 || a.state.ConsecutiveSameResult >= 2 || a.state.ConsecutiveErrors > 0 {
			scannerTemp = 0.2
		}
		a.client.SetTemperature(&scannerTemp)

		category := scanctx.CategoryNormalReasoning
		if a.state != nil {
			if a.state.PendingFailedReportCalls > 0 || a.state.MalformedToolOutputCount > 0 {
				category = scanctx.CategoryMalformedToolRecovery
			} else if a.state.NoToolCount > 0 {
				category = scanctx.CategoryNoToolRecovery
			} else if a.state.FinishAttempts > 0 && iterResult.Nudge != "" {
				category = scanctx.CategoryFinishRejectionRecovery
			}
		}

		response, usage, err := a.client.ChatWithUsage(msgsSnapshot)
		a.recordTokenAttribution(usage, msgsSnapshot, iter, category, 0)
		// Update activity after LLM response
		a.touchActivity()
		// A benchmark deadline, operator stop, or parent cancellation must win
		// over provider retry logic. Otherwise an already-canceled request can
		// enter the 25-attempt exponential backoff and keep a stopped scan alive
		// for many minutes after its deadline.
		if a.stopped.Load() || (a.ctx != nil && a.ctx.Err() != nil) {
			a.emit(Event{Type: "finished", Content: "Scan stopped", TotalTokens: tokenCount()})
			return
		}

		if err != nil {
			a.state.ConsecutiveErrors++
			errStr := err.Error()
			classified := llm.ClassifyErrorString(errStr)

			if classified.Class == llm.ErrorClassContextWindow {
				// Context window overflow: force-prune messages so the next
				// attempt has a smaller payload. Don't count this as a
				// consecutive error — it's recoverable via pruning.
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Context window overflow — force-pruning message history (%d messages)", len(a.messages)), TotalTokens: tokenCount()})
				a.forcePruneMessages()
				a.state.ConsecutiveErrors-- // don't penalize for recoverable overflow
				if a.state.ConsecutiveErrors < 0 {
					a.state.ConsecutiveErrors = 0
				}
				continue
			}

			// Rate limit / Overloaded / Quota exhausted: back off in progressive increments
			// and keep retrying until the upstream provider recovers or the window refreshes.
			//
			// CRITICAL:
			// 1. DO NOT terminate the scan on rate limits or quota resets. Keep the agent alive
			//    in memory so that when the provider window refreshes (e.g. rolling 5h provider quota,
			//    RPM/TPM resets), the scan resumes seamlessly without interruption.
			// 2. DO NOT emit provider rate-limit or quota error messages to the frontend/user.
			//    All upstream provider wait messages are logged strictly to backend server logs
			//    (log.Printf) so the SaaS user never sees scary billing or provider notices.
			if classified.Class == llm.ErrorClassRateLimit ||
				classified.Class == llm.ErrorClassOverloaded ||
				classified.Class == llm.ErrorClassQuotaExhausted {
				a.state.ConsecutiveErrors-- // don't penalize normal consecutive error count
				if a.state.ConsecutiveErrors < 0 {
					a.state.ConsecutiveErrors = 0
				}
				a.state.ConsecutiveRateLimits++

				var abortReason, reasonLabel string
				switch classified.Class {
				case llm.ErrorClassOverloaded:
					abortReason = "provider_overloaded"
					reasonLabel = "overload"
				case llm.ErrorClassQuotaExhausted:
					abortReason = "provider_quota_exhausted"
					reasonLabel = "quota wait"
				default:
					abortReason = "provider_rate_limited"
					reasonLabel = "rate-limit"
				}

				// Progressive retry backoff: 15s -> 30s -> 60s max per attempt.
				backoff := a.rateLimitBackoff(a.state.ConsecutiveRateLimits)
				if classified.Class == llm.ErrorClassQuotaExhausted && a.rateLimitBackoffFn == nil && backoff < 30*time.Second {
					backoff = 30 * time.Second
				}

				maxWait := a.maxRateLimitWait()
				if maxWait > 0 && a.state.CumulativeRateLimitWait >= maxWait {
					log.Printf("[agent:%s] LLM %s wait budget exhausted after %s", a.ID, reasonLabel, a.state.CumulativeRateLimitWait)
					a.emit(Event{Type: "paused", Content: "Scan paused: upstream provider temporarily unavailable; existing findings preserved.", TotalTokens: tokenCount(), Aborted: true, AbortReason: abortReason})
					return
				}

				// Cap backoff by remaining cumulative budget
				if maxWait > 0 {
					remaining := maxWait - a.state.CumulativeRateLimitWait
					if remaining <= 0 {
						log.Printf("[agent:%s] LLM %s wait budget exhausted", a.ID, reasonLabel)
						a.emit(Event{Type: "paused", Content: "Scan paused: upstream provider temporarily unavailable; existing findings preserved.", TotalTokens: tokenCount(), Aborted: true, AbortReason: abortReason})
						return
					}
					if remaining < backoff {
						backoff = remaining
					}
				}

				// Log strictly to backend server logs for operator visibility (silent on user frontend)
				log.Printf("[agent:%s] Upstream LLM %s encountered (%s). Waiting %s before retry (attempt %d, cumulative wait: %s)...",
					a.ID, reasonLabel, classified.Class, backoff, a.state.ConsecutiveRateLimits, a.state.CumulativeRateLimitWait.Round(time.Second))

				// Interruptible sleep: bail out immediately if the scan is stopped or canceled by operator.
				if a.ctx != nil {
					select {
					case <-a.ctx.Done():
						a.emit(Event{Type: "finished", Content: "Scan stopped", TotalTokens: tokenCount()})
						return
					case <-time.After(backoff):
					}
				} else {
					time.Sleep(backoff)
				}

				if a.stopped.Load() {
					return
				}

				a.state.CumulativeRateLimitWait += backoff
				a.touchActivity() // keep watchdog alive during rate-limit/quota backoff

				if maxWait > 0 && a.state.CumulativeRateLimitWait >= maxWait {
					log.Printf("[agent:%s] LLM %s wait budget exhausted after %s", a.ID, reasonLabel, a.state.CumulativeRateLimitWait)
					a.emit(Event{Type: "paused", Content: "Scan paused: upstream provider temporarily unavailable; existing findings preserved.", TotalTokens: tokenCount(), Aborted: true, AbortReason: abortReason})
					return
				}
				continue
			}

			a.emit(Event{Type: "error", Content: fmt.Sprintf("LLM error (attempt %d/25): %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount()})
			if a.state.ConsecutiveErrors >= 25 {
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Agent stopped: LLM failed %d consecutive times. Last error: %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount()})
				a.emit(Event{Type: "finished", Content: fmt.Sprintf("Agent stopped: LLM failed %d consecutive times. Last error: %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount(), Aborted: true, AbortReason: "llm_repeated_errors"})
				return
			}
			// Exponential backoff: 10s, 20s, 30s... capped at 120s
			// Long-running wildcard scans need more tolerance for transient API issues
			backoff := time.Duration(a.state.ConsecutiveErrors*10) * time.Second
			if backoff > 120*time.Second {
				backoff = 120 * time.Second
			}
			if a.ctx != nil {
				select {
				case <-a.ctx.Done():
					a.emit(Event{Type: "finished", Content: "Scan stopped", TotalTokens: tokenCount()})
					return
				case <-time.After(backoff):
				}
			} else {
				time.Sleep(backoff)
			}
			if a.stopped.Load() {
				return
			}
			continue
		}
		// ConsecutiveErrors reset is handled by OnHealthyResponse hook below

		// ── Hook: OnEmptyResponse ──
		if strings.TrimSpace(response) == "" {
			emptyResult := a.hooks.Fire(OnEmptyResponse, a.state, nil)
			a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ LLM returned empty response (%d/12)", a.state.EmptyResponseCount), TotalTokens: tokenCount()})
			if emptyResult.ForceSkip {
				a.emit(Event{Type: "error", Content: emptyResult.EmitMessage, TotalTokens: tokenCount()})
				a.emit(Event{Type: "finished", Content: "Agent stopped: LLM returned too many empty responses", TotalTokens: tokenCount(), Aborted: true, AbortReason: "llm_empty_responses"})
				return
			}
			if emptyResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: emptyResult.Nudge})
				a.msgMu.Unlock()
			}
			continue
		}
		// EmptyResponseCount reset is handled by OnHealthyResponse hook below

		// Strip <think>...</think> blocks for parsing
		responseClean := stripThink(response)

		// Extract display prose. It is emitted only after malformed tool-output
		// detection below so provider control-token leaks never pollute the UI or
		// get persisted back into the model's conversation.
		cleanText := llm.CleanContent(responseClean)
		cleanText = strings.TrimSpace(cleanText)

		toolCalls := llm.ParseToolCalls(responseClean)
		// ── Drop empty-Args calls for tools that require parameters ──
		// When a model drifts and splits a multi-parameter call's fields
		// across separate <function=NAME> blocks, the parser produces
		// well-formed calls with EMPTY bodies (e.g. <function=update_plan>
		// </function> → ToolCall{Name:"update_plan", Args:{}}). Such a call
		// can never satisfy the tool's required params, so sending it to the
		// registry just wastes an iteration on a guaranteed "missing required
		// parameter" error (observed ~10× near the end of the z-text.com
		// scan). Drop these fragments here so they fall through to the
		// orphan-recovery path (which can re-associate stray params) or the
		// no-tool compaction path. Tools whose params are ALL optional (e.g.
		// code_search) legitimately accept an empty body and are kept.
		if len(toolCalls) > 0 {
			kept := toolCalls[:0]
			for _, tc := range toolCalls {
				if len(tc.Args) == 0 && a.registry.RequiresParams(tc.Name) {
					continue
				}
				kept = append(kept, tc)
			}
			toolCalls = kept
		}
		// ── In-batch duplicate dedup ──
		// A model response can carry many tool calls, and executing a
		// byte-identical call twice within ONE turn cannot produce a different
		// result: the model has not seen the first result yet. Worse, the
		// repeat-call tracker counted in-batch duplicates toward the loop-limit
		// kill, force-finishing healthy scans mid-batch (production: a final
		// bookkeeping batch carried several identical empty update_plan calls
		// and a 60-minute scan with 11 unfinished tasks died without the model
		// ever getting a turn to adapt). Skip duplicates quietly; CROSS-turn
		// repeats still count toward the stuck-loop guard exactly as before.
		if deduped := dedupeBatchCalls(toolCalls); len(deduped) != len(toolCalls) {
			a.emit(Event{Type: "recovery", Content: fmt.Sprintf("Skipped %d duplicate tool call(s) within one response — an identical repeat in the same turn cannot produce a different result.", len(toolCalls)-len(deduped)), TotalTokens: tokenCount()})
			toolCalls = deduped
		}
		// ── Schema-guided recovery of dropped-open-tag tool calls ──
		// Some models intermittently drop the <function=NAME> open tag and
		// emit only <parameter=X>…</parameter> blocks + a trailing
		// </function>. ParseToolCalls can't recover the tool name from that,
		// so every such response counts as "no tool call" and the scan
		// force-stops at 15 (observed on codeant.ai). Recover by matching
		// the orphaned parameter set against the registered tool schemas:
		// a tool whose required params are all present is the intended call.
		// This runs BEFORE the no-tool hook so recovered calls are healthy,
		// not counted toward the reasoning-loop threshold.
		if len(toolCalls) == 0 {
			for _, oc := range llm.ParseOrphanedCalls(responseClean) {
				// Prefer the tool name the model actually emitted (it dropped only
				// the "<function=" prefix, e.g. `terminal_execute>`), validated
				// against the registry. This rescues the common case that
				// MatchByParams cannot resolve: a call carrying only {command},
				// which ties across terminal_execute / browser_action / pageagent
				// and is rejected as ambiguous — the exact regression that turned
				// dropped-tag shell calls into "no tool call" → reasoning loops.
				name, ok := "", false
				if oc.NameHint != "" {
					if _, exists := a.registry.Get(oc.NameHint); exists {
						name, ok = oc.NameHint, true
					}
				}
				if !ok {
					name, ok = a.registry.MatchByParams(oc.ParamNames)
				}
				if ok {
					a.emit(Event{Type: "message", Content: fmt.Sprintf("🔧 Recovered a tool call whose <function> open tag was dropped — resolved to '%s' (params %v).", name, oc.ParamNames), TotalTokens: tokenCount()})
					toolCalls = append(toolCalls, llm.ToolCall{Name: name, Args: oc.Args})
				}
			}
		}

		// Distinguish ordinary prose-only reasoning from an attempted tool call
		// corrupted by the provider/model protocol. The latter must be discarded
		// rather than appended to history: feeding a provider's leaked control-token
		// delimiters or a bare ` + "`" + ` marker back to the model caused it to
		// mimic the corruption for 30 turns and falsely finish a scan.
		malformedToolReason := ""
		if len(toolCalls) == 0 {
			malformedToolReason = llm.MalformedToolOutputReason(responseClean)
		}
		if malformedToolReason != "" {
			// Type "recovery", not "error": the discard-and-retry below is a
			// handled self-healing action and the scan continues normally.
			// Error-typed events render as red failures in hosted dashboards,
			// alarming users over routine protocol recovery.
			a.emit(Event{
				Type:        "recovery",
				Content:     fmt.Sprintf("Discarded malformed LLM tool output (%s); requesting a clean executable call.", malformedToolReason),
				TotalTokens: tokenCount(),
			})
		} else if cleanText != "" {
			a.emit(Event{Type: "message", Content: cleanText, TotalTokens: tokenCount()})
		}
		// Enforce the tool-call budget WITHIN the batch. overBudget is only
		// checked at iteration start, so a single response emitting many calls
		// could otherwise blow past XALGORIX_MAX_TOOL_CALLS. Truncate the batch
		// to the remaining allowance so the cap is honored precisely.
		requestedCalls := len(toolCalls)
		allowedCalls := requestedCalls
		maxToolCalls := 0
		if a.cfg != nil {
			maxToolCalls = a.cfg.MaxToolCalls
		}
		if a.scanBudget != nil {
			allowedCalls = a.scanBudget.reserveToolCalls(requestedCalls, maxToolCalls)
		} else if maxToolCalls > 0 {
			remaining := maxToolCalls - toolCallsTotal
			if remaining < 0 {
				remaining = 0
			}
			if allowedCalls > remaining {
				allowedCalls = remaining
			}
		}
		if allowedCalls < requestedCalls {
			a.emit(Event{Type: "message", Content: fmt.Sprintf("⏱️ Shared tool-call budget: executing %d of %d requested calls (scan cap %d reached).", allowedCalls, requestedCalls, maxToolCalls), TotalTokens: tokenCount()})
			toolCalls = toolCalls[:allowedCalls]
		}
		toolCallsTotal += allowedCalls

		// ── Persist the assistant turn ──
		// When tool calls were parsed OR recovered, store a CANONICAL rendering
		// (clean prose + well-formed <function=…> blocks) instead of the raw
		// response. The model few-shot-mimics its own prior turns, so persisting
		// malformed tool-call XML (e.g. a dropped "<function=" tag) teaches it to
		// keep malforming — the format drifts and escalates until it emits an
		// unrecoverable shape and the scan reasoning-loops. Rewriting to the
		// canonical form keeps the conversation self-consistent so the model
		// stays on-format. When NO tool call was found, store the raw response so
		// the no-tool hook's format nudge reflects the real (malformed) output.
		if malformedToolReason == "" {
			assistantContent := response
			if len(toolCalls) > 0 {
				assistantContent = canonicalizeAssistantTurn(cleanText, toolCalls)
			}
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "assistant", Content: assistantContent})
			a.msgMu.Unlock()
		}

		// ── Hook: OnNoToolResponse ──
		if len(toolCalls) == 0 {
			noToolResult := a.hooks.Fire(OnNoToolResponse, a.state, map[string]string{
				"response":         cleanText,
				"malformed_reason": malformedToolReason,
			})
			if noToolResult.ForceSkip {
				reason, detail := classifyNoToolAbort(a.state)
				if noToolResult.EmitMessage != "" {
					a.emit(Event{Type: "error", Content: noToolResult.EmitMessage, TotalTokens: tokenCount()})
				}
				a.emit(Event{Type: "finished", Content: detail, TotalTokens: tokenCount(), Aborted: true, AbortReason: reason})
				return
			}
			// Reasoning-loop recovery is NUDGE-ONLY: we inject a focused
			// "resume and call a tool" prompt and let the model recover on
			// its own. We deliberately do NOT compact the context here —
			// compaction is a context-size concern, unrelated to reasoning
			// loops, and collapsing the model's own working notes mid-thought
			// tends to make a stall worse. Proactive size-based compaction
			// still happens independently in the main loop (shouldPruneBeforeLLM).
			// NoToolCount is not reset here; the count climbing is what drives
			// the escalating nudges (and, in bounded mode, the eventual abort).
			if noToolResult.PruneContext {
				// Hard context reset: truncate the conversation to the system
				// prompt only. The model's own context (oversized, poisoned by
				// provider control-token leaks, or few-shot-mimicking its own
				// malformed turns) is the CAUSE of the corruption — nudging
				// into the same context just produces more of the same.
				a.msgMu.Lock()
				if len(a.messages) > 0 && a.messages[0].Role == "system" {
					a.messages = append(a.messages[:0:1], llm.Message{Role: "user", Content: noToolResult.Nudge})
				} else {
					a.messages = []llm.Message{{Role: "user", Content: noToolResult.Nudge}}
				}
				a.msgMu.Unlock()
				a.emit(Event{Type: "recovery", Content: "Context hard-reset: truncated conversation to system prompt + protocol recovery instruction.", TotalTokens: tokenCount()})
				// The count resets so the model gets a full recovery window in the
				// clean context — a relapse starts the ladder from step 1, not
				// from the abort edge.
				a.state.MalformedToolOutputCount = 0
			} else if noToolResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: noToolResult.Nudge})
				a.msgMu.Unlock()
			}
			// Avoid a rapid paid retry storm for provider-protocol corruption. The
			// delay is deliberately small and bounded; ordinary prose-only turns
			// keep their existing immediate retry behavior.
			if malformedToolReason != "" {
				seconds := a.state.MalformedToolOutputCount
				if seconds > 3 {
					seconds = 3
				}
				time.Sleep(time.Duration(seconds) * time.Second)
			}
			continue
		}
		// Non-empty response with tool calls = healthy. Reset all error counters.
		a.hooks.Fire(OnHealthyResponse, a.state, nil)

		for _, tc := range toolCalls {
			if a.stopped.Load() {
				break
			}
			if tc.Name == "terminal_execute" {
				if command, ok := tc.Args["command"]; ok {
					contextID := ""
					if a.scanCtx != nil {
						contextID = a.scanCtx.ID
					}
					normalized, note := terminal.NormalizeCommandForRequestRatePolicy(contextID, command)
					normalized = terminal.InjectScanHeadersIntoCommand(normalized)
					normalized = terminal.CapDirbusterRuntime(normalized)
					if normalized != command {
						updatedArgs := make(map[string]string, len(tc.Args))
						for k, v := range tc.Args {
							updatedArgs[k] = v
						}
						updatedArgs["command"] = normalized
						tc.Args = updatedArgs
						if note != "" {
							a.emit(Event{Type: "message", Content: note, TotalTokens: tokenCount()})
						}
					}
				}
			}

			// ── Hook: OnToolCall (work tracking + stuck tracking) ──
			toolArgs := map[string]string{
				"tool_name": tc.Name,
			}
			for k, v := range tc.Args {
				toolArgs[k] = v
			}

			if blocked, reason := a.shouldBlockForActivityPolicy(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ ACTIVITY POLICY BLOCKED TOOL — " + reason + noteBlockedToolCall(a.state, tc.Name, tc.Args)
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			if blocked, reason := a.shouldBlockForPhaseRestriction(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ PHASE RESTRICTION BLOCKED TOOL — " + reason + noteBlockedToolCall(a.state, tc.Name, tc.Args)
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			if blocked, reason := a.shouldBlockForMissingAuthPrerequisites(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ AUTH PREREQUISITE GUARD BLOCKED TOOL — " + reason + noteBlockedToolCall(a.state, tc.Name, tc.Args)
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			// ── In-scope guard ──
			// Runs UNCONDITIONALLY (active and passive). Probes and
			// finding reports for hosts not derived from the configured
			// scan target are rejected — prevents the agent from
			// pivoting to third-party hosts discovered via DNS, port
			// scans, related infrastructure, etc.
			if blocked, reason := a.shouldBlockForOutOfScope(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ OUT-OF-SCOPE TARGET BLOCKED — " + reason + noteBlockedToolCall(a.state, tc.Name, tc.Args)
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			// This call passed every block guard — a real, allowed action.
			// Clear the consecutive-blocked-call counter so only a SUSTAINED
			// block loop (no allowed call in between) escalates.
			a.state.ConsecutiveBlockedCalls = 0

			toolCallHook := a.hooks.Fire(OnToolCall, a.state, toolArgs)
			if toolCallHook.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: toolCallHook.Nudge})
				a.msgMu.Unlock()
			}
			if toolCallHook.EmitMessage != "" {
				a.emit(Event{Type: "message", Content: toolCallHook.EmitMessage, TotalTokens: tokenCount()})
				if strings.Contains(toolCallHook.EmitMessage, "Force finishing") || strings.Contains(toolCallHook.EmitMessage, "Loop limit reached") {
					a.emit(Event{Type: "finished", Content: toolCallHook.EmitMessage, TotalTokens: tokenCount(), Aborted: true, AbortReason: "report_retry_limit"})
					return
				}
			}
			if toolCallHook.ForceSkip {
				continue
			}

			// ── Hook: OnStuckCheck (nudge/force-skip based on stuck counters) ──
			stuckResult := a.hooks.Fire(OnStuckCheck, a.state, toolArgs)
			if stuckResult.EmitMessage != "" {
				if strings.Contains(stuckResult.EmitMessage, "Force finishing") || strings.Contains(stuckResult.EmitMessage, "Loop limit reached") {
					content := stuckResult.EmitMessage
					if content == "" || strings.Contains(content, "automated safety boundaries") {
						content = "Scan completed: Loop limit reached — testing safely finalized with existing findings."
					}
					a.emit(Event{Type: "finished", Content: content, TotalTokens: tokenCount(), Aborted: true, AbortReason: "stuck_loop_limit"})
					return
				}
			}
			if stuckResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: stuckResult.Nudge})
				a.msgMu.Unlock()
			}
			if stuckResult.CleanupBrowser {
				browser.CleanupContext(a.scanCtx.ID)
			}
			if stuckResult.ForceSkip {
				continue // skip executing this tool call
			}

			// Track coverage only after every scope, activity, policy, and loop
			// guard has accepted the call. Recording at OnToolCall time would let
			// a force-skipped request count as endpoint/class evidence even though
			// it never reached the target.
			a.hooks.Fire(OnToolExecute, a.state, toolArgs)

			a.emit(Event{
				Type:     "tool_call",
				ToolName: tc.Name,
				ToolArgs: tc.Args,
			})

			// Execute tool ASYNC with heartbeat monitoring
			result, err := a.executeToolAsync(tc.Name, tc.Args)
			if err != nil {
				result = tools.Result{Error: err.Error()}
			}

			a.emit(Event{
				Type:        "tool_result",
				ToolName:    tc.Name,
				ToolResult:  result,
				TotalTokens: tokenCount(),
			})

			// ── Hook: OnToolResult (WAF detection, tech detection) ──
			resultArgs := make(map[string]string, len(toolArgs)+2)
			for k, v := range toolArgs {
				resultArgs[k] = v
			}
			resultArgs["output"] = result.Output
			resultArgs["error"] = result.Error
			// Propagate tool-emitted identity metadata (e.g. read_skill tags
			// its result with the canonical skill name and duplicate flag) so
			// result hooks can count successful canonical loads instead of
			// guessing from the raw request args.
			if result.Metadata != nil {
				if v, ok := result.Metadata["skill_name"].(string); ok && v != "" {
					resultArgs["skill_name"] = v
				}
				if v, ok := result.Metadata["skill_duplicate"].(bool); ok && v {
					resultArgs["skill_duplicate"] = "true"
				}
			}
			toolResultHook := a.hooks.Fire(OnToolResult, a.state, resultArgs)
			if toolResultHook.EmitMessage != "" {
				a.emit(Event{Type: "message", Content: toolResultHook.EmitMessage, TotalTokens: tokenCount()})
			}
			if toolResultHook.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: toolResultHook.Nudge})
				a.msgMu.Unlock()
			}

			// ── Hook: OnFinishAttempt ──
			if tc.Name == "finish" || (result.Metadata != nil && result.Metadata["finished"] == true) {
				finishResult := a.hooks.Fire(OnFinishAttempt, a.state, nil)
				if finishResult.Block {
					rejectMsg := fmt.Sprintf("⚠️ FINISH REJECTED — %s\n\nDO NOT call finish again until you have done more testing.\nContinue with the NEXT PHASE of testing NOW.", finishResult.BlockReason)
					a.emit(Event{Type: "tool_result", ToolName: "finish", ToolResult: tools.Result{Output: rejectMsg}, TotalTokens: tokenCount()})
					a.msgMu.Lock()
					a.messages = append(a.messages, llm.Message{Role: "user", Content: rejectMsg})
					a.msgMu.Unlock()
					// Finish was rejected — switch to validator temperature (0.0)
					// for deterministic re-verification of coverage gaps
					a.client.SetTemperature(TempValidator)
					continue
				}
				content := result.Output
				if !a.state.DelegatedAgent {
					count := 0
					if a.scanCtx != nil {
						count = len(reporting.GetVulnerabilitiesForContext(a.scanCtx.ID))
					}
					content = authoritativeFinishSummary(content, count)
					// ── Honest completion assessment ──
					// The gates release a finish after the bounded rejection
					// ceiling; that must never read as "full assessment
					// completed". Compute the explicit terminal state, make it
					// visible in the final summary, and emit one compact
					// telemetry block for post-scan debugging.
					status, reasons := scanCompletionAssessment(a.state)
					a.state.CompletionStatus = status
					if status != CompletionStatusCompleted {
						content += "\n\n" + formatIncompleteSummary(status, reasons)
					}
					if summary := scanTelemetrySummary(a.state, status, reasons); summary != "" {
						a.emit(Event{Type: "message", Content: summary, TotalTokens: tokenCount()})
					}
				}
				a.emit(Event{Type: "finished", Content: content, TotalTokens: tokenCount()})
				return
			}

			resultMsg := formatToolResult(tc.Name, result)
			if a.boundedContextEnabled() && result.Error == "" {
				// Information-complete archiving: persist the COMPLETE raw
				// output (pre-truncation) so aged stubs can point at a
				// byte-identical retrievable original.
				minBytes := a.toolArchiveMinBytes()
				if len(result.Output) >= minBytes {
					if id := a.scanCtx.ToolOutputs.Archive(tc.Name, result.Output, minBytes); id != "" {
						resultMsg = strings.TrimRight(resultMsg, "\n") + "\n" + archiveToolResultMarker(id)
					}
				}
			}
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: resultMsg})
			a.msgMu.Unlock()

			// ── Per-role temperature switching ──
			// Adjust LLM temperature based on what the agent is about to do
			// next, inferred from the tool it just called.
			switch tc.Name {
			case "report_vulnerability":
				// Next response will write/refine a vulnerability report
				a.client.SetTemperature(TempReporter)
			case "add_note", "read_notes":
				// Next response involves analysis/reasoning about findings
				a.client.SetTemperature(TempReasoner)
			default:
				// Default scanning temperature for all other tools
				a.client.SetTemperature(TempScanner)
			}
		}
		// Prune message history to prevent context window overflow — but only
		// once the buffer has grown past the window-relative compaction ceiling
		// (pruneMessages self-guards on the same threshold; this check just
		// avoids the lock/scan when we're nowhere near it).
		if a.shouldPruneBeforeLLM() {
			a.pruneMessages()
		}
		// Optional iteration delay to pace LLM request velocity and conserve provider rolling-window quotas.
		if delay := a.getIterationDelay(); delay > 0 && !a.stopped.Load() && (a.maxIter == 0 || iter+1 < a.maxIter) {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-a.ctx.Done():
				timer.Stop()
			}
			if a.stopped.Load() || (a.ctx != nil && a.ctx.Err() != nil) {
				break
			}
		}
	}

	// The loop exited. Report the ACTUAL termination reason instead of always
	// blaming "maximum iterations". With the default unlimited iteration budget
	// (maxIter == 0) the loop can ONLY end here via an external Stop() or a
	// canceled context — mislabeling every such exit as "maximum iterations"
	// hid the real cause (user stop, shutdown, watchdog kill, or upstream
	// context cancellation) and made healthy scans look like they'd blown a cap.
	var finishReason string
	switch {
	case a.maxIter > 0 && iter >= a.maxIter:
		finishReason = fmt.Sprintf("Agent reached maximum iterations (%d)", a.maxIter)
	case a.stopped.Load():
		finishReason = "Scan stopped"
	case a.ctx != nil && a.ctx.Err() != nil:
		finishReason = "Scan canceled: " + a.ctx.Err().Error()
	default:
		finishReason = "Scan ended"
	}
	a.emit(Event{Type: "finished", Content: finishReason, TotalTokens: tokenCount()})
}

// Stop signals the agent to stop and kills all running processes.
func (a *Agent) Stop() {
	a.stopped.Store(true)

	if a.cancel != nil {
		a.cancel()
	}
	if a.ownsAgentGraph && a.agentGraph != nil {
		a.agentGraph.Stop()
	}

	// NOTE: Do NOT call terminal.KillAllProcesses() or browser.CleanupBrowser()
	// here — those are GLOBAL operations that kill processes across ALL instances.
	// Per-instance cleanup is handled by sctx.Close() in sess.cleanup().
	// The handleStop handler calls terminal.KillAllProcesses() directly for
	// user-initiated "Stop All" operations.
}

// WaitForDelegatedAgents waits for this root's child runners to observe
// cancellation and unwind. Cleanup uses a bounded wait before deleting shared
// scan-context stores, preventing a late child from writing after persistence.
func (a *Agent) WaitForDelegatedAgents(timeout time.Duration) bool {
	if !a.ownsAgentGraph || a.agentGraph == nil {
		return true
	}
	return a.agentGraph.WaitStopped(timeout)
}

// SendMessage injects an operator message into the running scan's
// conversation history so the agent picks it up on its next iteration.
// Routing it through the message buffer (instead of issuing a separate
// LLM call) avoids concurrent Chat() calls that would corrupt history.
//
// This is fire-and-forget: the returned string is an acknowledgement
// that the message was queued, NOT the agent's reply. The agent's
// response to the message surfaces later as normal scan events on the
// live feed. The error is non-nil only when the agent is already stopped.
func (a *Agent) SendMessage(message string) (string, error) {
	if a.stopped.Load() {
		return "", fmt.Errorf("agent is not running")
	}

	a.msgMu.Lock()
	a.messages = append(a.messages, llm.Message{
		Role:    "user",
		Content: "[USER MESSAGE DURING SCAN]: " + message,
	})
	a.msgMu.Unlock()

	// Emit as a visible event so it appears in the feed
	a.emit(Event{Type: "message", Content: fmt.Sprintf("📨 User message received: %s", message)})

	return "Message received and will be processed on the next iteration.", nil
}

func (a *Agent) emit(evt Event) {
	evt.AgentID = a.ID
	evt.Timestamp = time.Now()
	// Redact operator-supplied auth secrets from telemetry so credentials
	// don't leak into the live event stream, scan logs, or PDF reports.
	if len(a.secretValues) > 0 {
		evt.Content = a.redactSecrets(evt.Content)
		if evt.ToolResult.Output != "" {
			evt.ToolResult.Output = a.redactSecrets(evt.ToolResult.Output)
		}
		if evt.ToolResult.Error != "" {
			evt.ToolResult.Error = a.redactSecrets(evt.ToolResult.Error)
		}
		// Tool ARGUMENTS also carry secrets: the agent is instructed to pass
		// auth headers explicitly to curl/http_request (e.g. the second-account
		// IDOR/BOLA flow), so credentials land in ToolArgs and would otherwise
		// be broadcast/persisted in the clear. Redact a COPY so the agent's own
		// working args (used to actually run the tool) are left intact.
		if len(evt.ToolArgs) > 0 {
			red := make(map[string]string, len(evt.ToolArgs))
			for k, v := range evt.ToolArgs {
				red[k] = a.redactSecrets(v)
			}
			evt.ToolArgs = red
		}
	}
	if a.events != nil {
		// Critical events (finished, error) must never be dropped — use blocking send with timeout
		if evt.Type == "finished" || evt.Type == "error" {
			if !safeSend(a.events, evt, 10*time.Second) {
				log.Printf("⚠️ CRITICAL: Failed sending %s event (channel closed or full for 10s)", evt.Type)
			}
		} else {
			// Non-critical event: best-effort non-blocking send. A closed or
			// full channel simply drops the event, so the boolean result is
			// intentionally ignored.
			_ = safeSend(a.events, evt, 0)
		}
	}
}

// safeSend sends an event to a channel without panicking if the channel is closed.
// If timeout > 0, it blocks up to that duration. If timeout == 0, it's non-blocking.
// Returns true if sent successfully, false if dropped (closed, full, or timed out).
func safeSend(ch chan Event, evt Event, timeout time.Duration) (sent bool) {
	defer func() {
		if r := recover(); r != nil {
			// "send on closed channel" — channel was closed by parent session
			sent = false
		}
	}()
	if timeout > 0 {
		select {
		case ch <- evt:
			return true
		case <-time.After(timeout):
			return false
		}
	}
	select {
	case ch <- evt:
		return true
	default:
		return false
	}
}

// redactSecrets replaces operator-supplied auth values in s with a marker.
func (a *Agent) redactSecrets(s string) string {
	if s == "" {
		return s
	}
	for _, secret := range a.secretValues {
		if secret != "" && strings.Contains(s, secret) {
			s = strings.ReplaceAll(s, secret, "***REDACTED***")
		}
	}
	return s
}

// credentialsInURL extracts embedded clone credentials from a git/HTTP URL of
// the form scheme://userinfo@host/path — e.g. a GitHub token in
// https://x-access-token:<TOKEN>@github.com/org/repo.git. It returns the
// full userinfo ("user:pass") and, separately, the password/token component,
// so they can be registered as redaction secrets. Returns nil when the URL
// carries no credentials. Values shorter than 4 chars are skipped to avoid
// redacting trivially-common substrings.
func credentialsInURL(raw string) []string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return nil
	}
	rest := raw[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return nil
	}
	// The host part may itself contain no '@'; take the userinfo up to the
	// FIRST '@' (credentials cannot contain an unescaped '@').
	userinfo := rest[:at]
	if userinfo == "" {
		return nil
	}
	var out []string
	if len(userinfo) >= 4 {
		out = append(out, userinfo)
	}
	if c := strings.Index(userinfo, ":"); c >= 0 {
		if pw := userinfo[c+1:]; len(pw) >= 4 {
			out = append(out, pw)
		}
	}
	return out
}

// SetTargetAuth sets per-scan authenticated-session credentials, overriding
// the global default. Call before Run(). Empty string clears it.
func (a *Agent) SetTargetAuth(s string) { a.targetAuth = strings.TrimSpace(s) }

// SetTargetAuthSecondary sets a per-scan SECOND account's credentials (for
// horizontal IDOR/BOLA proof). Call before Run(). Empty string clears it.
func (a *Agent) SetTargetAuthSecondary(s string) { a.targetAuthB = strings.TrimSpace(s) }

// CodeScanMode selects a code-first scanning strategy where the primary
// subject is the target's source (a repo/path), not a live URL.
type CodeScanMode int

const (
	// CodeScanNone is the default: black-box or whitebox-augmented testing
	// against a live target URL.
	CodeScanNone CodeScanMode = iota
	// CodeScanReview is source review / SAST with NO live target: the agent
	// reads the code, traces source→sink→reachable-route, and reports
	// source-verified findings. Findings are clearly labeled as statically
	// verified (not runtime-exploited), since there is no running target.
	CodeScanReview
	// CodeScanProvision builds and runs the target's source locally (in the
	// agent's sandbox, on a loopback port the orchestrator allowlists), then
	// pentests the running instance for exploit-verified findings.
	CodeScanProvision
)

// SetCodeScanMode sets the code-first scan strategy. Call before Run().
func (a *Agent) SetCodeScanMode(m CodeScanMode) { a.codeScanMode = m }

// SetSourceRepo sets the per-scan whitebox source (git URL or local path),
// overriding the global default. Call before Run().
func (a *Agent) SetSourceRepo(s string) { a.sourceRepo = strings.TrimSpace(s) }

// SetScanContext sets the per-scan context artifact path (OpenAPI/HAR/Postman
// file or directory) used to seed the attack surface. Call before Run().
func (a *Agent) SetScanContext(s string) { a.scanContext = strings.TrimSpace(s) }

// SetInitialIteration sets the starting iteration index for resumed runs. Call before Run().
func (a *Agent) SetInitialIteration(iter int) {
	if iter > 0 {
		a.initialIter = iter
	}
}

// SetResumeBriefing sets a briefing summarizing prior state when resuming a scan. Call before Run().
func (a *Agent) SetResumeBriefing(s string) {
	a.resumeBriefing = strings.TrimSpace(s)
}

func (a *Agent) getIterationDelay() time.Duration {
	if a == nil {
		return 0
	}
	if ms := a.iterationDelayMs.Load(); ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	if a.cfg != nil && a.cfg.IterationDelaySec > 0 {
		return time.Duration(a.cfg.IterationDelaySec * float64(time.Second))
	}
	return 0
}

// SetIterationDelay dynamically updates the iteration delay in seconds.
// It updates the agent's internal delay, its configuration, and recursively propagates
// to any active child/subagent runners.
func (a *Agent) SetIterationDelay(delaySec float64) {
	if a == nil {
		return
	}
	if delaySec < 0 {
		delaySec = 0
	}
	a.iterationDelayMs.Store(int64(delaySec * 1000))
	if a.cfg != nil {
		a.cfg.IterationDelaySec = delaySec
	}
	a.childrenMu.Lock()
	for child := range a.children {
		child.SetIterationDelay(delaySec)
	}
	a.childrenMu.Unlock()
}

func (a *Agent) registerChildAgent(child *Agent) {
	if a == nil || child == nil {
		return
	}
	a.childrenMu.Lock()
	if a.children == nil {
		a.children = make(map[*Agent]struct{})
	}
	a.children[child] = struct{}{}
	a.childrenMu.Unlock()
}

func (a *Agent) unregisterChildAgent(child *Agent) {
	if a == nil || child == nil {
		return
	}
	a.childrenMu.Lock()
	delete(a.children, child)
	a.childrenMu.Unlock()
}

// prepareScanEnvironment wires per-scan authenticated-session credentials and
// whitebox source into the shared scan context. Runs at the start of Run()
// (in the scan's own goroutine, so a slow git clone never blocks scan
// creation / the HTTP handler). Idempotent and safe for sub-agents: the source
// clone is guarded so only the first agent for a context resolves it.
func (a *Agent) prepareScanEnvironment() {
	if a.scanCtx == nil {
		return
	}
	// Authenticated session → applied to http_request for this scan context.
	if headers := httpclient.ParseAuthHeaders(a.targetAuth); len(headers) > 0 {
		httpclient.SetSessionAuth(a.scanCtx.ID, headers)
		for _, v := range headers {
			if len(strings.TrimSpace(v)) >= 4 { // avoid redacting trivially short values
				a.secretValues = append(a.secretValues, v)
			}
		}
	}
	// Second account (B) is NOT auto-applied — the agent uses it manually to
	// prove horizontal access control. Still redact its values from telemetry.
	for _, v := range httpclient.ParseAuthHeaders(a.targetAuthB) {
		if len(strings.TrimSpace(v)) >= 4 {
			a.secretValues = append(a.secretValues, v)
		}
	}
	// Whitebox source (git clone / local path). Resolve once per scan context.
	if a.sourceRepo != "" && codesearch.GetSourceRoot(a.scanCtx.ID) == "" {
		dest := a.scanCtx.ScanDir
		if dest == "" {
			dest = os.TempDir()
		}
		dest = filepath.Join(dest, "source")
		// A private-repo clone URL may embed a token
		// (https://x-access-token:<TOKEN>@github.com/...). Register those
		// credentials as redaction secrets BEFORE any emit/log so the token
		// never leaks into telemetry, the scan log, PDF reports, or git's
		// own "authentication failed for <url>" error output.
		a.secretValues = append(a.secretValues, credentialsInURL(a.sourceRepo)...)
		a.emit(Event{Type: "message", Content: fmt.Sprintf("📦 Whitebox: resolving source (%s)…", a.redactSecrets(a.sourceRepo))})
		if root, err := codesearch.ResolveSource(a.sourceRepo, dest); err != nil {
			a.emit(Event{Type: "error", Content: "Whitebox source unavailable: " + a.redactSecrets(err.Error()) + " — continuing black-box."})
			log.Printf("[agent] whitebox source unavailable (%s): %v", a.redactSecrets(a.sourceRepo), a.redactSecrets(err.Error()))
		} else if root != "" {
			codesearch.SetSourceRoot(a.scanCtx.ID, root)
			a.emit(Event{Type: "message", Content: "📦 Whitebox source ready — use code_search to hunt sinks."})
			log.Printf("[agent] whitebox source ready at %s", root)
			// Auto-seed the ledger from source so the source-to-runtime bridge
			// starts populated (mirrors seedLedgerFromSurface for uploaded
			// artifacts): dangerous sinks + reachable routes become schedulable
			// hypotheses from iteration 1, without waiting for the model to call
			// scan_source_sinks / scan_source_routes.
			if s := a.seedLedgerFromSource(); s.SinkHypotheses+s.RouteHypotheses > 0 {
				a.emit(Event{Type: "message", Content: fmt.Sprintf("🔎 Seeded %d source→sink and %d route hypotheses from source (%d route↔sink correlated) — use read_ledger and probe_hypothesis to confirm reachability.", s.SinkHypotheses, s.RouteHypotheses, s.Correlated)})
				log.Printf("[agent] source seeding: %d sink, %d route hypotheses (%d correlated)", s.SinkHypotheses, s.RouteHypotheses, s.Correlated)
			}
		}
	}
	// Attack-surface seeding (OpenAPI / HAR / Postman). Parse the operator's
	// context artifacts into a real endpoint surface + any captured auth, so the
	// scan starts informed instead of blindly crawling.
	if a.scanContext != "" && a.scanContextBriefing == "" {
		if res, err := attacksurface.LoadFromPath(a.scanContext); err != nil {
			a.emit(Event{Type: "error", Content: "Scan context unavailable: " + err.Error() + " — continuing without seeded surface."})
			log.Printf("[agent] scan context unavailable (%s): %v", a.scanContext, err)
		} else if res != nil {
			a.scanContextBriefing = res.Briefing()
			// Harvest auth captured in real requests (HAR/Postman) when the
			// operator didn't already supply explicit target auth.
			if len(res.AuthHeaders) > 0 && len(httpclient.ParseAuthHeaders(a.targetAuth)) == 0 {
				httpclient.SetSessionAuth(a.scanCtx.ID, res.AuthHeaders)
				for _, v := range res.AuthHeaders {
					if len(strings.TrimSpace(v)) >= 4 {
						a.secretValues = append(a.secretValues, v)
					}
				}
			}
			// Turn the parsed surface into schedulable ledger hypotheses so the
			// uploaded context drives authz_matrix and the specialists, not just
			// the text briefing. Idempotent (the ledger dedups), so sub-agents
			// that also parse the context add nothing new.
			seeded := a.seedLedgerFromSurface(res)
			// Retain the typed endpoint metadata (methods, parameters) for
			// the structured applicability layer — the notes briefing stays
			// the prose mirror, but the planner consumes this typed form.
			for _, e := range res.Endpoints {
				host, epath := splitSurfaceEndpoint(e.Path, res.BaseURLs)
				if epath == "" {
					continue
				}
				record := SeededSurfaceEndpoint{
					Path:   epath,
					Method: strings.ToUpper(strings.TrimSpace(e.Method)),
					Source: "context",
				}
				if e.Source != "" {
					record.Source = "context:" + e.Source
				}
				record.Params = append(record.Params, e.Params...)
				if host != "" {
					recordEndpointMethod(a.state, host+epath, record.Method)
				}
				a.state.SeededSurface = append(a.state.SeededSurface, record)
			}
			if a.scanContextBriefing != "" {
				msg := fmt.Sprintf("🗺️ Attack surface seeded from context (%d endpoints", len(res.Endpoints))
				if seeded > 0 {
					msg += fmt.Sprintf(", %d ledger hypotheses", seeded)
				}
				msg += ")."
				a.emit(Event{Type: "message", Content: msg})
			}
		}
	}
}

// authGuidance returns an authenticated-session briefing when the operator
// supplied target credentials, or "" otherwise. Post-auth surface (IDOR/BOLA,
// privilege escalation, business logic) is where the high-value bugs live, so
// the agent must know it is authenticated and must diff authed vs unauthed.
func (a *Agent) authGuidance() string {
	headers := httpclient.ParseAuthHeaders(a.targetAuth)
	if len(headers) == 0 {
		return ""
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var curlHdrs strings.Builder
	for _, n := range names {
		curlHdrs.WriteString(fmt.Sprintf(" -H %q", n+": "+headers[n]))
	}
	return fmt.Sprintf(`
## AUTHENTICATED SESSION (operator-supplied)
You have VALID authenticated credentials for this target. They are applied AUTOMATICALLY to every http_request call (%s), so your requests are authenticated by default.
- For terminal tools (curl/ffuf/sqlmap/etc.) add these headers explicitly, e.g.: curl%s <url>
- HUNT THE POST-AUTH SURFACE — this is where the money is: IDOR/BOLA (swap ids/uuids to reach OTHER users' data), broken function-level auth (BFLA), privilege escalation (low-priv → admin actions), tenant isolation, and multi-step business-logic flaws.
- ALWAYS DIFF authenticated vs unauthenticated: replay the same request with the auth headers REMOVED (pass an empty value for that header in http_request) — if protected data/actions still work unauthenticated, that is a broken-access-control finding.
%s`, strings.Join(names, ", "), curlHdrs.String(), a.secondAccountGuidance())
}

// secondAccountGuidance returns the horizontal-access-control (IDOR/BOLA)
// playbook when a second account is configured, or "" otherwise. Two valid
// sessions let the agent PROVE cross-user access with concrete evidence.
func (a *Agent) secondAccountGuidance() string {
	headers := httpclient.ParseAuthHeaders(a.targetAuthB)
	if len(headers) == 0 {
		return "- If you can obtain a SECOND account, compare horizontal access (user A's token reaching user B's objects).\n"
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var curlHdrs strings.Builder
	for _, n := range names {
		curlHdrs.WriteString(fmt.Sprintf(" -H %q", n+": "+headers[n]))
	}
	return fmt.Sprintf(`
## SECOND ACCOUNT (operator-supplied) — PROVE IDOR/BOLA
You ALSO have a DISTINCT second account (account B). Its headers (%s) are NOT applied automatically — pass them explicitly to prove horizontal access control:
- With account B in curl: curl%s <url>
- METHODOLOGY: (1) as account A, create/enumerate an object and note its id/uuid (e.g. GET /api/orders → id=1001, owned by A); (2) request that SAME object as account B (curl with B's headers, or http_request with B's headers overriding the session); (3) if B can READ or MODIFY A's object, that is CONFIRMED BOLA/IDOR — capture both responses as proof.
- Do this for every object-scoped endpoint from the attack surface. Also test BFLA: can a low-privilege account reach an admin-only function?
- The strongest evidence is B receiving A's private data (or successfully mutating A's resource). Report with verification_method=data_extracted and paste BOTH requests/responses.
`, strings.Join(names, ", "), curlHdrs.String())
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// overBudget reports whether any configured per-scan resource cap has been
// reached (MAPTA §2.7/§3.3). All caps default to 0 = unlimited, so this is a
// no-op unless the operator opts in. Returns a human-readable reason.
func (a *Agent) overBudget(toolCallsTotal int) (bool, string) {
	if a.cfg == nil {
		return false, ""
	}
	if a.cfg.MaxDurationSec > 0 {
		elapsed := time.Duration(0)
		started := false
		if a.scanBudget != nil {
			elapsed, started = a.scanBudget.elapsed()
		} else if !a.scanStart.IsZero() {
			elapsed, started = time.Since(a.scanStart), true
		}
		if started && elapsed >= time.Duration(a.cfg.MaxDurationSec)*time.Second {
			return true, fmt.Sprintf("time %s ≥ cap %ds", elapsed.Round(time.Second), a.cfg.MaxDurationSec)
		}
	}
	usedToolCalls := toolCallsTotal
	if a.scanBudget != nil {
		usedToolCalls = a.scanBudget.toolCallCount()
	}
	if a.cfg.MaxToolCalls > 0 && usedToolCalls >= a.cfg.MaxToolCalls {
		return true, fmt.Sprintf("%d tool calls ≥ cap %d", usedToolCalls, a.cfg.MaxToolCalls)
	}
	if a.cfg.MaxTokens > 0 && a.client != nil {
		total := a.syncBudgetTokens()
		if total >= a.cfg.MaxTokens {
			return true, fmt.Sprintf("%d tokens ≥ cap %d", total, a.cfg.MaxTokens)
		}
	}
	return false, ""
}

var httpxFixOnce sync.Once

// fixHttpxConflict detects and removes Python's httpx if it shadows ProjectDiscovery's httpx.
func fixHttpxConflict() {
	httpxFixOnce.Do(func() {
		// Check if httpx exists
		httpxPath, err := exec.LookPath("httpx")
		if err != nil {
			return // httpx not installed at all, will be installed later
		}

		// Check if it's Python's httpx by running --version
		out, err := exec.Command(httpxPath, "--version").CombinedOutput()
		if err != nil {
			return // Can't determine, skip
		}

		output := strings.ToLower(string(out))
		if strings.Contains(output, "python") || strings.Contains(output, "httpx/0.") {
			log.Println("⚠️  Detected Python httpx interfering with ProjectDiscovery httpx — removing it...")

			// Try removing Python httpx
			for _, pip := range []string{"pip3", "pip", "pipx"} {
				if _, err := exec.LookPath(pip); err == nil {
					cmd := exec.Command(pip, "uninstall", "httpx", "-y")
					if out, err := cmd.CombinedOutput(); err != nil {
						log.Printf("Failed to uninstall Python httpx via %s: %s", pip, string(out))
					}
				}
			}

			// Install ProjectDiscovery httpx
			cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Failed to install ProjectDiscovery httpx: %s", string(out))
			} else {
				log.Println("✅ Replaced Python httpx with ProjectDiscovery httpx")
			}
		}
	})
}

func determineAgentType(agentName string, isDelegated bool) string {
	if !isDelegated {
		return scanctx.AgentTypeRoot
	}
	lower := strings.ToLower(agentName)
	switch {
	case strings.Contains(lower, "authz") || strings.Contains(lower, "logic"):
		return scanctx.AgentTypeAuthzLogic
	case strings.Contains(lower, "inject") || strings.Contains(lower, "server"):
		return scanctx.AgentTypeInjectionServer
	case strings.Contains(lower, "client") || strings.Contains(lower, "source") || strings.Contains(lower, "xss"):
		return scanctx.AgentTypeClientSource
	case strings.Contains(lower, "verifier") || strings.Contains(lower, "verify"):
		return scanctx.AgentTypeVerifier
	default:
		return scanctx.AgentTypeOther
	}
}

func calculateMessageMetrics(msgs []llm.Message) (totalBytes, sysBytes, userBytes, asstBytes, toolCount, toolBytes, skillCount, skillBytes int) {
	for _, m := range msgs {
		b := len(m.Content)
		totalBytes += b
		switch m.Role {
		case "system":
			sysBytes += b
		case "assistant":
			asstBytes += b
		case "user":
			userBytes += b
			isTool := strings.Contains(m.Content, "<function_results>") || strings.Contains(m.Content, "Tool '") || strings.Contains(m.Content, "result:\n")
			if isTool {
				toolCount++
				toolBytes += b
				if strings.Contains(m.Content, "read_skill") || strings.Contains(m.Content, "list_skills") || strings.Contains(m.Content, "Skill already loaded") {
					skillCount++
					skillBytes += b
				}
			}
		}
	}
	return
}

func (a *Agent) recordTokenAttribution(usage *llm.TokenUsage, msgs []llm.Message, iter int, category string, retryAttempt int) {
	if a == nil || a.scanCtx == nil || a.scanCtx.Tokens == nil {
		return
	}
	totBytes, sysBytes, usrBytes, asstBytes, tCount, tBytes, sCount, sBytes := calculateMessageMetrics(msgs)
	pTokens, outTokens, _ := a.client.GetTokens()

	model := ""
	provider := ""
	if a.cfg != nil {
		model = a.cfg.LLM
		provider = a.cfg.LLMProvider
	}

	rec := scanctx.TokenAttribution{
		ScanID:                  a.scanCtx.ID,
		AgentID:                 a.ID,
		AgentType:               determineAgentType(a.Name, a.state != nil && a.state.DelegatedAgent),
		Iteration:               iter,
		Model:                   model,
		Provider:                provider,
		PromptTokens:            0,
		CompletionTokens:        0,
		TotalTokens:             0,
		CachedInputTokens:       0,
		UncachedInputTokens:     0,
		MessageCount:            len(msgs),
		SerializedMessageBytes:  totBytes,
		SystemMessageBytes:      sysBytes,
		UserMessageBytes:        usrBytes,
		AssistantMessageBytes:   asstBytes,
		ToolResultCount:         tCount,
		ToolResultBytes:         tBytes,
		SkillResultCount:        sCount,
		SkillResultBytes:        sBytes,
		ConversationBufferBytes: totBytes,
		RetryAttempt:            retryAttempt,
		RequestCategory:         category,
		CompactionCount:         a.compactionCount,
		AgentCumulativePrompt:   pTokens,
		AgentCumulativeOutput:   outTokens,
		Timestamp:               time.Now(),
	}
	if usage != nil {
		rec.PromptTokens = usage.PromptTokens
		rec.CompletionTokens = usage.CompletionTokens
		rec.TotalTokens = usage.TotalTokens
		rec.CachedInputTokens = usage.GetCachedTokens()
		rec.CacheReported = usage.HasCachedTokens
		rec.UncachedInputTokens = usage.PromptTokens - rec.CachedInputTokens
		if rec.UncachedInputTokens < 0 {
			rec.UncachedInputTokens = 0
		}
	}
	a.scanCtx.Tokens.Record(rec)
}
