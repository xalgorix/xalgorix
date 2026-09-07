// Command xalgorix-bench runs the scanner against the built-in benchmark
// challenges and prints a per-class scorecard. It is an operator tool, NOT part
// of the shipped release: each challenge triggers a full LLM-driven agent run
// with live network + tool execution, so it needs XALGORIX_LLM + XALGORIX_API_KEY
// (or a provider profile) set and cannot run in CI.
//
// Usage:
//
//	XALGORIX_LLM=... XALGORIX_API_KEY=... xalgorix-bench [-only reflected-xss,idor] [-task "..."]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/bench"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/realbench"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func main() {
	only := flag.String("only", "", "comma-separated challenge names to run (default: all built-in)")
	task := flag.String("task", "Perform a full security assessment of this target and prove any vulnerability you find with a concrete PoC.", "instruction passed to the agent")
	timeout := flag.Duration("timeout", bench.DefaultChallengeTimeout, "per-challenge wall-clock timeout (e.g. 5m); 0 disables")
	manifestPath := flag.String("manifest", "", "real-world benchmark manifest (switches from built-in challenges to one pinned product target)")
	targetID := flag.String("target-id", "", "target id from -manifest")
	targetURL := flag.String("target-url", "", "running target URL (default: manifest container.default_url)")
	sourceDir := flag.String("source-dir", "", "optional checked-out source tree for a white-box real-world scan")
	resultJSON := flag.String("result-json", "", "write real-world score and full findings as private JSON (mode 0600)")
	runs := flag.Int("runs", 1, "independent sequential runs for a real-world target (1-10; default 1)")
	flag.Parse()

	cfg := config.Get()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: config invalid — set XALGORIX_LLM and XALGORIX_API_KEY (or XALGORIX_LLM_PROFILE):", err)
		os.Exit(2)
	}

	if *manifestPath != "" {
		runRealWorld(*manifestPath, *targetID, *targetURL, *sourceDir, *resultJSON, *task, *timeout, *runs)
		return
	}
	if *targetID != "" || *targetURL != "" || *sourceDir != "" || *resultJSON != "" || *runs != 1 {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: -target-id, -target-url, -source-dir, -result-json, and -runs require -manifest")
		os.Exit(2)
	}

	challenges := bench.Builtin()
	if *only != "" {
		challenges = filterChallenges(challenges, *only)
		if len(challenges) == 0 {
			fmt.Fprintf(os.Stderr, "xalgorix-bench: no built-in challenges matched -only=%q\n", *only)
			os.Exit(2)
		}
	}

	fmt.Fprintf(os.Stderr, "xalgorix-bench: running %d challenge(s) with model %s (per-challenge timeout %s)\n", len(challenges), cfg.ResolveModel(), *timeout)
	card := bench.RunWithTimeout(context.Background(), challenges, realScan(*task), *timeout)
	fmt.Print(card.String())
}

type realWorldRunEvidence struct {
	Run         int                       `json:"run"`
	GeneratedAt time.Time                 `json:"generated_at"`
	ElapsedMS   int64                     `json:"elapsed_ms"`
	TimedOut    bool                      `json:"timed_out,omitempty"`
	Error       string                    `json:"error,omitempty"`
	Score       realbench.Result          `json:"score"`
	Findings    []reporting.Vulnerability `json:"findings"`
}

func runRealWorld(manifestPath, targetID, targetURL, sourceDir, resultPath, instruction string, timeout time.Duration, runs int) {
	if targetID == "" {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: -target-id is required with -manifest")
		os.Exit(2)
	}
	suite, err := realbench.LoadFile(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-bench:", err)
		os.Exit(2)
	}
	target, ok := suite.Target(targetID)
	if !ok {
		fmt.Fprintf(os.Stderr, "xalgorix-bench: target %q is not present in %s\n", targetID, manifestPath)
		os.Exit(2)
	}
	if targetURL == "" {
		targetURL = target.Container.DefaultURL
	}
	if err := realbench.ValidateLoopbackURL(targetURL); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: target URL:", err)
		os.Exit(2)
	}
	if runs < 1 || runs > 10 {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: -runs must be between 1 and 10")
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "xalgorix-bench: real-world target %s (%s %s) at %s — %d independent run(s)\n",
		target.ID, target.Product, target.Version, targetURL, runs)
	scores := make([]realbench.Result, 0, runs)
	evidence := make([]realWorldRunEvidence, 0, runs)
	hadRunFailure := false
	for run := 1; run <= runs; run++ {
		ctx := context.Background()
		cancel := func() {}
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, timeout)
		}
		scanID := "realbench-" + target.ID
		if runs > 1 {
			scanID = fmt.Sprintf("%s-run-%02d", scanID, run)
		}
		fmt.Fprintf(os.Stderr, "xalgorix-bench: run %d/%d (%s)\n", run, runs, scanID)
		started := time.Now().UTC()
		findings, scanErr := realScan(instruction)(ctx, targetURL, sourceDir, scanID, bench.Auth{})
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()

		result := realbench.Score(suite, target, findings)
		scores = append(scores, result)
		fmt.Printf("Run %d/%d\n%s", run, runs, result.String())
		runEvidence := realWorldRunEvidence{
			Run:         run,
			GeneratedAt: time.Now().UTC(),
			ElapsedMS:   time.Since(started).Milliseconds(),
			TimedOut:    timedOut,
			Score:       result,
			Findings:    findings,
		}
		if scanErr != nil {
			runEvidence.Error = scanErr.Error()
			fmt.Fprintf(os.Stderr, "xalgorix-bench: run %d scan error: %v\n", run, scanErr)
			hadRunFailure = true
		}
		if timedOut {
			fmt.Fprintf(os.Stderr, "xalgorix-bench: run %d reached its %s deadline\n", run, timeout)
			hadRunFailure = true
		}
		evidence = append(evidence, runEvidence)
	}

	stability, err := realbench.Aggregate(scores)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: aggregate real-world results:", err)
		os.Exit(1)
	}
	fmt.Print(stability.String())
	if !stability.Stable {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: acceptance failed — every documented vulnerability must match in every run and fixed controls must have zero regressions")
		hadRunFailure = true
	}

	if resultPath != "" {
		payload := struct {
			SchemaVersion int                       `json:"schema_version"`
			GeneratedAt   time.Time                 `json:"generated_at"`
			TargetURL     string                    `json:"target_url"`
			Stability     realbench.StabilityResult `json:"stability"`
			Runs          []realWorldRunEvidence    `json:"runs"`
		}{
			SchemaVersion: 2,
			GeneratedAt:   time.Now().UTC(),
			TargetURL:     targetURL,
			Stability:     stability,
			Runs:          evidence,
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "xalgorix-bench: encode result JSON:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(resultPath, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "xalgorix-bench: write result JSON:", err)
			os.Exit(1)
		}
		if err := os.Chmod(resultPath, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "xalgorix-bench: secure result JSON permissions:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "xalgorix-bench: wrote private benchmark evidence to %s\n", resultPath)
	}
	if hadRunFailure {
		os.Exit(1)
	}
}

func filterChallenges(all []bench.Challenge, csv string) []bench.Challenge {
	want := map[string]bool{}
	for _, n := range strings.Split(csv, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	out := make([]bench.Challenge, 0, len(want))
	for _, c := range all {
		if want[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// realScan builds the ScanFunc that drives a real agent run against one target
// and returns the findings it produced. Mirrors the production scan wiring
// (internal/web/scan_session.go) minus the dashboard plumbing.
func realScan(instruction string) bench.ScanFunc {
	return func(ctx context.Context, target, sourceDir, scanID string, auth bench.Auth) ([]reporting.Vulnerability, error) {
		cfg := config.Get()

		// Every attempt needs a clean filesystem. Keep isolated workspaces under
		// the project's tmp/ directory so benchmark state never leaks between runs.
		scanDir, err := bench.NewTempDir("xalgorix-bench-")
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(scanDir, 0o750); err != nil {
			_ = os.RemoveAll(scanDir)
			return nil, err
		}
		defer func() { _ = os.RemoveAll(scanDir) }()
		sc := scanctx.New(scanID, scanDir)
		scanctx.Activate(sc)
		defer func() {
			scanctx.Deactivate(sc.ID)
			sc.Close()
			reporting.CleanupContext(sc.ID)
		}()

		// Drain agent events. Logging the agent's tool calls, verifier/report
		// outcomes, errors, and finish reason to stderr is what makes a failing
		// challenge diagnosable — without it the run is a black box (only infra
		// logs show). Kept compact (one line per event, args/outputs truncated)
		// and prefixed with the scan id so a multi-challenge run stays readable.
		events := make(chan agent.Event, 512)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for ev := range events {
				switch ev.Type {
				case "tool_call":
					fmt.Fprintf(os.Stderr, "  [ev %s] → %s %s\n", scanID, ev.ToolName, briefArgs(ev.ToolArgs))
				case "tool_result":
					if ev.ToolResult.Error != "" {
						fmt.Fprintf(os.Stderr, "  [ev %s] ✗ %s: %s\n", scanID, ev.ToolName, truncate(oneLine(ev.ToolResult.Error), 240))
					} else if isDiagResultTool(ev.ToolName) {
						fmt.Fprintf(os.Stderr, "  [ev %s] ✓ %s: %s\n", scanID, ev.ToolName, truncate(oneLine(ev.ToolResult.Output), 240))
					}
				case "error":
					fmt.Fprintf(os.Stderr, "  [ev %s] ERROR %s\n", scanID, truncate(oneLine(ev.Content), 240))
				case "finished":
					if ev.Aborted {
						fmt.Fprintf(os.Stderr, "  [ev %s] FINISHED aborted=%s %s\n", scanID, ev.AbortReason, truncate(oneLine(ev.Content), 160))
					} else {
						fmt.Fprintf(os.Stderr, "  [ev %s] FINISHED %s\n", scanID, truncate(oneLine(ev.Content), 160))
					}
				}
			}
		}()

		// AllowLocalTargets lets the scan reach the loopback challenge server.
		guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0, AllowLocalTargets: true}
		ag := agent.NewAgent(cfg, "XalgorixBench", events, guard, sc, agent.WithBenchmarkIsolation())
		ag.SetPhaseRestrictions(nil)
		ag.SetActivityPolicy("active", "active", []string{target})
		// Authenticated challenge: wire the seeded identities so the scan carries
		// role A as its session and authz_matrix can replay requests as role B —
		// the setup real BOLA/BFLA/IDOR proof needs (mirrors production's
		// XALGORIX_TARGET_AUTH / _B). Stateless challenges pass an empty Auth.
		if lines := headerLines(auth.A); lines != "" {
			ag.SetTargetAuth(lines)
			fmt.Fprintf(os.Stderr, "  [bench] %s → role A session seeded (%d header(s))\n", scanID, len(auth.A))
		}
		if lines := headerLines(auth.B); lines != "" {
			ag.SetTargetAuthSecondary(lines)
			fmt.Fprintf(os.Stderr, "  [bench] %s → role B (second account) seeded (%d header(s))\n", scanID, len(auth.B))
		}
		// Whitebox challenge: wire the materialized source tree so the scan can
		// use the source-to-runtime bridge (auto-seed + scan_source_sinks/routes
		// + probe_hypothesis), mirroring production's per-scan source repo.
		if sourceDir != "" {
			ag.SetSourceRepo(sourceDir)
			fmt.Fprintf(os.Stderr, "  [bench] %s → source %s\n", scanID, sourceDir)
		}

		fmt.Fprintf(os.Stderr, "  [bench] %s → %s\n", scanID, target)
		// Run the (blocking) scan in a goroutine so the harness's per-challenge
		// deadline can stop a wandering or stuck scan instead of hanging the run.
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			ag.Run([]string{target}, instruction)
		}()
		select {
		case <-runDone:
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "  [bench] %s → deadline reached, stopping scan\n", scanID)
			ag.Stop()
			<-runDone
		}

		close(events)
		<-done

		findings := reporting.GetVulnerabilitiesForContext(sc.ID)
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "    finding %s: title=%q endpoint=%q target=%q cwe=%q sev=%q tags=%v\n",
				f.ID, f.Title, f.Endpoint, f.Target, f.CWE, f.Severity, f.Tags)
		}
		return findings, nil
	}
}

// isDiagResultTool reports whether a tool's successful result is worth logging
// in full for diagnosis (verifiers, reporting, OOB polling, authz) — as opposed
// to noisy recon output (curl/ffuf/nuclei) whose call args already tell the
// story.
func isDiagResultTool(name string) bool {
	switch name {
	case "verify_xss", "verify_sqli", "verify_ssti", "verify_oob",
		"report_vulnerability", "oob_callback", "probe_hypothesis", "authz_matrix":
		return true
	}
	return false
}

// briefArgs renders tool args as a compact, deterministic "k=v" list with each
// value shortened, so a tool_call line shows what mattered (the URL, payload,
// title, severity, …) without dumping large request bodies.
func briefArgs(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := oneLine(args[k])
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+truncate(v, 100))
	}
	return truncate(strings.Join(parts, " "), 300)
}

// headerLines renders credential headers as newline-joined "Name: value" lines
// (sorted for determinism) — the format SetTargetAuth / SetTargetAuthSecondary
// parse. Returns "" for an empty set.
func headerLines(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+": "+h[k])
	}
	return strings.Join(lines, "\n")
}

// oneLine collapses whitespace/newlines so a multi-line value stays on one log
// line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
