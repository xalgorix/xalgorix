package bench

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// ScanFunc runs a full scan against target (the base URL of a challenge app)
// under the given scan id, and returns the findings it produced. sourceDir is
// the challenge's materialized whitebox source tree (the scan wires it as the
// target's source repo), or "" for a pure black-box challenge. It is injected
// so the harness stays free of the heavy, non-hermetic agent machinery: the
// real implementation (cmd/xalgorix-bench) drives the LLM agent and makes live
// calls, while tests pass a deterministic fake.
type ScanFunc func(ctx context.Context, target, sourceDir, scanID string, auth Auth) ([]reporting.Vulnerability, error)

// DefaultChallengeTimeout bounds how long a single challenge scan may run. A
// scan against a trivial challenge app should finish quickly; without a bound a
// wandering or stuck scan can hang the whole run.
const DefaultChallengeTimeout = 8 * time.Minute

// TempRoot keeps benchmark-only state inside the project instead of the
// operating system's global temporary directory.
const TempRoot = "tmp"

// NewTempDir creates an isolated benchmark workspace below the project-local
// tmp/ directory. The caller owns the returned directory and must remove it.
func NewTempDir(pattern string) (string, error) {
	if err := os.MkdirAll(TempRoot, 0o750); err != nil {
		return "", err
	}
	return os.MkdirTemp(TempRoot, pattern)
}

// Run executes each challenge in order with the default per-challenge timeout.
func Run(ctx context.Context, challenges []Challenge, scan ScanFunc) Scorecard {
	return RunWithTimeout(ctx, challenges, scan, DefaultChallengeTimeout)
}

// RunWithTimeout executes each challenge in order: it starts the challenge app,
// invokes the scan against its base URL under a per-challenge deadline, scores
// the findings against the expected class, and aggregates a Scorecard.
// Challenges run sequentially so a single shared LLM/tool budget isn't contended
// and the run is reproducible. A per-challenge timeout <= 0 disables the bound.
func RunWithTimeout(ctx context.Context, challenges []Challenge, scan ScanFunc, perChallenge time.Duration) Scorecard {
	card := Scorecard{Results: make([]Result, 0, len(challenges))}
	for _, c := range challenges {
		if ctx.Err() != nil {
			break
		}
		card.Results = append(card.Results, runOne(ctx, c, scan, perChallenge))
	}
	return card
}

func runOne(parent context.Context, c Challenge, scan ScanFunc, timeout time.Duration) Result {
	srv := c.Start()
	defer srv.Close()

	// Materialize the whitebox source tree (if any) to a temp dir the scan can
	// point its source repo at, and clean it up afterward.
	sourceDir := ""
	if len(c.SourceFiles) > 0 {
		if dir, err := writeSourceFiles(c.SourceFiles); err == nil {
			sourceDir = dir
			defer func() { _ = os.RemoveAll(dir) }()
		}
	}

	ctx := parent
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, timeout)
		defer cancel()
	}

	res := Result{Name: c.Name, Class: canonicalClass(c.Class), Negative: c.Negative}
	start := time.Now()
	findings, err := scan(ctx, srv.URL, sourceDir, "bench-"+c.Name, c.Auth)
	res.Elapsed = time.Since(start)
	res.Findings = len(findings)
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if err != nil && !res.TimedOut {
		res.Err = err
	}
	// Score whatever findings were gathered — a scan that timed out may still
	// have reported the vulnerability before the deadline. For a negative
	// control the scoring inverts: reporting the class is a false positive, so
	// "solved" means the class was correctly NOT reported. MatchedFindingID
	// holds the offending finding id when a negative control false-positives.
	reported, id := Solved(c.Class, findings)
	res.MatchedFindingID = id
	if c.Negative {
		res.Solved = !reported
	} else {
		res.Solved = reported
	}
	return res
}

// writeSourceFiles materializes a challenge's whitebox source tree (relative
// path → content) into a fresh temp directory, creating parent directories as
// needed, and returns its path. The caller owns the directory and should remove
// it when done.
func writeSourceFiles(files map[string]string) (string, error) {
	dir, err := NewTempDir("xalgorix-bench-src-")
	if err != nil {
		return "", err
	}
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return dir, err
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return dir, err
		}
	}
	return dir, nil
}
