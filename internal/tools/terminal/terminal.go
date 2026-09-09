// Package terminal provides the terminal_execute tool.
package terminal

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/iolimit"
)

const maxOutputLen = 20000

// Per-command timeout tiers
const (
	defaultCmdTimeout = 10 * time.Minute // most commands
	heavyCmdTimeout   = 60 * time.Minute // nmap, nuclei, ffuf, gobuster, sqlmap, masscan
	hardMaxTimeout    = 2 * time.Hour    // absolute ceiling — nothing runs longer
)

// ── Per-instance terminal stores ──
var (
	termStores   = make(map[string]*termStore)
	termStoresMu sync.RWMutex
)

type termStore struct {
	mu              sync.Mutex
	processGroup    map[*exec.Cmd]context.CancelFunc
	activeCommand   string
	activeStartTime time.Time
	streamCallback  func(string)
	workDir         string
}

// getTermStoreByID returns the terminal store for a specific context ID.
// Creates a new store if one doesn't exist (double-checked locking).
func getTermStoreByID(id string) *termStore {
	termStoresMu.RLock()
	s, ok := termStores[id]
	termStoresMu.RUnlock()
	if ok {
		return s
	}

	termStoresMu.Lock()
	defer termStoresMu.Unlock()
	if s, ok := termStores[id]; ok {
		return s
	}
	s = &termStore{processGroup: make(map[*exec.Cmd]context.CancelFunc)}
	termStores[id] = s
	return s
}

// getTermStore returns the terminal store for the default (CLI) scan context.
func getTermStore() *termStore {
	return getTermStoreByID(scanctx.Default().ID)
}

func normalizeContextID(id string) string {
	if strings.TrimSpace(id) == "" {
		return scanctx.Default().ID
	}
	return id
}

// heavyToolPatterns are commands that get extended timeouts.
var heavyToolPatterns = []string{
	"nmap", "nuclei", "ffuf", "gobuster", "dirsearch", "feroxbuster",
	"sqlmap", "masscan", "wpscan", "joomscan", "dalfox", "katana",
	"gospider", "subfinder", "amass", "rustscan", "httpx", "dnsx",
	"naabu", "tlsx", "mapcidr", "alterx", "asnmap", "uncover", "gau",
	"waybackurls", "hakrawler", "arjun", "paramspider", "dirb", "whatweb",
	"wafw00f",
}

// isHeavyTool returns true if the command involves a resource-intensive tool.
// Used for both timeout selection and resource throttling (Layer 2).
func isHeavyTool(command string) bool {
	lower := strings.ToLower(command)
	for _, tool := range heavyToolPatterns {
		if strings.Contains(lower, tool) {
			return true
		}
	}
	return false
}

// computeTimeout decides how long a command is allowed to run.
func computeTimeout(command string) time.Duration {
	if isHeavyTool(command) {
		return heavyCmdTimeout
	}
	return defaultCmdTimeout
}

// NormalizeCommandForRequestRatePolicy rewrites known scanner flags so terminal
// commands honor the effective per-scan request-rate policy. It is exported so
// callers can normalize before broadcasting the tool event, while runShellInternal
// calls it again as a defense in depth for direct terminal execution paths.
func NormalizeCommandForRequestRatePolicy(contextID string, command string) (string, string) {
	policy := requestRatePolicyForContext(contextID)
	if !policy.Enabled() {
		return command, ""
	}
	rewritten := rewriteCommandForRequestRatePolicy(command, policy)
	if rewritten == command {
		return command, ""
	}
	return rewritten, fmt.Sprintf("[RATE POLICY] Adjusted terminal command to honor max %s requests/sec (%s).\n", formatPolicyRPS(policy.MaxRPS), policy.Source)
}

func requestRatePolicyForContext(contextID string) scanctx.RequestRatePolicy {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil {
		if policy := sc.RequestRatePolicy(); policy.Enabled() {
			return policy
		}
	}
	if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
		return scanctx.NormalizeRequestRatePolicy(scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS, Source: "XALGORIX_RATE_RPS"})
	}
	return scanctx.RequestRatePolicy{}
}

func rewriteCommandForRequestRatePolicy(command string, policy scanctx.RequestRatePolicy) string {
	return rewriteShellSegments(command, func(segment string) string {
		return rewriteCommandSegmentForRequestRatePolicy(segment, policy)
	})
}

// dirbusterRuntimeCapSeconds bounds how long a single content-discovery tool may
// run before it is force-stopped. Kept below the default per-command timeout so
// a capped buster still leaves budget for the actual exploitation step.
const dirbusterRuntimeCapSeconds = 180

// CapDirbusterRuntime injects a hard runtime cap into directory/content
// brute-force tools when the model omits one. ffuf without -maxtime and
// feroxbuster without --time-limit routinely run until the full per-command
// timeout on CTF/real apps (few matches, so a piped `| head` never closes its
// side of the pipe), which repeatedly burned whole attempts and starved the
// real exploit (observed on the SQLi/method-tamper/traversal challenges). This
// is an ALWAYS-ON backstop — independent of the request-rate policy — for the
// prompt guidance the model sometimes ignores. It only ADDS a cap when none is
// present, so an explicit smaller bound the model set is preserved.
func CapDirbusterRuntime(command string) string {
	cap := strconv.Itoa(dirbusterRuntimeCapSeconds)
	return rewriteShellSegments(command, func(segment string) string {
		if hasToolCommand(segment, "ffuf") && !hasCommandFlag(segment, "-maxtime") {
			segment = appendCommandArg(segment, "-maxtime "+cap)
		}
		if hasToolCommand(segment, "feroxbuster") && !hasCommandFlag(segment, "--time-limit") {
			segment = appendCommandArg(segment, "--time-limit "+cap+"s")
		}
		if hasToolCommand(segment, "dirsearch") && !hasCommandFlag(segment, "--max-time") {
			segment = appendCommandArg(segment, "--max-time "+cap)
		}
		return segment
	})
}

// hasCommandFlag reports whether a flag (long or short) is already present in a
// command segment, matched as a whole token so -maxtime does not match e.g.
// -maxtime-job and --time-limit does not partial-match a longer flag.
func hasCommandFlag(command, flag string) bool {
	re := regexp.MustCompile(`(?i)(^|\s)` + regexp.QuoteMeta(flag) + `(?:=|\s|$)`)
	return re.FindStringIndex(command) != nil
}

func rewriteShellSegments(command string, rewrite func(string) string) string {
	var b strings.Builder
	start := 0
	var quote rune
	escaped := false
	i := 0
	for i < len(command) {
		r, size := utf8.DecodeRuneInString(command[i:])
		if escaped {
			escaped = false
			i += size
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			i += size
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			i += size
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			i += size
			continue
		}
		delimiterLen := 0
		if r == ';' || r == '|' {
			delimiterLen = 1
			if r == '|' && i+1 < len(command) && command[i+1] == '|' {
				delimiterLen = 2
			}
		} else if r == '&' && i+1 < len(command) && command[i+1] == '&' {
			delimiterLen = 2
		}
		if delimiterLen == 0 {
			i += size
			continue
		}
		b.WriteString(rewrite(command[start:i]))
		b.WriteString(command[i : i+delimiterLen])
		start = i + delimiterLen
		i = start
	}
	b.WriteString(rewrite(command[start:]))
	return b.String()
}

// rateExemptDiscoveryTools are subdomain-discovery / liveness-probing tools that
// are EXEMPT from the request-rate rewrite. They either hit third-party sources
// (passive subdomain enumeration) or fan out a single request across thousands
// of DISTINCT hosts (DNS resolution, HTTP liveness probing), so a global low-RPS
// cap cripples enumeration without protecting any single target. The rate policy
// exists to keep AGGRESSIVE testing of ONE host/app polite (nuclei, ffuf, nmap,
// masscan, naabu port scans, sqlmap) — not to throttle recon. Throttling httpx
// to ~10 rps is what made a wildcard scan of a huge target (e.g. att.com) find
// only a fraction of its live subdomains before the 30-min per-command kill.
var rateExemptDiscoveryTools = []string{
	"httpx", "dnsx", "subfinder", "assetfinder", "findomain", "amass",
	"puredns", "massdns", "shuffledns", "alterx", "chaos", "gau", "gauplus",
	"waybackurls", "github-subdomains", "dnsgen", "cero",
}

func rewriteCommandSegmentForRequestRatePolicy(segment string, policy scanctx.RequestRatePolicy) string {
	rps := policy.CommandRPS()
	if rps <= 0 {
		return segment
	}
	// Discovery / liveness tools run at full speed — the per-target rate cap
	// does not apply to recon that fans out across many hosts or third-party
	// sources. A command segment is a single piped stage (rewriteShellSegments
	// splits on ; | && ||), so this exempts e.g. the `httpx` stage of
	// `subfinder -d x | dnsx | httpx` while a later `nuclei` stage stays capped.
	for _, tool := range rateExemptDiscoveryTools {
		if hasToolCommand(segment, tool) {
			return segment
		}
	}
	rate := strconv.Itoa(rps)
	delay := formatPolicyDelay(policy)
	rewritten := segment

	if hasToolCommand(rewritten, "nuclei") {
		rewritten = setFlagValue(rewritten, []string{"-rl", "-rate-limit"}, rate)
		rewritten = capFlagValue(rewritten, []string{"-c"}, rate)
	}
	if hasToolCommand(rewritten, "nmap") {
		rewritten = removeFlagWithValue(rewritten, []string{"--min-rate", "--min-parallelism"})
		rewritten = replaceNmapTiming(rewritten)
		rewritten = ensureNmapTiming(rewritten)
		rewritten = setFlagValue(rewritten, []string{"--max-rate"}, rate)
		rewritten = setFlagValue(rewritten, []string{"--scan-delay"}, delay)
	}
	if hasToolCommand(rewritten, "masscan") {
		rewritten = setFlagValue(rewritten, []string{"--rate"}, rate)
	}
	if hasToolCommand(rewritten, "naabu") {
		rewritten = setFlagValue(rewritten, []string{"-rate"}, rate)
		rewritten = capFlagValue(rewritten, []string{"-c"}, rate)
	}
	// NOTE: httpx, dnsx, and subfinder are intentionally NOT throttled here —
	// they are handled by the rateExemptDiscoveryTools early-return above.
	if hasToolCommand(rewritten, "katana") {
		rewritten = setFlagValue(rewritten, []string{"-rl", "-rate-limit"}, rate)
		rewritten = capFlagValue(rewritten, []string{"-c"}, rate)
	}
	if hasToolCommand(rewritten, "ffuf") {
		rewritten = setFlagValue(rewritten, []string{"-rate"}, rate)
		rewritten = capFlagValue(rewritten, []string{"-t"}, rate)
	}
	if hasToolCommand(rewritten, "feroxbuster") {
		rewritten = setFlagValue(rewritten, []string{"--rate-limit"}, rate)
		rewritten = capFlagValue(rewritten, []string{"-t"}, rate)
	}
	if hasToolCommand(rewritten, "gobuster") {
		rewritten = setFlagValue(rewritten, []string{"--delay"}, delay)
		rewritten = setFlagValue(rewritten, []string{"-t"}, "1")
	}
	if hasToolCommand(rewritten, "xargs") {
		rewritten = setExistingShortFlagValue(rewritten, "-P", "1")
	}
	if hasToolCommand(rewritten, "parallel") {
		rewritten = setParallelJobs(rewritten, "1")
	}
	for _, tool := range []string{"gau", "hakrawler", "gospider", "arjun", "subjack"} {
		if hasToolCommand(rewritten, tool) {
			rewritten = capFlagValue(rewritten, []string{"--threads", "-threads", "-t", "--concurrent"}, rate)
		}
	}

	return rewritten
}

func hasToolCommand(segment, tool string) bool {
	re := regexp.MustCompile(`(?i)(^|[\s(])(?:sudo\s+)?` + regexp.QuoteMeta(tool) + `($|[\s])`)
	return re.FindStringIndex(segment) != nil
}

func replaceNmapTiming(command string) string {
	re := regexp.MustCompile(`(?i)(^|\s)-T[3-5]($|\s)`)
	return re.ReplaceAllString(command, "${1}-T2${2}")
}

func ensureNmapTiming(command string) string {
	re := regexp.MustCompile(`(?i)(^|\s)-T[0-5]($|\s)`)
	if re.FindStringIndex(command) != nil {
		return command
	}
	return appendCommandArg(command, "-T2")
}

func setFlagValue(command string, flags []string, value string) string {
	for _, flag := range flags {
		re := flagValueRegexp(flag)
		if re.FindStringIndex(command) != nil {
			return re.ReplaceAllString(command, "${1}"+flag+" "+value)
		}
	}
	return appendCommandArg(command, flags[0]+" "+value)
}

func setShortFlagValue(command string, flag string, value string) string {
	sticky := regexp.MustCompile(`(?i)(^|\s)` + regexp.QuoteMeta(flag) + `[0-9]+($|\s)`)
	if sticky.FindStringIndex(command) != nil {
		return sticky.ReplaceAllString(command, "${1}"+flag+" "+value+"${2}")
	}
	return setFlagValue(command, []string{flag}, value)
}

func setExistingShortFlagValue(command string, flag string, value string) string {
	sticky := regexp.MustCompile(`(?i)(^|\s)` + regexp.QuoteMeta(flag) + `[0-9]+($|\s)`)
	if sticky.FindStringIndex(command) != nil {
		return sticky.ReplaceAllString(command, "${1}"+flag+" "+value+"${2}")
	}
	re := flagValueRegexp(flag)
	if re.FindStringIndex(command) != nil {
		return re.ReplaceAllString(command, "${1}"+flag+" "+value)
	}
	return command
}

func setParallelJobs(command string, value string) string {
	if flagValueRegexp("--jobs").FindStringIndex(command) != nil {
		return setFlagValue(command, []string{"--jobs"}, value)
	}
	if regexp.MustCompile(`(?i)(^|\s)-j(?:[0-9]+|\s+[0-9]+)($|\s)`).FindStringIndex(command) != nil {
		return setShortFlagValue(command, "-j", value)
	}
	option := "--jobs " + value
	if idx := strings.Index(command, " :::"); idx >= 0 {
		head := strings.TrimRight(command[:idx], " \t")
		return head + " " + option + command[idx:]
	}
	return appendCommandArg(command, option)
}

func capFlagValue(command string, flags []string, maxValue string) string {
	maxInt, err := strconv.Atoi(maxValue)
	if err != nil || maxInt <= 0 {
		return setFlagValue(command, flags, maxValue)
	}
	for _, flag := range flags {
		re := flagValueRegexp(flag)
		match := re.FindStringSubmatch(command)
		if len(match) < 3 {
			continue
		}
		current, err := strconv.Atoi(match[2])
		if err == nil && current > 0 && current <= maxInt {
			return command
		}
		return re.ReplaceAllString(command, "${1}"+flag+" "+maxValue)
	}
	return appendCommandArg(command, flags[0]+" "+maxValue)
}

func removeFlagWithValue(command string, flags []string) string {
	for _, flag := range flags {
		re := flagValueRegexp(flag)
		command = re.ReplaceAllString(command, "$1")
	}
	return collapseCommandSpaces(command)
}

func flagValueRegexp(flag string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(^|\s)` + regexp.QuoteMeta(flag) + `(?:=|\s+)([^\s;&|]+)`)
}

func appendCommandArg(command string, arg string) string {
	trimmed := strings.TrimRight(command, " \t")
	trailing := command[len(trimmed):]
	if strings.TrimSpace(trimmed) == "" {
		return command
	}
	return trimmed + " " + arg + trailing
}

func collapseCommandSpaces(command string) string {
	return regexp.MustCompile(`[ \t]{2,}`).ReplaceAllString(command, " ")
}

func formatPolicyRPS(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(value, 'f', 3, 64), "0"), ".")
}

func formatPolicyDelay(policy scanctx.RequestRatePolicy) string {
	delay := policy.Delay()
	if delay <= 0 {
		return "0ms"
	}
	if delay%time.Second == 0 {
		return strconv.Itoa(int(delay/time.Second)) + "s"
	}
	return strconv.Itoa(int(delay/time.Millisecond)) + "ms"
}

type requestRateRuntime struct {
	BinDir     string
	PythonPath string
	LockDir    string
	DelayMS    int
}

func prepareRequestRateRuntime(workDir string, policy scanctx.RequestRatePolicy) (requestRateRuntime, error) {
	policy = scanctx.NormalizeRequestRatePolicy(policy)
	if !policy.Enabled() {
		return requestRateRuntime{}, nil
	}
	delayMS := int(policy.Delay() / time.Millisecond)
	if delayMS <= 0 {
		return requestRateRuntime{}, nil
	}

	root := filepath.Join(workDir, ".xalgorix-rate")
	rt := requestRateRuntime{
		BinDir:     filepath.Join(root, "bin"),
		PythonPath: filepath.Join(root, "python"),
		LockDir:    filepath.Join(root, "locks"),
		DelayMS:    delayMS,
	}
	for _, dir := range []string{rt.BinDir, rt.PythonPath, rt.LockDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return requestRateRuntime{}, err
		}
	}

	if err := writeRateLimitedBinaryWrapper(rt.BinDir, "curl"); err != nil {
		return requestRateRuntime{}, err
	}
	if err := writeRateLimitedBinaryWrapper(rt.BinDir, "wget"); err != nil {
		return requestRateRuntime{}, err
	}
	if err := writePythonRateLimiter(rt.PythonPath); err != nil {
		return requestRateRuntime{}, err
	}
	return rt, nil
}

func writeRateLimitedBinaryWrapper(binDir, name string) error {
	realPath, err := exec.LookPath(name)
	if err != nil || strings.HasPrefix(realPath, binDir+string(os.PathSeparator)) {
		return nil
	}
	wrapperPath := filepath.Join(binDir, name)
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
lock_dir="${XALGORIX_RATE_LOCK_DIR:-/tmp/xalgorix-rate}"
delay_ms="${XALGORIX_RATE_DELAY_MS:-0}"
mkdir -p "$lock_dir"
stamp="$lock_dir/last_request_ms"
lock="$lock_dir/request.lock"
rate_wait() {
  if [[ "$delay_ms" =~ ^[0-9]+$ ]] && (( delay_ms > 0 )); then
    now=$(date +%%s%%3N)
    last=0
    if [[ -r "$stamp" ]]; then
      read -r last < "$stamp" || last=0
    fi
    wait_ms=$(( last + delay_ms - now ))
    if (( wait_ms > 0 )); then
      sleep "$(awk "BEGIN { printf \"%%.3f\", $wait_ms / 1000 }")"
    fi
    date +%%s%%3N > "$stamp"
  fi
}
if command -v flock >/dev/null 2>&1; then
  { flock 9; rate_wait; } 9>"$lock"
else
  rate_wait
fi
exec %s "$@"
`, shellQuote(realPath))
	// The wrapper must be executable by the agent's subprocesses, so 0755
	// is intentional; it contains no secrets (a rate-limiting shim around
	// curl/wget).
	return os.WriteFile(wrapperPath, []byte(script), 0o755) //nolint:gosec // G306: generated executable wrapper needs exec bit
}

func writePythonRateLimiter(pythonPath string) error {
	siteCustomize := filepath.Join(pythonPath, "sitecustomize.py")
	source := `import functools
import os
import time

try:
    import fcntl
except Exception:
    fcntl = None

_delay_ms = int(os.environ.get("XALGORIX_RATE_DELAY_MS", "0") or "0")
_lock_dir = os.environ.get("XALGORIX_RATE_LOCK_DIR", "/tmp/xalgorix-rate")
_patched = {}


def _wait():
    if _delay_ms <= 0:
        return
    os.makedirs(_lock_dir, exist_ok=True)
    lock_path = os.path.join(_lock_dir, "request.lock")
    stamp_path = os.path.join(_lock_dir, "last_request_ms")
    with open(lock_path, "a+") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            now = int(time.time() * 1000)
            last = 0
            try:
                with open(stamp_path, "r") as stamp:
                    last = int((stamp.read() or "0").strip() or "0")
            except Exception:
                last = 0
            wait_ms = last + _delay_ms - now
            if wait_ms > 0:
                time.sleep(wait_ms / 1000.0)
            with open(stamp_path, "w") as stamp:
                stamp.write(str(int(time.time() * 1000)))
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _patch(obj, attr, async_func=False):
    key = (id(obj), attr)
    if key in _patched:
        return
    original = getattr(obj, attr, None)
    if original is None:
        return
    if async_func:
        @functools.wraps(original)
        async def async_wrapper(*args, **kwargs):
            _wait()
            return await original(*args, **kwargs)
        setattr(obj, attr, async_wrapper)
    else:
        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            _wait()
            return original(*args, **kwargs)
        setattr(obj, attr, wrapper)
    _patched[key] = True


try:
    import http.client
    _patch(http.client.HTTPConnection, "request")
    _patch(http.client.HTTPSConnection, "request")
except Exception:
    pass

try:
    import urllib.request
    _patch(urllib.request, "urlopen")
except Exception:
    pass

try:
    import requests
    _patch(requests.sessions.Session, "request")
except Exception:
    pass

try:
    import httpx
    _patch(httpx.Client, "request")
    _patch(httpx.AsyncClient, "request", async_func=True)
except Exception:
    pass

try:
    import aiohttp
    _patch(aiohttp.ClientSession, "_request", async_func=True)
except Exception:
    pass
`
	return os.WriteFile(siteCustomize, []byte(source), 0o600)
}

// setProcessLimits applies resource constraints to a child process:
// - Adjusts OOM score so the kernel kills scan tools before xalgorix
// - Sets RLIMIT_AS (virtual memory limit) when memoryLimited is true
func setProcessLimits(cmd *exec.Cmd, memoryLimited bool, memLimitBytes int64) {
	if cmd.Process == nil {
		return
	}
	setProcessLimitsForPID(cmd.Process.Pid, memoryLimited, memLimitBytes)
}

// ApplyProcessLimits applies the same child-process protections used by
// terminal_execute to subprocess-based tools in other packages.
func ApplyProcessLimits(cmd *exec.Cmd, memoryLimited bool) {
	setProcessLimits(cmd, memoryLimited, resources.CurrentToolMemoryLimitBytes(false))
}

// ApplyProcessLimitsWithLimit applies child-process protections using an
// already-reserved resource lease memory limit.
func ApplyProcessLimitsWithLimit(cmd *exec.Cmd, memoryLimited bool, memLimitBytes int64) {
	setProcessLimits(cmd, memoryLimited, memLimitBytes)
}

// ApplyProcessLimitsToPID is the PID-based companion to
// ApplyProcessLimitsWithLimit. It is intended for tools that spawn their
// child process outside of os/exec (e.g. go-rod's Launcher, which manages
// the Chromium subprocess internally and exposes only Launcher.PID()).
// Call this immediately after the launcher reports a non-zero PID so the
// kernel-side OOM and RLIMIT_AS protections track the lease's memory
// ceiling for the whole Chromium process tree.
func ApplyProcessLimitsToPID(pid int, memoryLimited bool, memLimitBytes int64) {
	setProcessLimitsForPID(pid, memoryLimited, memLimitBytes)
}

// ActiveProcessCount returns the number of currently running processes.
func ActiveProcessCount() int {
	return ActiveProcessCountForContext(scanctx.Default().ID)
}

// ActiveProcessCountForContext returns the number of running processes for one context.
func ActiveProcessCountForContext(contextID string) int {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		return sc.Terminal.ActiveProcessCount()
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.processGroup)
}

// GetActiveCommand returns the currently running command and how long it's been running.
func GetActiveCommand() (string, time.Duration) {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeCommand == "" {
		return "", 0
	}
	return s.activeCommand, time.Since(s.activeStartTime)
}

// GetActiveCommandStartTime returns the start time of the active command.
func GetActiveCommandStartTime() time.Time {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeStartTime
}

// TrackProcess registers a command to be tracked by the watchdog and killed on Stop.
func TrackProcess(cmd *exec.Cmd, cancel context.CancelFunc, commandStr string) {
	TrackProcessForContext(scanctx.Default().ID, cmd, cancel, commandStr)
}

// TrackProcessForContext registers a command against a specific scan context.
func TrackProcessForContext(contextID string, cmd *exec.Cmd, cancel context.CancelFunc, commandStr string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	s.processGroup[cmd] = cancel
	if len(commandStr) > 200 {
		s.activeCommand = commandStr[:200] + "..."
	} else {
		s.activeCommand = commandStr
	}
	s.activeStartTime = time.Now()
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.TrackProcess(cmd, cancel, commandStr)
	}
}

// UntrackProcess removes a command from tracking once it completes.
func UntrackProcess(cmd *exec.Cmd) {
	UntrackProcessForContext(scanctx.Default().ID, cmd)
}

// UntrackProcessForContext removes a command from a specific scan context.
func UntrackProcessForContext(contextID string, cmd *exec.Cmd) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	delete(s.processGroup, cmd)
	if len(s.processGroup) == 0 {
		s.activeCommand = ""
	}
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.UntrackProcess(cmd)
	}
}

// ReapDeadProcesses checks all tracked processes and removes any that have
// already exited.
func ReapDeadProcesses() int {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()

	reaped := 0
	for cmd, cancel := range s.processGroup {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			log.Printf("[REAP] Removing dead process from tracker: pid=%d", cmd.Process.Pid)
			delete(s.processGroup, cmd)
			if cancel != nil {
				cancel()
			}
			reaped++
		}
	}

	if reaped > 0 && len(s.processGroup) == 0 {
		s.activeCommand = ""
	}
	return reaped
}

// SetStreamCallback sets a callback that receives partial output from running commands.
func SetStreamCallback(cb func(partialOutput string)) {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamCallback = cb
}

// ClearStreamCallback removes the stream callback.
func ClearStreamCallback() {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamCallback = nil
}

func streamCallbackForContext(contextID string) func(string) {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		if cb := sc.Terminal.GetStreamCallback(); cb != nil {
			return cb
		}
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamCallback
}

// KillAllProcesses kills all running processes for the active scan context.
func KillAllProcesses() {
	KillAllProcessesForContext(scanctx.Default().ID)
}

// KillAllProcessesForContext kills all processes for one scan context.
func KillAllProcessesForContext(contextID string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	for cmd, cancel := range s.processGroup {
		killTrackedProcess(cmd)
		if cancel != nil {
			cancel()
		}
	}
	s.processGroup = make(map[*exec.Cmd]context.CancelFunc)
	s.activeCommand = ""
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.KillAll()
	}
}

func killTrackedProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	pid := cmd.Process.Pid
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 0 {
		selfPGID, selfErr := syscall.Getpgid(os.Getpid())
		if selfErr != nil || pgid != selfPGID {
			if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				log.Printf("[terminal] Failed to kill process group %d for pid %d: %v", pgid, pid, err)
			}
		} else {
			log.Printf("[terminal] Refusing to kill process group %d for pid %d because it matches xalgorix", pgid, pid)
		}
	}

	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		log.Printf("[terminal] Failed to kill process pid %d: %v", pid, err)
	}
}

// SetWorkDir sets the working directory for terminal commands.
func SetWorkDir(dir string) {
	SetWorkDirForContext(scanctx.Default().ID, dir)
}

// SetWorkDirForContext sets the working directory for one scan context.
func SetWorkDirForContext(contextID, dir string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	s.workDir = dir
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.SetWorkDir(dir)
	}
}

// GetWorkDir returns the current working directory.
func GetWorkDir() string {
	return GetWorkDirForContext(scanctx.Default().ID)
}

// GetWorkDirForContext returns the current working directory for one scan context.
func GetWorkDirForContext(contextID string) string {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		if wd := sc.Terminal.GetWorkDir(); wd != "" {
			return wd
		}
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workDir
}

// CleanupContext removes the terminal store for a deactivated context.
func CleanupContext(contextID string) {
	KillAllProcessesForContext(contextID)
	termStoresMu.Lock()
	defer termStoresMu.Unlock()
	delete(termStores, contextID)
}

// Common command → package mappings for auto-install.
var packageMap = map[string]string{
	// DNS & networking
	"nslookup":   "dnsutils",
	"dig":        "dnsutils",
	"host":       "dnsutils",
	"whois":      "whois",
	"traceroute": "traceroute",
	"ping":       "iputils-ping",
	"nmap":       "nmap",
	"netcat":     "ncat",
	"nc":         "ncat",
	"socat":      "socat",
	"tcpdump":    "tcpdump",
	"ss":         "iproute2",
	"ip":         "iproute2",
	"arp":        "net-tools",
	"ifconfig":   "net-tools",
	"netstat":    "net-tools",
	// Web / HTTP
	"curl":   "curl",
	"wget":   "wget",
	"httpie": "httpie",
	"http":   "httpie",
	// SSL/TLS
	"openssl": "openssl",
	// Recon / enumeration (Go tools — resolved to go install in installPackage)
	"dirb":        "dirb",
	"gobuster":    "gobuster",
	"ffuf":        "ffuf",
	"subfinder":   "subfinder",
	"assetfinder": "assetfinder",
	"masscan":     "masscan",
	"wfuzz":       "wfuzz",
	"httpx":       "httpx",
	"dnsx":        "dnsx",
	"nuclei":      "nuclei",
	"katana":      "katana",
	"gospider":    "gospider",
	"gau":         "gau",
	"waybackurls": "waybackurls",
	"hakrawler":   "hakrawler",
	"naabu":       "naabu",
	"dalfox":      "dalfox",
	"paramspider": "paramspider",
	"feroxbuster": "feroxbuster",
	// Findomain — Rust binary, installed via package manager or cargo
	"findomain": "findomain",
	// Parameter discovery — arjun/uro are Python (pipx), x8 is Rust (cargo)
	"arjun": "arjun",
	"uro":   "uro",
	"x8":    "x8",
	// Text processing
	"jq":        "jq",
	"xmllint":   "libxml2-utils",
	"html2text": "html2text",
	// Git
	"git": "git",
	// Python
	"python3":     "python3",
	"pip3":        "python3-pip",
	"pip":         "python3-pip",
	"scrapling":   "scrapling", // Handled by pipx in installPackage
	"python-venv": "python3-venv",
	// General
	"tree":    "tree",
	"unzip":   "unzip",
	"zip":     "zip",
	"file":    "file",
	"strings": "binutils",
	"xxd":     "xxd",
	"base64":  "coreutils",
	"awk":     "gawk",
	"sed":     "sed",
	"grep":    "grep",
	"find":    "findutils",
	"xargs":   "findutils",
	"bc":      "bc",
	// SQL
	"sqlmap": "sqlmap",

	// ── Extended coverage for docs/tools.md ─────────────────────────
	// Go tools — routed to `go install` via goTools in installPackage.
	"shuffledns": "shuffledns",
	"gosec":      "gosec",
	"subjack":    "subjack",
	"gitleaks":   "gitleaks",
	"unfurl":     "unfurl",
	"gron":       "gron",
	"httprobe":   "httprobe",
	// Python tools — routed to pipx/pip via pipxTools.
	"semgrep":    "semgrep",
	"bandit":     "bandit",
	"git-dumper": "git-dumper",
	// Ruby tool — routed to gem via gemTools.
	"brakeman": "brakeman",
	// Distro packages (apt). gh needs GitHub's apt repo (added in the Dockerfile).
	"dirsearch": "dirsearch",
	"gh":        "gh",
}

// decode decodes a base64 string
func decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// decodeHex decodes a hex string
func decodeHex(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

// Register adds terminal tools to the registry.
// The registry is captured in the closure so tool execution resolves the correct
// per-session terminal store via registry.GetScanContextID().
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "terminal_execute",
		Description: "Execute a shell command in the terminal. Returns stdout, stderr, and exit code. Automatically installs missing tools. Commands have a 10-minute timeout by default (30 minutes for heavy tools like nmap/nuclei). Use targeted scans to stay within limits.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "The shell command to execute", Required: true},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executeCommandForRegistry(r, args)
		},
	})
}

// toolExists checks if a tool is available in the expanded PATH
// (same directories as runShell uses). This is more reliable than
// exec.LookPath which only searches the Go process's own PATH.
func toolExists(name string) bool {
	// First try the standard PATH
	if _, err := exec.LookPath(name); err == nil {
		return true
	}

	// Then check expanded locations that runShell adds
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = homeDir + "/go"
	}

	extraDirs := []string{
		goPath + "/bin",
		homeDir + "/go/bin",
		homeDir + "/.local/bin",
		homeDir + "/.cargo/bin",
		"/usr/local/bin",
		"/snap/bin",
	}

	for _, dir := range extraDirs {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// executeCommandForRegistry resolves the correct terminal store via the registry's ScanContextID.
func executeCommandForRegistry(reg *tools.Registry, args map[string]string) (tools.Result, error) {
	return executeCommandWithContextID(reg.GetScanContextID(), args)
}

// executeCommand is the backward-compatible version using scanctx.Default().
//
//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func executeCommand(args map[string]string) (tools.Result, error) {
	return executeCommandWithContextID(scanctx.Default().ID, args)
}

func executeCommandWithContextID(contextID string, args map[string]string) (tools.Result, error) {
	command := args["command"]
	if command == "" {
		return tools.Result{}, fmt.Errorf("command is required")
	}

	// Block destructive commands
	if reason := isBlockedCommand(command); reason != "" {
		return tools.Result{Output: fmt.Sprintf("[BLOCKED] Destructive command rejected: %s. Xalgorix is read-only — it tests for vulnerabilities without causing damage.", reason)}, nil
	}

	// Pre-check: install missing tools BEFORE running the command.
	// Use the same expanded PATH as runShell so we find tools in ~/.cargo/bin, ~/go/bin, etc.
	var preInstalled []string
	toolsToCheck := extractCommands(command)
	for _, tool := range toolsToCheck {
		if !toolExists(tool) {
			pkg := resolvePackage(tool)
			if pkg != "" {
				installPackage(pkg)
				preInstalled = append(preInstalled, tool)
			}
		}
	}

	// Run the command using the correct context's store
	output, exitCode := runShellWithContext(contextID, command)

	// If it still fails with "command not found", try one more install+retry.
	// This catches tools not in extractCommands' list (e.g. piped commands).
	if exitCode == 127 || isCommandNotFound(output) {
		missingCmd := extractMissingCommand(output)
		if missingCmd != "" {
			pkg := resolvePackage(missingCmd)
			if pkg != "" {
				installOutput := installPackage(pkg)
				retryOutput, retryExit := runShellWithContext(contextID, command)
				combined := fmt.Sprintf("[auto-installed %s (%s)]\n%s\n%s",
					missingCmd, pkg, installOutput, retryOutput)
				if retryExit != 0 {
					combined += fmt.Sprintf("\n[exit code: %d]", retryExit)
				}
				return tools.Result{Output: combined}, nil
			}
		}
	}

	// Prepend install info if we installed anything
	if len(preInstalled) > 0 {
		output = fmt.Sprintf("[pre-installed: %s]\n%s", strings.Join(preInstalled, ", "), output)
	}

	return tools.Result{Output: output}, nil
}

func ensureVenv() {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	venvPath := filepath.Join(homeDir, "venv")

	// Check if venv exists
	if _, err := os.Stat(venvPath); os.IsNotExist(err) {
		// Create venv
		fmt.Println("Creating Python virtual environment at ~/venv...")
		cmd := exec.Command("python3", "-m", "venv", venvPath)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to create Python venv at %s: %v", venvPath, err)
		}
	}
}

// runShellWithContext executes a shell command using the terminal store for the
// given context ID. This ensures streaming callbacks and process tracking are
// routed through the correct per-session store instead of the global default.
func runShellWithContext(contextID string, command string) (string, int) {
	return runShellInternal(contextID, command)
}

//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func runShell(command string) (string, int) {
	return runShellInternal(scanctx.Default().ID, command)
}

func commandWaitContext(contextID string) context.Context {
	if sc := scanctx.Get(contextID); sc != nil && sc.Ctx != nil {
		return sc.Ctx
	}
	return context.Background()
}

// effectiveWorkDirForContext resolves the working directory for a terminal
// command. Resolution order (R8.6, R8.10):
//
//  1. an explicitly set per-context Terminal workdir (sc.Terminal.GetWorkDir()
//     or the package-level termStore.workDir),
//  2. the active Scan_Context's ScanDir,
//  3. cfg.WorkspaceRoot (= Data_Dir),
//  4. /tmp/xalgorix-workspace as a last-resort sentinel.
//
// $CWD is intentionally NOT consulted: the previous os.Getwd() fallback was
// the source of the workspace-leak bug where running xalgorix from a source
// tree caused tmp/, .cache/, .config/, .local/share/ to be created in that
// tree by prepareCommandWorkspace. Falling back to WorkspaceRoot keeps the
// resolution rooted inside the Allow_List even if every higher-priority
// source is empty.
func effectiveWorkDirForContext(contextID string, cfg *config.Config) string {
	workDir := strings.TrimSpace(GetWorkDirForContext(contextID))
	if workDir == "" {
		if sc := scanctx.Get(contextID); sc != nil {
			workDir = strings.TrimSpace(sc.ScanDir)
		}
	}
	if workDir == "" && cfg != nil {
		// Prefer WorkspaceRoot (the explicit Data_Dir resolution root) over
		// the legacy Workspace alias so a future divergence stays correct.
		workDir = strings.TrimSpace(cfg.WorkspaceRoot)
		if workDir == "" {
			workDir = strings.TrimSpace(cfg.Workspace)
		}
	}
	if workDir == "" {
		workDir = "/tmp/xalgorix-workspace"
	}
	if !filepath.IsAbs(workDir) {
		if abs, err := filepath.Abs(workDir); err == nil {
			workDir = abs
		}
	}
	return filepath.Clean(workDir)
}

// prepareCommandWorkspace creates the per-command workspace skeleton
// (`tmp/`, `.cache/`, `.config/`, `.local/share/`) under workDir.
//
// Callers MUST pass a workDir resolved through effectiveWorkDirForContext so
// the directories land under sc.ScanDir (when a Scan_Context is active) or
// cfg.WorkspaceRoot (= Data_Dir) otherwise — never under $CWD (R8.6, R8.10).
// This is the workspace-leak fix paired with the env-var routing in
// commandEnv (R8.9).
func prepareCommandWorkspace(workDir string) error {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	for _, dir := range []string{
		filepath.Join(workDir, "tmp"),
		filepath.Join(workDir, ".cache"),
		filepath.Join(workDir, ".config"),
		filepath.Join(workDir, ".local", "share"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// commandEnv builds the environment for the terminal child process. Every
// path-flavored variable (HOME, TMPDIR, XDG_CACHE_HOME, XDG_CONFIG_HOME,
// XDG_DATA_HOME, XALGORIX_WORKSPACE) is rooted at workDir, which the caller
// resolved via effectiveWorkDirForContext. This is the terminal counterpart
// of pythonWorkspaceEnv and satisfies R8.9 / R8.10 — XDG_* and TMPDIR for
// every spawned terminal command stay inside sc.ScanDir (or
// cfg.WorkspaceRoot when no Scan_Context is active), never $CWD.
func commandEnv(homeDir, goPath, workDir string, rateRuntime requestRateRuntime) []string {
	dynamicPath := goPath + "/bin:" + homeDir + "/go/bin:" + homeDir + "/.local/bin"
	dynamicPath += ":" + homeDir + "/.cargo/bin"
	dynamicPath += ":/usr/local/bin:/snap/bin"
	if rateRuntime.BinDir != "" {
		dynamicPath = rateRuntime.BinDir + ":" + dynamicPath
	}

	replace := map[string]bool{
		"PATH":                   true,
		"GOPATH":                 true,
		"HOME":                   true,
		"TMPDIR":                 true,
		"XDG_CACHE_HOME":         true,
		"XDG_CONFIG_HOME":        true,
		"XDG_DATA_HOME":          true,
		"XALGORIX_WORKSPACE":     true,
		"PYTHONPATH":             true,
		"XALGORIX_RATE_LOCK_DIR": true,
		"XALGORIX_RATE_DELAY_MS": true,
	}
	env := make([]string, 0, len(os.Environ())+8)
	existingPythonPath := os.Getenv("PYTHONPATH")
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && replace[key] {
			continue
		}
		env = append(env, kv)
	}

	env = append(env,
		"PATH="+dynamicPath+":"+os.Getenv("PATH"),
		"GOPATH="+goPath,
		"HOME="+workDir,
		"TMPDIR="+filepath.Join(workDir, "tmp"),
		"XDG_CACHE_HOME="+filepath.Join(workDir, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(workDir, ".config"),
		"XDG_DATA_HOME="+filepath.Join(workDir, ".local", "share"),
		"XALGORIX_WORKSPACE="+workDir,
	)
	if rateRuntime.PythonPath != "" {
		pythonPath := rateRuntime.PythonPath
		if existingPythonPath != "" {
			pythonPath += ":" + existingPythonPath
		}
		env = append(env,
			"PYTHONPATH="+pythonPath,
			"XALGORIX_RATE_LOCK_DIR="+rateRuntime.LockDir,
			"XALGORIX_RATE_DELAY_MS="+strconv.Itoa(rateRuntime.DelayMS),
		)
	} else if existingPythonPath != "" {
		env = append(env, "PYTHONPATH="+existingPythonPath)
	}
	return env
}

func shellPrelude(homeDir, workDir string, memLimitBytes int64) string {
	var b strings.Builder
	if memLimitBytes > 0 {
		limitKB := memLimitBytes / 1024
		fmt.Fprintf(&b, "ulimit -Sv %d 2>/dev/null || true\n", limitKB)
		fmt.Fprintf(&b, "ulimit -Hv %d 2>/dev/null || true\n", limitKB)
	}
	fmt.Fprintf(&b, "export HOME=%s\n", shellQuote(workDir))
	fmt.Fprintf(&b, "export TMPDIR=%s\n", shellQuote(filepath.Join(workDir, "tmp")))
	fmt.Fprintf(&b, "export XDG_CACHE_HOME=%s\n", shellQuote(filepath.Join(workDir, ".cache")))
	fmt.Fprintf(&b, "export XDG_CONFIG_HOME=%s\n", shellQuote(filepath.Join(workDir, ".config")))
	fmt.Fprintf(&b, "export XDG_DATA_HOME=%s\n", shellQuote(filepath.Join(workDir, ".local", "share")))
	fmt.Fprintf(&b, "export XALGORIX_WORKSPACE=%s\n", shellQuote(workDir))
	b.WriteString(`__xalgorix_workspace="$(pwd -P)"
__xalgorix_resolve_path() {
  realpath -m "$1" 2>/dev/null || readlink -m "$1" 2>/dev/null || printf '%s\n' "$1"
}
cd() {
  local dest target resolved before after
  if [ "$#" -eq 0 ]; then
    dest="$__xalgorix_workspace"
  else
    dest="$1"
  fi
  if [ "$dest" = "-" ]; then
    before="$PWD"
    builtin cd - >/dev/null || return
    after="$(pwd -P)"
    case "$after" in
      "$__xalgorix_workspace"|"$__xalgorix_workspace"/*) pwd; return ;;
      *) builtin cd "$before"; printf '[WORKSPACE GUARD] cd outside scan workspace blocked: %s\n' "$dest" >&2; return 1 ;;
    esac
  fi
  case "$dest" in
    "~") target="$__xalgorix_workspace" ;;
    "~/"*) target="$__xalgorix_workspace/${dest#~/}" ;;
    /*) target="$dest" ;;
    *) target="$PWD/$dest" ;;
  esac
  resolved="$(__xalgorix_resolve_path "$target")"
  case "$resolved" in
    "$__xalgorix_workspace"|"$__xalgorix_workspace"/*) builtin cd "$resolved" ;;
    *) printf '[WORKSPACE GUARD] cd outside scan workspace blocked: %s\n' "$dest" >&2; return 1 ;;
  esac
}
`)
	fmt.Fprintf(&b, "source %s 2>/dev/null || true\n", shellQuote(filepath.Join(homeDir, "venv", "bin", "activate")))
	return b.String()
}

func runShellInternal(contextID string, command string) (string, int) {
	contextID = normalizeContextID(contextID)
	// Ensure venv exists
	ensureVenv()

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	// Compute timeout based on command type
	cleanCmd, ratePolicyNotice := NormalizeCommandForRequestRatePolicy(contextID, command)
	cleanCmd = InjectScanHeadersIntoCommand(cleanCmd)

	cfg := config.Get()
	workDir := effectiveWorkDirForContext(contextID, cfg)
	if err := prepareCommandWorkspace(workDir); err != nil {
		return fmt.Sprintf("Failed to prepare command workspace %s: %v", workDir, err), -1
	}
	wordlistCmd, wordlistNotice, wordlistErr := normalizeCommandWordlists(cleanCmd, workDir)
	if wordlistErr != nil {
		return ratePolicyNotice + fmt.Sprintf("[WORDLIST] Could not prepare a portable wordlist: %v", wordlistErr), -1
	}
	cleanCmd = wordlistCmd
	commandNotice := ratePolicyNotice + wordlistNotice
	timeout := computeTimeout(cleanCmd)
	if timeout > hardMaxTimeout {
		timeout = hardMaxTimeout
	}
	rateRuntime, err := prepareRequestRateRuntime(workDir, requestRatePolicyForContext(contextID))
	if err != nil {
		return commandNotice + fmt.Sprintf("Failed to prepare request-rate runtime %s: %v", workDir, err), -1
	}

	// Set PATH to include common tool locations (dynamic - works for any user)
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = homeDir + "/go"
	}
	// ── Layer 2: Pre-exec resource throttle ──
	// Before launching, check if the system has enough resources.
	// Heavy tools (nuclei, masscan, etc.) are gated more strictly.
	// Under pressure, commands wait here instead of returning a fake failure
	// to the agent. The command runtime timeout starts only after launch.
	heavy := isHeavyTool(cleanCmd)
	toolLabel := resources.ToolLogLabel(cleanCmd)
	waitCtx := commandWaitContext(contextID)
	lease, err := resources.AcquireToolLeaseContext(waitCtx, heavy, toolLabel)
	if err != nil {
		return commandNotice + fmt.Sprintf("[CANCELED] Tool launch canceled before starting %q: %v", toolLabel, err), -1
	}
	defer lease.Release()
	memLimitBytes := lease.MemoryLimitBytes()

	command = shellPrelude(homeDir, workDir, memLimitBytes) + cleanCmd

	ctx, cancel := context.WithTimeout(waitCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
	cmd.Env = commandEnv(homeDir, goPath, workDir, rateRuntime)

	// Create new process group for this command so we can kill the
	// entire tree (bash + children like curl) on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Kill the entire process group on context cancellation/timeout.
	// exec.CommandContext only sends SIGKILL to the parent bash process,
	// but child processes (curl, for loops, etc.) in the new process group
	// survive as orphans, keeping stdout/stderr pipes open. This causes
	// wg.Wait() to block until the watchdog's 30-minute kill.
	// Fix: use cmd.Cancel to send SIGKILL to the negative PGID, which
	// kills the entire tree and closes all pipe write ends.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Kill entire process group: negative PID = process group
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return os.ErrProcessDone
	}

	// Use pipes for real-time output streaming
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return commandNotice + fmt.Sprintf("Failed to create stdout pipe: %v", err), -1
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return commandNotice + fmt.Sprintf("Failed to create stderr pipe: %v", err), -1
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return commandNotice + fmt.Sprintf("Failed to start command: %v", err), -1
	}

	// ── Layer 3: Post-start process limits ──
	// Set OOM score and a per-process memory limit on the shell and children.
	setProcessLimits(cmd, true, memLimitBytes)

	TrackProcessForContext(contextID, cmd, cancel, cleanCmd)
	defer UntrackProcessForContext(contextID, cmd)

	// Read output in goroutines with periodic streaming.
	// Captured output is bounded at 1 MiB stdout / 512 KiB stderr by
	// iolimit.LimitedBuffer; bytes past the limit are silently dropped and
	// surfaced via Truncated() markers in the assembled result.
	stdout, stderr := iolimit.NewLimited(1<<20, 1<<19)
	var wg sync.WaitGroup

	// Stream stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		lastStream := time.Now()
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				_, _ = stdout.Write(buf[:n])

				// Stream partial output every 10 seconds.
				cb := streamCallbackForContext(contextID)
				if cb != nil && time.Since(lastStream) > 10*time.Second {
					out := stdout.String()
					if len(out) > 2000 {
						out = "...\n" + out[len(out)-2000:]
					}
					cb(out)
					lastStream = time.Now()
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream stderr (also capped)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				_, _ = stderr.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for output readers to finish, then the process.
	// IMPORTANT: wg.Wait() MUST run before cmd.Wait(). The Go docs say
	// "it is incorrect to call Wait before all reads from the pipe have
	// completed" when using StdoutPipe — calling cmd.Wait() first would
	// close the pipes and lose buffered data.
	//
	// On timeout: cmd.Cancel kills the entire process group (SIGKILL to
	// -PGID), which closes all pipe write ends, causing the goroutines
	// to get EOF → wg.Wait() returns → cmd.Wait() runs.
	wg.Wait()
	err = cmd.Wait()
	// Note: process unregistration is handled by defer UntrackProcess(cmd) above

	stdoutStr := stdout.String()
	if stdout.Truncated() {
		stdoutStr += "\n[output truncated at 1 MiB]"
	}
	stderrStr := stderr.String()
	if stderr.Truncated() {
		stderrStr += "\n[stderr truncated at 512 KiB]"
	}

	exitCode := 0
	if err != nil {
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			// Command was killed by timeout
			return commandNotice + fmt.Sprintf("[TIMEOUT] Command killed after %s. Use more targeted scans (fewer ports, specific paths, smaller scope) to stay within the time limit.\nPartial stdout:\n%s\nPartial stderr:\n%s",
				timeout.Round(time.Second), truncate(stdoutStr), truncate(stderrStr)), -1
		} else if ctx.Err() == context.Canceled {
			// Context was canceled (Stop or watchdog kill)
			return commandNotice + fmt.Sprintf("Command canceled.\nPartial stdout:\n%s\nPartial stderr:\n%s",
				truncate(stdoutStr), truncate(stderrStr)), -1
		}
	}

	return commandNotice + formatOutput(stdoutStr, stderrStr, exitCode), exitCode
}

func isCommandNotFound(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "command not found") ||
		strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "not found in") ||
		strings.Contains(lower, ": not found")
}

func extractMissingCommand(output string) string {
	// Patterns: "bash: line N: <cmd>: command not found"
	//           "<cmd>: command not found"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "command not found") || strings.Contains(lower, ": not found") {
			// Extract the command name — typically the word before ": command not found"
			parts := strings.Split(line, ":")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				// Skip "bash", "line N", "STDERR", etc.
				if p != "" && !strings.HasPrefix(p, "bash") &&
					!strings.HasPrefix(p, "line ") &&
					!strings.HasPrefix(p, "STDERR") &&
					!strings.Contains(p, "command not found") &&
					!strings.Contains(p, "not found") &&
					!strings.HasPrefix(p, "/") {
					// Clean up — take last word (handles paths)
					words := strings.Fields(p)
					if len(words) > 0 {
						cmd := words[len(words)-1]
						// Validate it looks like a command
						if len(cmd) > 0 && len(cmd) < 50 && !strings.ContainsAny(cmd, " \t(){}[]") {
							return cmd
						}
					}
				}
			}
		}
	}
	return ""
}

func resolvePackage(cmd string) string {
	// Check our built-in map first
	if pkg, ok := packageMap[cmd]; ok {
		return pkg
	}
	// Don't blindly fall back — only return if we know the package
	return ""
}

// sudoPrefix returns "sudo " when the process is non-root AND the operator
// has explicitly opted in via XALGORIX_AUTO_INSTALL_SUDO=1. The previous
// behavior was to silently sudo any install attempt, which is a privilege
// escalation surface when xalgorix is launched by a user with passwordless
// sudo (which the --start systemd flow encourages).
func sudoPrefix() string {
	if os.Getuid() == 0 {
		return ""
	}
	if cfg := config.Get(); cfg.AllowAutoInstallSudo {
		return "sudo "
	}
	return ""
}

// aptListsRefreshed gates `apt-get update` so it runs at most once per
// process. Container and minimal images routinely ship with
// /var/lib/apt/lists wiped, so the first apt install in a session would
// otherwise fail with "Unable to locate package" until the index is
// refreshed. Without this guard, an agent command installing N missing apt
// tools (e.g. `httpx | jq | html2text`) triggered N sequential full-mirror
// `apt-get update` round-trips. Once one update has run, subsequent installs
// reuse the now-populated lists. The empty-lists check makes the refresh a
// true no-op on systems that already carry fresh lists.
var (
	aptListsMu        sync.Mutex
	aptListsRefreshed bool
)

// maybeRefreshAptLists runs `apt-get update` once per process, and only when
// the package lists look empty/stale. It returns the combined output (for
// diagnostics) and is a no-op on non-apt systems or after the first success.
func maybeRefreshAptLists() string {
	aptListsMu.Lock()
	defer aptListsMu.Unlock()
	if aptListsRefreshed {
		return ""
	}
	aptListsRefreshed = true // mark first regardless of outcome so a failing mirror doesn't retry forever
	if _, err := exec.LookPath("apt-get"); err != nil {
		return ""
	}
	// Skip the network round-trip entirely when the lists dir already
	// contains index files (host system, or an image that kept them).
	if entries, err := os.ReadDir("/var/lib/apt/lists"); err == nil {
		hasIndex := false
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "_Packages") || strings.HasSuffix(e.Name(), "_InRelease") {
				hasIndex = true
				break
			}
		}
		if hasIndex {
			return ""
		}
	}
	// Plain `apt-get update` (no -qq): the output is captured and surfaced
	// to the LLM on failure, so suppressing diagnostics here would hide the
	// mirror-unreachable vs. package-absent distinction needed to debug.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "bash", "-c", sudoPrefix()+"apt-get update 2>&1").CombinedOutput()
	return string(out)
}

// installPackage installs a system package on demand. Gated behind
// XALGORIX_ALLOW_AUTO_INSTALL — defaults to true for root and false for
// non-root, so a stock unprivileged xalgorix invocation can never call
// apt-get/cargo/npm to install software without the operator's say-so.
func installPackage(pkg string) string {
	// Auto-install gate. Two reasons this is opt-in for non-root:
	//   1) `apt-get install` runs maintainer scripts as root.
	//   2) `npm install -g` of an attacker-chosen name (typosquat) gets a
	//      shell as the install user.
	// The agent's tool prompt should learn to surface "tool not installed"
	// to the human rather than try to install behind their back.
	cfg := config.Get()
	if !cfg.AllowAutoInstall {
		return fmt.Sprintf(
			"[install %s blocked: auto-install is disabled. Set XALGORIX_ALLOW_AUTO_INSTALL=1 in ~/.xalgorix.env to enable, or install manually.]",
			pkg,
		)
	}

	// Special handling for pipx-installed tools
	pipxTools := map[string]string{
		"arjun":       "arjun",
		"paramspider": "paramspider",
		"scrapling":   "scrapling",
		"uro":         "uro",
		"semgrep":     "semgrep",
		"bandit":      "bandit",
		"git-dumper":  "git-dumper",
	}

	// Special handling for Cargo (Rust) tools
	cargoTools := map[string]string{
		"feroxbuster": "feroxbuster",
		"findomain":   "findomain",
		"x8":          "x8",
	}

	// Special handling for Go-installed tools
	goTools := map[string]string{
		// ProjectDiscovery suite
		"nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"katana":    "github.com/projectdiscovery/katana/cmd/katana@latest",
		"naabu":     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		// Web crawlers & URL discovery
		"gospider":    "github.com/jaeles-project/gospider@latest",
		"gau":         "github.com/lc/gau/v2/cmd/gau@latest",
		"waybackurls": "github.com/tomnomnom/waybackurls@latest",
		"hakrawler":   "github.com/hakluke/hakrawler@latest",
		// Fuzzing & enumeration
		"gobuster":    "github.com/OJ/gobuster/v3@latest",
		"ffuf":        "github.com/ffuf/ffuf/v2@latest",
		"assetfinder": "github.com/tomnomnom/assetfinder@latest",
		// Vulnerability scanners
		"dalfox": "github.com/hahwul/dalfox/v2@latest",
		// Extended coverage (docs/tools.md)
		"shuffledns": "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
		"unfurl":     "github.com/tomnomnom/unfurl@latest",
		"gron":       "github.com/tomnomnom/gron@latest",
		"httprobe":   "github.com/tomnomnom/httprobe@latest",
		"gitleaks":   "github.com/zricethezav/gitleaks/v8@latest",
		"gosec":      "github.com/securego/gosec/v2/cmd/gosec@latest",
		"subjack":    "github.com/haccer/subjack@latest",
	}

	// npm-installed tools
	npmTools := map[string]string{
		"playwright-cli": "@anthropic-ai/playwright-cli",
	}

	// gem-installed tools (Ruby)
	gemTools := map[string]string{
		"brakeman": "brakeman",
	}

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	// pipx-installed tools (Python)
	if pipxPkg, ok := pipxTools[pkg]; ok {
		installCmd := fmt.Sprintf("pipx install %s 2>&1 || pip3 install %s 2>&1", pipxPkg, pipxPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s via pipx/pip failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via pipx successfully]", pkg)
	}

	// Cargo (Rust) tools
	if cargoPkg, ok := cargoTools[pkg]; ok {
		// Try apt first (faster), then cargo install as fallback. The cargo
		// fallback runs as the current user (no sudo) so it lands in
		// ~/.cargo/bin and respects user toolchain.
		installCmd := fmt.Sprintf("%sapt-get install -y -q %s 2>&1 || cargo install %s 2>&1", sudoPrefix(), cargoPkg, cargoPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s via apt/cargo failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s successfully]", pkg)
	}

	// gem (Ruby) tools
	if gemPkg, ok := gemTools[pkg]; ok {
		installCmd := fmt.Sprintf("gem install --no-document %s 2>&1", gemPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s via gem failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via gem successfully]", pkg)
	}

	if goPkg, ok := goTools[pkg]; ok {
		installCmd := fmt.Sprintf("GOBIN=%s/go/bin go install -v %s 2>&1", homeDir, goPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()

		// If default proxy fails, retry with GOPROXY=direct
		if err != nil {
			installCmd = fmt.Sprintf("GOBIN=%s/go/bin GOPROXY=direct go install -v %s 2>&1", homeDir, goPkg)
			cmd = exec.CommandContext(ctx, "bash", "-c", installCmd)
			out, err = cmd.CombinedOutput()
		}

		if err != nil {
			return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via go install successfully]", pkg)
	}

	// Special handling for npm-installed tools
	if npmPkg, ok := npmTools[pkg]; ok {
		installCmd := fmt.Sprintf("npm install -g %s 2>&1", npmPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 10 min for npm install
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil && sudoPrefix() != "" {
			// Try with sudo only if the operator has opted in.
			installCmd = sudoPrefix() + installCmd
			cmd = exec.CommandContext(ctx, "bash", "-c", installCmd)
			out, err = cmd.CombinedOutput()
		}
		if err != nil {
			return fmt.Sprintf("[install %s via npm failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via npm successfully]", pkg)
	}

	// Detect package manager and build install command
	var installCmd string

	if _, err := exec.LookPath("apt-get"); err == nil {
		// Refresh the package index once per process (see maybeRefreshAptLists).
		// Minimal/container images ship with /var/lib/apt/lists wiped, so an
		// install-only call fails with "Unable to locate package" until the
		// index is populated.
		maybeRefreshAptLists()
		installCmd = fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("dnf"); err == nil {
		installCmd = fmt.Sprintf("dnf install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("yum"); err == nil {
		installCmd = fmt.Sprintf("yum install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("pacman"); err == nil {
		installCmd = fmt.Sprintf("pacman -S --noconfirm %s 2>&1", pkg)
	} else if _, err := exec.LookPath("apk"); err == nil {
		installCmd = fmt.Sprintf("apk add --no-cache %s 2>&1", pkg)
	} else {
		return fmt.Sprintf("[cannot auto-install: no supported package manager found for %s]", pkg)
	}

	// Prefix with sudo only when the operator has opted in via
	// XALGORIX_AUTO_INSTALL_SUDO=1. Without that, this install will fail
	// for non-root users — which is the safer default than silently
	// escalating package-manager invocations.
	installCmd = sudoPrefix() + installCmd

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 10 min for pkg install
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
	}

	return fmt.Sprintf("[installed %s successfully]", pkg)
}

func formatOutput(stdout, stderr string, exitCode int) string {
	var b strings.Builder

	if stdout != "" {
		b.WriteString(truncate(stdout))
	}

	if stderr != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		b.WriteString(truncate(stderr))
	}

	if exitCode != 0 {
		b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitCode))
	}

	return b.String()
}

func truncate(s string) string {
	if len(s) > maxOutputLen {
		half := maxOutputLen / 2
		return s[:half] + "\n\n... [TRUNCATED] ...\n\n" + s[len(s)-half:]
	}
	return s
}

// blockedPatterns contains destructive commands that must never be executed.
var blockedPatterns = []struct {
	pattern string
	reason  string
}{
	{"rm -rf /", "recursive delete of root filesystem"},
	{"rm -rf /*", "recursive delete of root filesystem"},
	{"rm -rf ~", "recursive delete of home directory"},
	{"rm -rf .", "recursive delete of current directory"},
	{"> /dev/sd", "overwriting disk device"},
	{"dd if=/dev/zero", "overwriting with zeros"},
	{"dd if=/dev/random", "overwriting with random data"},
	{"mkfs", "formatting filesystem"},
	{"shutdown", "system shutdown"},
	{"reboot", "system reboot"},
	{"init 0", "system halt"},
	{"init 6", "system reboot"},
	{"halt", "system halt"},
	{"poweroff", "system poweroff"},
	{":(){ :|:&};:", "fork bomb"},
	{"chmod 777 /", "removing all file permissions on root"},
	{"chown -R", "recursive ownership change"},
	// SQL destructive statements
	{"drop table", "SQL DROP TABLE"},
	{"drop database", "SQL DROP DATABASE"},
	{"delete from", "SQL DELETE FROM"},
	{"truncate table", "SQL TRUNCATE TABLE"},
	// Python destructive
	{"shutil.rmtree", "recursive directory removal"},
	{"os.remove", "file deletion"},
	// Noisy / false-positive-heavy tools
	{"nikto", "nikto is blocked — too many false positives. Use nuclei or manual testing instead"},
}

// isBlockedCommand checks if a command matches any blocked pattern.
// It also detects encoding attempts (base64, hex, etc.) and checks decoded content.
//
// IMPORTANT: This is a BEST-EFFORT GUARDRAIL, not a security boundary.
// A determined adversary (or a confused LLM) can trivially bypass any
// string-based denylist via subshells, quoting tricks (r”m), variable
// expansion (rm$IFS-rf$IFS/), eval $'\\x72m -rf /', fetching a script over
// HTTP then piping to sh, writing destructive code with tee, etc.
//
// The real isolation must be operational: run xalgorix as an unprivileged
// user, inside a container/VM, with the workspace mounted read-write and
// the rest of the filesystem read-only. The blocklist is here to catch
// honest mistakes, not malice.
func isBlockedCommand(cmd string) string {
	// First check the raw command
	if reason := checkBlocked(cmd); reason != "" {
		return reason
	}

	// Try to decode and check base64 encoded commands
	if decoded := tryBase64Decode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via base64 decoding)"
		}
	}

	// Try hex decoding
	if decoded := tryHexDecode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via hex decoding)"
		}
	}

	// Try URL decoding
	if decoded := tryURLDecode(cmd); decoded != "" && decoded != cmd {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via URL decoding)"
		}
	}

	// Check for common obfuscation patterns
	if reason := checkObfuscation(cmd); reason != "" {
		return reason
	}

	return ""
}

// checkBlocked is the core blocking logic
func checkBlocked(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, bp := range blockedPatterns {
		if strings.Contains(lower, bp.pattern) {
			return bp.reason
		}
	}
	return ""
}

// tryBase64Decode attempts to decode a base64 string
func tryBase64Decode(cmd string) string {
	// Remove common prefixes
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimSuffix(cmd, " | base64 -d")
	cmd = strings.TrimSuffix(cmd, " | base64 --decode")
	cmd = strings.TrimSuffix(cmd, "| base64 -d")
	cmd = strings.TrimSuffix(cmd, "| base64 --decode")
	cmd = strings.Trim(cmd, " \t\n")

	// Try standard base64
	if decoded, err := decodeBase64(cmd); err == nil && len(decoded) > 0 {
		return decoded
	}

	return ""
}

// decodeBase64 decodes a base64 string
func decodeBase64(cmd string) (string, error) {
	// Add padding if needed
	missing := 4 - (len(cmd) % 4)
	if missing != 4 {
		cmd += strings.Repeat("=", missing)
	}

	data, err := decode(cmd) // using the existing base64 decode
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// tryHexDecode attempts to decode a hex string
func tryHexDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Check if it looks like hex (0x... or just hex chars)
	if !isHexString(cmd) {
		return ""
	}

	data, err := decodeHex(cmd)
	if err != nil {
		return ""
	}
	return string(data)
}

// isHexString checks if a string is valid hexadecimal
func isHexString(s string) bool {
	s = strings.ToLower(s)
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	_, err := decodeHex(s)
	return err == nil
}

// tryURLDecode attempts to URL decode a string
func tryURLDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Must contain URL-encoded characters
	if !strings.ContainsAny(cmd, "%") {
		return ""
	}

	decoded := simpleURLDecode(cmd)
	return decoded
}

// simpleURLDecode does basic URL decoding
func simpleURLDecode(s string) string {
	result := s
	result = strings.ReplaceAll(result, "%20", " ")
	result = strings.ReplaceAll(result, "%2F", "/")
	result = strings.ReplaceAll(result, "%3A", ":")
	result = strings.ReplaceAll(result, "%3F", "?")
	result = strings.ReplaceAll(result, "%3D", "=")
	result = strings.ReplaceAll(result, "%26", "&")
	result = strings.ReplaceAll(result, "%27", "'")
	result = strings.ReplaceAll(result, "%22", "\"")
	result = strings.ReplaceAll(result, "%3C", "<")
	result = strings.ReplaceAll(result, "%3E", ">")
	result = strings.ReplaceAll(result, "%5C", "\\")
	result = strings.ReplaceAll(result, "%2D", "-")
	result = strings.ReplaceAll(result, "%5F", "_")
	result = strings.ReplaceAll(result, "%2E", ".")
	result = strings.ReplaceAll(result, "%2B", "+")
	result = strings.ReplaceAll(result, "%24", "$")
	result = strings.ReplaceAll(result, "%40", "@")
	result = strings.ReplaceAll(result, "%23", "#")
	// Handle %XX hex sequences
	for i := 0; i < len(result)-2; i++ {
		if result[i] == '%' {
			hex := result[i+1 : i+3]
			if data, err := decodeHex(hex); err == nil && len(data) == 1 {
				result = result[:i] + string(data[0]) + result[i+3:]
				i-- // recheck from the new position
			}
		}
	}
	return result
}

// extractCommands extracts all unique tool/command names from a shell command
func extractCommands(cmd string) []string {
	// Common security tools to look for
	toolsList := []string{
		"nmap", "sqlmap", "gobuster", "ffuf", "dirb", "curl", "wget",
		"nuclei", "httpx", "dnsx", "subfinder", "findomain", "assetfinder",
		"masscan", "nc", "netcat", "socat", "openssl", "whatweb", "wafw00f",
		"gospider", "katana", "hakrawler", "gau", "waybackurls", "paramspider",
		"arjun", "x8", "jq", "xmllint", "hydra", "john",
		"git", "dirsearch", "feroxbuster", "testssl", "sslyze",
		"okenv", "ds_store", "gitdumper", "githacker",
		// Extended coverage (docs/tools.md): pre-install before first use.
		"shuffledns", "gosec", "subjack", "gitleaks", "semgrep", "bandit",
		"brakeman", "git-dumper",
	}

	found := make(map[string]bool)
	lowerCmd := strings.ToLower(cmd)

	for _, tool := range toolsList {
		// Check if tool appears as a standalone word in the command
		patterns := []string{
			" " + tool + " ",
			" " + tool + "\n",
			"|" + tool + " ",
			"&&" + tool + " ",
			tool + " -",
			tool + " --",
		}
		for _, p := range patterns {
			if strings.Contains(lowerCmd, p) {
				found[tool] = true
			}
		}
	}

	result := make([]string, 0, len(found))
	for t := range found {
		result = append(result, t)
	}

	// Also check if the command starts with a known tool
	cmdTrimmed := strings.TrimSpace(lowerCmd)
	for _, tool := range toolsList {
		if (strings.HasPrefix(cmdTrimmed, tool+" ") || cmdTrimmed == tool) && !found[tool] {
			found[tool] = true
			result = append(result, tool)
		}
	}

	return result
}

// hexEscapeRe matches a single \xNN hex-escape byte (e.g. \x72).
var hexEscapeRe = regexp.MustCompile(`(?i)\\x([0-9a-f]{2})`)

// chrCallRe matches chr(NN) / CHR( NN ) style character-code calls.
var chrCallRe = regexp.MustCompile(`(?i)chr\s*\(\s*(\d{1,3})\s*\)`)

// decodeHexEscapes replaces \xNN escape sequences with their literal byte
// value, leaving the rest of the command untouched, so the decoded form can be
// matched against the destructive-command denylist.
func decodeHexEscapes(cmd string) string {
	return hexEscapeRe.ReplaceAllStringFunc(cmd, func(m string) string {
		b, err := decodeHex(m[2:])
		if err != nil || len(b) != 1 {
			return m
		}
		return string(b)
	})
}

// decodeChrCalls replaces chr(NN) calls with their literal character.
func decodeChrCalls(cmd string) string {
	return chrCallRe.ReplaceAllStringFunc(cmd, func(m string) string {
		sub := chrCallRe.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		n, err := strconv.Atoi(sub[1])
		if err != nil || n < 0 || n > 255 {
			return m
		}
		return string(rune(n))
	})
}

// checkObfuscation detects obfuscation techniques that DECODE to a destructive
// command. Earlier versions blanket-blocked any \xNN hex escape or chr() call
// regardless of what it decoded to, which produced false positives on
// legitimate pentest payloads (e.g. \x90 NOP sleds, \x00 fuzz bytes, SQL
// injection CHAR()/CHR() expressions). We now decode the obfuscated bytes and
// only block when the decoded text matches the destructive-command denylist.
// Note: fully hex-encoded commands are already handled by tryHexDecode in
// isBlockedCommand; this function covers \xNN / chr() escapes embedded inside a
// larger command string.
func checkObfuscation(cmd string) string {
	if decoded := decodeHexEscapes(cmd); decoded != cmd {
		if reason := checkBlocked(decoded); reason != "" {
			return "obfuscated command detected: " + reason + " (via hex escape decoding)"
		}
	}
	if decoded := decodeChrCalls(cmd); decoded != cmd {
		if reason := checkBlocked(decoded); reason != "" {
			return "obfuscated command detected: " + reason + " (via chr() decoding)"
		}
	}
	return ""
}
