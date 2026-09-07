package terminal

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestIsBlockedCommand_DangerousAndObfuscatedInputs(t *testing.T) {
	dangerous := "rm -rf /"
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"raw destructive", dangerous, "recursive delete"},
		{"base64 destructive", base64.StdEncoding.EncodeToString([]byte(dangerous)), "base64"},
		{"hex destructive", "726d202d7266202f", "hex"},
		{"url destructive", "rm%20-rf%20%2F", "URL"},
		{"blocked noisy scanner", "nikto -h https://example.test", "false positives"},
		{"hex escape decodes to destructive", `echo \x72\x6d\x20\x2d\x72\x66\x20\x2f`, "obfuscated"},
		{"chr() decodes to destructive", `chr(114)chr(109)chr(32)chr(45)chr(114)chr(102)chr(32)chr(47)`, "obfuscated"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isBlockedCommand(tc.cmd)
			if got == "" {
				t.Fatalf("command %q was not blocked", tc.cmd)
			}
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tc.want)) {
				t.Fatalf("block reason = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestIsBlockedCommand_AllowsBenignReconCommands(t *testing.T) {
	for _, cmd := range []string{
		"curl -I https://example.test",
		"nmap -sV -p 443 example.test",
		"python3 -c 'print(123)'",
		// Benign hex payloads must NOT be blocked: NOP sled, null fuzz bytes.
		`printf '\x90\x90\x90\x90' | nc target 9000`,
		`python3 -c "print('\x00\x01\x02')"`,
		// Benign chr() usage (does not decode to a destructive command).
		`python3 -c "print(chr(65)+chr(66)+chr(67))"`,
	} {
		if got := isBlockedCommand(cmd); got != "" {
			t.Fatalf("benign command %q was blocked: %s", cmd, got)
		}
	}
}

func TestCommandHelpers_ClassifyHeavyToolsAndPackages(t *testing.T) {
	if !isHeavyTool("nuclei -u https://example.test") {
		t.Fatal("nuclei should be classified as heavy")
	}
	if !isHeavyTool("httpx -l hosts.txt -silent") {
		t.Fatal("httpx should be classified as heavy")
	}
	if !isHeavyTool("naabu -host example.test") {
		t.Fatal("naabu should be classified as heavy")
	}
	if isHeavyTool("curl -I https://example.test") {
		t.Fatal("curl should not be classified as heavy")
	}
	if computeTimeout("nmap -sV example.test") != heavyCmdTimeout {
		t.Fatal("nmap should get heavy command timeout")
	}
	if computeTimeout("curl -I https://example.test") != defaultCmdTimeout {
		t.Fatal("curl should get default command timeout")
	}
	if heavyCmdTimeout <= defaultCmdTimeout || hardMaxTimeout < 2*time.Hour {
		t.Fatal("timeout tiers are not ordered as expected")
	}

	if got := resolvePackage("dig"); got != "dnsutils" {
		t.Fatalf("resolvePackage(dig) = %q", got)
	}
	if got := resolvePackage("definitely-not-known"); got != "" {
		t.Fatalf("unknown command resolved to package %q", got)
	}
}

func TestResolvePackage_ExtendedToolCoverage(t *testing.T) {
	// Every tool advertised in docs/tools.md that the engine is expected to
	// auto-install must resolve to a non-empty package name; otherwise the
	// reactive install path (extractMissingCommand → resolvePackage →
	// installPackage) silently no-ops and the agent just sees "command not
	// found". Regression guard for the coverage gap found on 2026-07-25 and
	// for the auto-install mapping bugs #286/#288 (paramspider, arjun, x8, uro).
	for _, tool := range []string{
		// Go tools
		"shuffledns", "gosec", "subjack", "gitleaks", "unfurl", "gron", "httprobe",
		// Python (pipx) tools
		"paramspider", "semgrep", "bandit", "git-dumper", "arjun", "uro",
		// Rust (cargo)
		"x8",
		// Ruby (gem)
		"brakeman",
		// Distro packages (apt)
		"findomain", "dirsearch", "gh",
	} {
		if pkg := resolvePackage(tool); pkg == "" {
			t.Errorf("resolvePackage(%q) = %q; tool not auto-installable (missing from packageMap)", tool, "")
		}
	}
}

func TestNormalizeCommandForRequestRatePolicy_RewritesScannerFlags(t *testing.T) {
	sc := scanctx.New("term-rate", t.TempDir())
	sc.SetRequestRatePolicy(scanctx.RequestRatePolicy{MaxRPS: 3, Source: "custom instructions"})
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	cases := []struct {
		name string
		cmd  string
		want []string
		bad  []string
	}{
		{
			name: "nuclei",
			cmd:  "nuclei -u https://example.test -rl 20 -c 50 -o nuclei.txt",
			want: []string{"-rl 3", "-c 3"},
			bad:  []string{"-rl 20", "-c 50"},
		},
		{
			name: "nmap",
			cmd:  "nmap -sV -sC -T4 --min-rate 100 --top-ports 200 example.test",
			want: []string{"-T2", "--max-rate 3", "--scan-delay 334ms"},
			bad:  []string{"-T4", "--min-rate"},
		},
		{
			name: "naabu still throttled",
			cmd:  "naabu -host example.test -rate 1000 -c 50",
			want: []string{"-rate 3", "-c 3"},
			bad:  []string{"-rate 1000", "-c 50"},
		},
		{
			name: "gobuster delay",
			cmd:  "gobuster dir -u https://example.test -w words.txt -t 50",
			want: []string{"-t 1", "--delay 334ms"},
			bad:  []string{"-t 50"},
		},
		{
			name: "xargs fanout",
			cmd:  "cat urls.txt | xargs -P20 -I{} curl -s {}",
			want: []string{"xargs -P 1", "curl -s"},
			bad:  []string{"-P20"},
		},
		{
			name: "parallel fanout",
			cmd:  "parallel -j20 curl -s ::: https://a.test https://b.test",
			want: []string{"parallel -j 1"},
			bad:  []string{"-j20"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note := NormalizeCommandForRequestRatePolicy(sc.ID, tc.cmd)
			if note == "" {
				t.Fatal("expected normalization note")
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("normalized command %q missing %q", got, want)
				}
			}
			for _, bad := range tc.bad {
				if strings.Contains(got, bad) {
					t.Fatalf("normalized command %q still contains %q", got, bad)
				}
			}
		})
	}
}

// Subdomain-discovery / liveness tools are EXEMPT from the rate rewrite so
// enumeration of large targets can actually complete (issue: att.com wildcard
// scan found only a fraction of its live subdomains because httpx/dnsx were
// throttled to ~10 rps). Their commands must pass through UNCHANGED with no
// rate-policy note.
func TestNormalizeCommandForRequestRatePolicy_ExemptsDiscoveryTools(t *testing.T) {
	sc := scanctx.New("term-rate-exempt", t.TempDir())
	sc.SetRequestRatePolicy(scanctx.RequestRatePolicy{MaxRPS: 3, Source: "custom instructions"})
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	exempt := []string{
		"cat urls.txt | httpx -silent -threads 50 -rl 200 | tee live.txt",
		"cat all_subs.txt | dnsx -silent -a -resp -threads 100",
		"subfinder -d att.com -all -recursive -silent -t 50 -rl 100 -o subs.txt",
		"assetfinder --subs-only att.com",
		"puredns resolve subs.txt -r resolvers.txt",
	}
	for _, cmd := range exempt {
		got, note := NormalizeCommandForRequestRatePolicy(sc.ID, cmd)
		if note != "" {
			t.Errorf("discovery command should NOT be rate-rewritten: %q -> note %q", cmd, note)
		}
		if got != cmd {
			t.Errorf("discovery command should be unchanged:\n  in:  %q\n  out: %q", cmd, got)
		}
	}

	// A discovery stage piped into an aggressive stage: the discovery stage is
	// exempt, the aggressive stage is still throttled.
	mixed := "subfinder -d att.com -silent | httpx -silent -threads 50 | nuclei -rl 100 -c 50"
	got, note := NormalizeCommandForRequestRatePolicy(sc.ID, mixed)
	if note == "" {
		t.Fatal("mixed pipeline with nuclei should still produce a rate note")
	}
	if !strings.Contains(got, "-threads 50") {
		t.Errorf("httpx stage in mixed pipeline should stay unthrottled: %q", got)
	}
	if strings.Contains(got, "-rl 100") || strings.Contains(got, "-c 50") {
		t.Errorf("nuclei stage in mixed pipeline should be throttled: %q", got)
	}
}

func TestPrepareRequestRateRuntimeCreatesWrappersAndPythonHook(t *testing.T) {
	rt, err := prepareRequestRateRuntime(t.TempDir(), scanctx.RequestRatePolicy{MaxRPS: 3, Source: "test"})
	if err != nil {
		t.Fatalf("prepareRequestRateRuntime: %v", err)
	}
	if rt.DelayMS != 334 {
		t.Fatalf("DelayMS = %d, want 334", rt.DelayMS)
	}
	if rt.BinDir == "" || rt.PythonPath == "" || rt.LockDir == "" {
		t.Fatalf("runtime paths were not set: %+v", rt)
	}
	if _, err := os.Stat(filepath.Join(rt.PythonPath, "sitecustomize.py")); err != nil {
		t.Fatalf("sitecustomize.py missing: %v", err)
	}

	env := commandEnv("/home/tester", "/home/tester/go", "/tmp/work", rt)
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH="+rt.BinDir+":") {
		t.Fatalf("PATH does not start with rate wrapper dir: %s", joined)
	}
	if !strings.Contains(joined, "PYTHONPATH="+rt.PythonPath) {
		t.Fatalf("PYTHONPATH missing rate hook: %s", joined)
	}
	if !strings.Contains(joined, "XALGORIX_RATE_DELAY_MS=334") {
		t.Fatalf("rate delay env missing: %s", joined)
	}
}

func TestExtractCommandAndMissingCommandParsing(t *testing.T) {
	cmds := extractCommands("curl -s https://example.test | jq . && nuclei -u https://example.test")
	joined := strings.Join(cmds, ",")
	for _, want := range []string{"curl", "jq", "nuclei"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("extractCommands missing %q from %v", want, cmds)
		}
	}

	output := "STDERR:\nbash: line 1: fancytool: command not found\n[exit code: 127]"
	if got := extractMissingCommand(output); got != "fancytool" {
		t.Fatalf("extractMissingCommand = %q", got)
	}
	if !isCommandNotFound(output) {
		t.Fatal("command-not-found output was not detected")
	}
}

func TestProcessTrackingIsContextSpecific(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep is not available")
	}

	scA := scanctx.New("term-a", t.TempDir())
	scB := scanctx.New("term-b", t.TempDir())
	scanctx.Activate(scA)
	scanctx.Activate(scB)
	t.Cleanup(func() {
		CleanupContext(scA.ID)
		CleanupContext(scB.ID)
		scanctx.Deactivate(scA.ID)
		scanctx.Deactivate(scB.ID)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	TrackProcessForContext(scA.ID, cmd, cancel, "sleep 30")
	if got := ActiveProcessCountForContext(scA.ID); got != 1 {
		t.Fatalf("context A process count = %d, want 1", got)
	}
	if got := ActiveProcessCountForContext(scB.ID); got != 0 {
		t.Fatalf("context B process count = %d, want 0", got)
	}

	KillAllProcessesForContext(scB.ID)
	if got := ActiveProcessCountForContext(scA.ID); got != 1 {
		t.Fatalf("killing context B affected context A, count=%d", got)
	}

	KillAllProcessesForContext(scA.ID)
	if got := ActiveProcessCountForContext(scA.ID); got != 0 {
		t.Fatalf("context A process count after kill = %d, want 0", got)
	}
}

func TestWorkDirPrefersScanContext(t *testing.T) {
	sc := scanctx.New("term-workdir", t.TempDir())
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	sc.Terminal.SetWorkDir("/tmp/from-scanctx")
	store := getTermStoreByID(sc.ID)
	store.mu.Lock()
	store.workDir = "/tmp/from-terminal-store"
	store.mu.Unlock()

	if got := GetWorkDirForContext(sc.ID); got != "/tmp/from-scanctx" {
		t.Fatalf("GetWorkDirForContext = %q", got)
	}
}

func TestRunShellScopesHomeAndBlocksCdOutsideWorkspace(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	sc := scanctx.New("term-scope", t.TempDir())
	sc.Terminal.SetWorkDir(sc.ScanDir)
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	out, code := runShellInternal(sc.ID, `printf 'home=%s\npwd=%s\ntmpdir=%s\n' "$HOME" "$PWD" "$TMPDIR"; cd /root; printf 'after=%s\n' "$PWD"`)
	if code != 0 {
		t.Fatalf("runShellInternal exit=%d output=%q", code, out)
	}
	if !strings.Contains(out, "home="+sc.ScanDir) {
		t.Fatalf("HOME was not scoped to scan dir: %q", out)
	}
	if !strings.Contains(out, "pwd="+sc.ScanDir) || !strings.Contains(out, "after="+sc.ScanDir) {
		t.Fatalf("command escaped scan dir: %q", out)
	}
	if !strings.Contains(out, "tmpdir="+filepath.Join(sc.ScanDir, "tmp")) {
		t.Fatalf("TMPDIR was not scoped to scan tmp/: %q", out)
	}
	if !strings.Contains(out, "[WORKSPACE GUARD] cd outside scan workspace blocked") {
		t.Fatalf("workspace guard did not report blocked cd: %q", out)
	}
	if _, err := os.Stat(filepath.Join(sc.ScanDir, "tmp")); err != nil {
		t.Fatalf("workspace temp dir missing: %v", err)
	}
}
