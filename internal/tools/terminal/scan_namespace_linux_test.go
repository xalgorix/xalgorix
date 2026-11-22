//go:build linux

package terminal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// These tests create real PID and mount namespaces, which needs root
// (CAP_SYS_ADMIN). To run them without root, use a user namespace:
//
//	unshare -r --mount --propagation shared go test ./internal/tools/terminal/ -run ScanNamespace
//
// --propagation shared reproduces a systemd host, where / is a shared mount and
// a /proc mounted inside the namespace would leak back out unless the
// namespace makes its mounts slaves first.
func requireScanNamespaces(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_SYS_ADMIN); run under: unshare -r --mount --propagation shared go test ...")
	}
	if _, ok := isolationTool(); !ok {
		t.Skipf("process isolation unavailable here: %s", isolationNoReason)
	}
}

func newIsolatedTestContext(t *testing.T) string {
	t.Helper()
	id := fmt.Sprintf("pidns-test-%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { releaseScanNamespace(id) })
	return id
}

// runIsolated runs a shell script in contextID's namespace the way the
// terminal and python tools start commands: its own process group, then
// isolateCommand.
func runIsolated(t *testing.T, contextID, dir, script string, memLimitBytes int64) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !isolateCommand(contextID, cmd, memLimitBytes) {
		t.Fatalf("isolateCommand(%q) returned false", contextID)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %q: %v", script, err)
	}
	return out.String(), code
}

func namespacePIDFor(t *testing.T, contextID string) int {
	t.Helper()
	scanNamespacesMu.Lock()
	defer scanNamespacesMu.Unlock()
	ns := scanNamespaces[contextID]
	if ns == nil {
		t.Fatalf("no namespace for %q", contextID)
	}
	return ns.pid
}

func TestScanNamespaceHidesHostProcesses(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)

	out, code := runIsolated(t, id, "", "ps -e -o pid=,comm=", 0)
	if code != 0 {
		t.Fatalf("ps exit %d: %s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// PID 1 (the namespace's init), the sh running ps, and ps itself.
	if len(lines) > 4 {
		t.Fatalf("ps inside the namespace listed %d processes, want only the scan's own:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(strings.TrimSpace(lines[0]), "1 ") {
		t.Fatalf("first process inside the namespace is not PID 1:\n%s", out)
	}

	// The test process is outside the namespace: it is neither listed nor
	// signalable by its host PID.
	self := strconv.Itoa(os.Getpid())
	out, _ = runIsolated(t, id, "", "test -e /proc/"+self+" && echo visible || echo hidden", 0)
	if strings.TrimSpace(out) != "hidden" {
		t.Fatalf("host PID %s is visible inside the namespace: %q", self, out)
	}

	// The namespace's private /proc must not have replaced the engine's.
	if _, err := os.Stat("/proc/" + self); err != nil {
		t.Fatalf("the engine's /proc changed after creating a namespace: %v", err)
	}
	if target, err := os.Readlink("/proc/self"); err != nil || target != self {
		t.Fatalf("/proc/self in the engine = %q, %v; want %s (namespace /proc leaked out)", target, err, self)
	}
}

func TestScanNamespaceKillEverythingSparesHostProcesses(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)

	host := exec.Command("sleep", "60")
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Process.Kill(); _ = host.Wait() })

	// The incident command, run inside the namespace.
	runIsolated(t, id, "", `ps aux 2>/dev/null | awk 'NR>1 {print $2}' | head -300 | xargs -r kill -9 2>/dev/null; kill -9 -1 2>/dev/null; true`, 0)

	if err := host.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("a host process died when a scan command killed everything it could see: %v", err)
	}
	// PID 1 ignores signals from inside, so the namespace keeps working.
	if out, code := runIsolated(t, id, "", "echo alive", 0); code != 0 || strings.TrimSpace(out) != "alive" {
		t.Fatalf("namespace unusable after kill -9 -1: exit %d, %q", code, out)
	}
}

func TestScanNamespaceKeepsBackgroundProcessesUntilReleased(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)

	runIsolated(t, id, "", "nohup sleep 300 >/dev/null 2>&1 & echo started", 0)
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, _ := runIsolated(t, id, "", "ps -e -o comm= | grep -c '^sleep$'", 0)
		if strings.TrimSpace(out) == "1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background process from an earlier command is gone: %q", out)
		}
		time.Sleep(50 * time.Millisecond)
	}

	pid1 := namespacePIDFor(t, id)
	releaseScanNamespace(id)
	if err := syscall.Kill(pid1, 0); err == nil {
		t.Fatalf("namespace PID 1 (host PID %d) still alive after release", pid1)
	}
	// A new command gets a fresh namespace without the old background process.
	out, _ := runIsolated(t, id, "", "ps -e -o comm= | grep -c '^sleep$'", 0)
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("background process survived the release of its namespace: %q", out)
	}
}

func TestScanNamespaceReapsOrphans(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)

	runIsolated(t, id, "", "(sleep 0.2 &) ; true", 0)
	time.Sleep(600 * time.Millisecond)
	out, _ := runIsolated(t, id, "", "ps -e -o stat= | grep -c '^Z'", 0)
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("orphan left as a zombie in the namespace: %q", out)
	}
}

func TestScanNamespacePreservesDirExitCodeAndLimits(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)
	dir := t.TempDir()

	out, code := runIsolated(t, id, dir, "pwd; cat /proc/self/oom_score_adj; ulimit -v; exit 7", 256<<20)
	if code != 7 {
		t.Fatalf("exit code = %d, want 7 (output %q)", code, out)
	}
	got := strings.Fields(out)
	if len(got) != 3 || got[0] != dir || got[1] != "500" || got[2] != strconv.Itoa(256<<10) {
		t.Fatalf("got %q, want [%s 500 %d]", got, dir, 256<<10)
	}
}

func TestScanNamespaceProcessGroupKillReachesTheCommand(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)

	cmd := exec.Command("sh", "-c", "sleep 300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !isolateCommand(id, cmd, 0) {
		t.Fatal("isolateCommand returned false")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	// What the terminal tool does on timeout or stop.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not exit after its process group was killed")
	}
	out, _ := runIsolated(t, id, "", "ps -e -o comm= | grep -c '^sleep$'", 0)
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("process group kill left the command running inside the namespace: %q", out)
	}
}

func TestScanNamespaceEndsWithItsScan(t *testing.T) {
	requireScanNamespaces(t)
	id := newIsolatedTestContext(t)
	sc := scanctx.New(id, t.TempDir())
	scanctx.Activate(sc)
	t.Cleanup(func() { scanctx.Deactivate(id) })

	runIsolated(t, id, "", "nohup sleep 300 >/dev/null 2>&1 &", 0)
	pid1 := namespacePIDFor(t, id)

	sc.Close() // cancels the scan context
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid1, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("namespace PID 1 (host PID %d) still alive after its scan ended", pid1)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if isolateCommand(id, exec.Command("true"), 0) {
		t.Fatal("isolateCommand started a namespace for a scan that has already ended")
	}
}

func TestScanNamespaceDisabledByConfig(t *testing.T) {
	cfg := config.Get()
	prev := cfg.ProcessIsolation
	cfg.ProcessIsolation = false
	t.Cleanup(func() { cfg.ProcessIsolation = prev })

	cmd := exec.Command("true")
	path, args := cmd.Path, append([]string(nil), cmd.Args...)
	if isolateCommand("pidns-disabled", cmd, 0) {
		t.Fatal("isolateCommand isolated a command with XALGORIX_PROCESS_ISOLATION=false")
	}
	if cmd.Path != path || strings.Join(cmd.Args, " ") != strings.Join(args, " ") {
		t.Fatalf("isolateCommand changed the command while disabled: %s %q", cmd.Path, cmd.Args)
	}
}

// The full terminal_execute path (prelude, workspace guard, env, limits) runs
// inside the scan's namespace, and a background process outlives the command
// that started it until the scan's terminal context is cleaned up.
func TestTerminalCommandsRunInTheScanNamespace(t *testing.T) {
	requireScanNamespaces(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	t.Setenv("HOME", t.TempDir())
	sc := scanctx.New(fmt.Sprintf("pidns-term-%d", time.Now().UnixNano()), t.TempDir())
	sc.Terminal.SetWorkDir(sc.ScanDir)
	scanctx.Activate(sc)
	t.Cleanup(func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	})

	self := strconv.Itoa(os.Getpid())
	out, code := runShellInternal(sc.ID, `printf 'pwd=%s\n' "$PWD"; test -e /proc/`+self+` && echo host=visible || echo host=hidden; nohup sleep 300 >/dev/null 2>&1 & echo started`)
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out)
	}
	for _, want := range []string{"pwd=" + sc.ScanDir, "host=hidden", "started"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q is missing %q", out, want)
		}
	}

	out, code = runShellInternal(sc.ID, `ps -e -o comm= | grep -c '^sleep$'`)
	if code != 0 || !strings.Contains(out, "1") {
		t.Fatalf("background process from the previous command not visible: exit=%d %q", code, out)
	}

	pid1 := namespacePIDFor(t, sc.ID)
	CleanupContext(sc.ID)
	if err := syscall.Kill(pid1, 0); err == nil {
		t.Fatalf("namespace PID 1 (host PID %d) still alive after CleanupContext", pid1)
	}
}
