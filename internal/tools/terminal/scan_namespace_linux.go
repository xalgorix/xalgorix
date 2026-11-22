//go:build linux

package terminal

// Scan process isolation.
//
// Every terminal_execute and python_action command of a scan runs inside a PID
// namespace that belongs to that scan, with its own /proc. Inside it, ps, top,
// pgrep, kill, pkill and killall see and reach only the scan's processes:
// never the host's services, the engine, or another scan. Without it, a command
// run as root can list and SIGKILL every process on the machine. A model that
// mistakes the host's processes for its own leftovers ("ps aux | ... | xargs
// kill -9") then takes down whatever else runs there.
//
// There is one namespace per scan, not per command, so background processes
// keep working across commands: a listener or local app started with
// "nohup ... &" in one command is still there for the next. The namespace's
// PID 1 is a small bash loop. It reaps orphaned processes and blocks reading
// a pipe that only the engine holds. When the scan ends, or the engine exits
// and the pipe closes, PID 1 exits and the kernel kills everything left in the
// namespace. No scan process outlives its scan.
//
// Commands enter the namespace with nsenter(1). Creating the namespaces needs
// CAP_SYS_ADMIN, so isolation applies when the engine runs as root (the
// systemd and hosted deployments). Otherwise (an unprivileged user, or a
// container without that capability) commands run as before, and a one-time
// log line says why. XALGORIX_PROCESS_ISOLATION=false turns it off.
//
// This bounds what a confused command can reach. It is not a sandbox against a
// deliberately hostile one: a root process inside can still unmount the
// private /proc or talk to the host's service manager. The command guard in
// process_guard.go refuses the service-manager commands; running scans as an
// unprivileged user or in a container is the stronger boundary.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// scanNamespaceInit is PID 1 of a scan's namespace. The mount namespace starts
// as a copy of the engine's, with the host's propagation (usually shared). It
// must become a slave first. Otherwise mounting the private /proc would
// propagate back and replace the host's /proc. A slave still receives mounts
// the host makes later. The read loop ends when the engine closes the pipe on
// stdin. bash reaps orphans that are reparented to it while it waits.
const scanNamespaceInit = `mount --make-rslave / || exit 96
mount -t proc -o nosuid,nodev,noexec proc /proc || exit 97
trap '' HUP INT QUIT TERM PIPE USR1 USR2 ALRM
echo ready
exec >/dev/null 2>&1
while read -r _; do :; done
`

// scanNamespaceExec runs inside the namespace, between nsenter and the real
// command. The engine applies OOM and memory limits to the PID it starts,
// which is now nsenter, and nsenter forks the command before those limits
// land. So the command sets them on itself before exec. $1 is the address-space
// limit in KiB (0 = none); the rest is the command.
const scanNamespaceExec = `lim=$1; shift
echo 500 > /proc/self/oom_score_adj 2>/dev/null
if [ "$lim" -gt 0 ] 2>/dev/null; then ulimit -v "$lim" 2>/dev/null; fi
exec "$@"
`

const scanNamespaceReadyTimeout = 10 * time.Second

type scanNamespace struct {
	init  *exec.Cmd
	pid   int             // host PID of the namespace's PID 1
	keep  *os.File        // write end of PID 1's stdin; closing it ends the namespace
	done  chan struct{}   // closed once PID 1 has exited and been reaped
	owner context.Context // lifetime of the scan that owns it; nil outside a scan context
}

func (ns *scanNamespace) alive() bool {
	select {
	case <-ns.done:
		return false
	default:
		return true
	}
}

// stop ends the namespace. Closing the pipe lets PID 1 exit on its own, and
// the kill covers a PID 1 that is stuck. Either way the kernel then kills
// every process left in the namespace.
func (ns *scanNamespace) stop() {
	_ = ns.keep.Close()
	if ns.alive() {
		_ = ns.init.Process.Kill()
	}
	select {
	case <-ns.done:
	case <-time.After(5 * time.Second):
		log.Printf("[ISOLATION] Namespace PID 1 (host PID %d) did not exit within 5s of being stopped", ns.pid)
	}
}

var (
	scanNamespacesMu sync.Mutex
	scanNamespaces   = make(map[string]*scanNamespace)

	isolationProbeOnce sync.Once
	isolationNsenter   string // "" when this host cannot isolate
	isolationNoReason  string
	isolationBroken    atomic.Bool // set after a failure that retrying will not fix
	isolationLogOnce   sync.Once
)

// isolationTool returns the nsenter path when commands should be isolated.
func isolationTool() (string, bool) {
	if !config.Get().ProcessIsolation {
		return "", false
	}
	isolationProbeOnce.Do(func() {
		if os.Geteuid() != 0 {
			isolationNoReason = "the engine is not running as root"
			return
		}
		path, err := exec.LookPath("nsenter")
		if err != nil {
			isolationNoReason = "nsenter (util-linux) is not installed"
			return
		}
		if _, err := exec.LookPath("mount"); err != nil {
			isolationNoReason = "mount (util-linux) is not installed"
			return
		}
		isolationNsenter = path
	})
	if isolationNsenter == "" {
		isolationLogOnce.Do(func() {
			log.Printf("[ISOLATION] Scan commands run without process isolation: %s. A command can then see and signal every process this user can.", isolationNoReason)
		})
		return "", false
	}
	if isolationBroken.Load() {
		return "", false
	}
	return isolationNsenter, true
}

// processIsolationAvailable reports whether commands on this host run in a
// scan namespace.
func processIsolationAvailable() bool {
	_, ok := isolationTool()
	return ok
}

// isolateCommand rewrites cmd so it runs inside contextID's namespace, creating
// the namespace on first use. Call it after cmd.Path, cmd.Args and cmd.Dir are
// final and before Start. It returns false, leaving cmd untouched, when
// isolation is off or unavailable; the command then runs as it always has.
//
// The process group that terminal and python commands kill on timeout or stop
// still covers the command: nsenter is the group leader and the command it
// forks inside the namespace inherits the group.
func isolateCommand(contextID string, cmd *exec.Cmd, memLimitBytes int64) bool {
	if cmd == nil || cmd.Err != nil || cmd.Path == "" || len(cmd.Args) == 0 {
		return false
	}
	nsenter, ok := isolationTool()
	if !ok {
		return false
	}
	pid, ok := scanNamespacePID(normalizeContextID(contextID))
	if !ok {
		return false
	}
	limitKB := int64(0)
	if memLimitBytes > 0 {
		limitKB = memLimitBytes / 1024
	}
	args := []string{nsenter, "--target", strconv.Itoa(pid), "--pid", "--mount"}
	if cmd.Dir != "" {
		// Entering a mount namespace resets the working directory to its root.
		args = append(args, "--wd="+cmd.Dir)
	}
	args = append(args, "--", "/bin/sh", "-c", scanNamespaceExec, "xalgorix-scan", strconv.FormatInt(limitKB, 10), cmd.Path)
	args = append(args, cmd.Args[1:]...)
	cmd.Path = nsenter
	cmd.Args = args
	return true
}

// scanNamespacePID returns the host PID of contextID's namespace PID 1,
// starting the namespace if it does not exist or has died.
func scanNamespacePID(contextID string) (int, bool) {
	var owner context.Context
	if sc := scanctx.Get(contextID); sc != nil && sc.Ctx != nil {
		owner = sc.Ctx
	}

	scanNamespacesMu.Lock()
	defer scanNamespacesMu.Unlock()

	if ns := scanNamespaces[contextID]; ns != nil {
		if ns.alive() && (ns.owner == nil || ns.owner.Err() == nil) {
			return ns.pid, true
		}
		// PID 1 died (its background processes went with it), or the scan
		// that owned it has ended and this context ID is being reused.
		ns.stop()
		delete(scanNamespaces, contextID)
	}
	if owner != nil && owner.Err() != nil {
		return 0, false // the scan is over; don't start a namespace nobody will release
	}

	ns, err := startScanNamespace()
	if err != nil {
		var permanent permanentIsolationError
		if errors.As(err, &permanent) {
			isolationBroken.Store(true)
			log.Printf("[ISOLATION] Cannot create a scan namespace, so scan commands run without process isolation from now on: %v", err)
		} else {
			log.Printf("[ISOLATION] Cannot create a namespace for scan context %s; this command runs without process isolation: %v", contextID, err)
		}
		return 0, false
	}
	ns.owner = owner
	scanNamespaces[contextID] = ns
	log.Printf("[ISOLATION] Scan context %s: commands run in their own PID namespace (PID 1 is host PID %d)", contextID, ns.pid)

	if owner != nil {
		go func() {
			select {
			case <-owner.Done():
				releaseScanNamespaceIfCurrent(contextID, ns)
			case <-ns.done:
			}
		}()
	}
	return ns.pid, true
}

// permanentIsolationError marks a failure that every later attempt would hit
// too, such as the kernel refusing to create the namespaces.
type permanentIsolationError struct{ err error }

func (e permanentIsolationError) Error() string { return e.err.Error() }
func (e permanentIsolationError) Unwrap() error { return e.err }

func startScanNamespace() (*scanNamespace, error) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		return nil, permanentIsolationError{fmt.Errorf("bash not found: %w", err)}
	}
	keepR, keepW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		_ = keepR.Close()
		_ = keepW.Close()
		return nil, err
	}

	cmd := &exec.Cmd{
		Path:   bash,
		Args:   []string{"xalgorix-scan-init", "-c", scanNamespaceInit},
		Dir:    "/",
		Env:    []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"},
		Stdin:  keepR,
		Stdout: readyW,
		Stderr: readyW,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
			Setsid:     true,
		},
	}
	startErr := cmd.Start()
	// The child holds its own copies now. The engine keeps only keepW, which
	// is close-on-exec, so no later command inherits it and keeps PID 1 alive.
	_ = keepR.Close()
	_ = readyW.Close()
	if startErr != nil {
		_ = keepW.Close()
		_ = readyR.Close()
		if errors.Is(startErr, syscall.EPERM) || errors.Is(startErr, syscall.EINVAL) || errors.Is(startErr, syscall.ENOSYS) {
			return nil, permanentIsolationError{startErr}
		}
		return nil, startErr
	}

	ns := &scanNamespace{init: cmd, pid: cmd.Process.Pid, keep: keepW, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(ns.done)
	}()

	_ = readyR.SetReadDeadline(time.Now().Add(scanNamespaceReadyTimeout))
	line, readErr := bufio.NewReader(readyR).ReadString('\n')
	_ = readyR.Close()
	line = strings.TrimSpace(line)
	if line == "ready" {
		return ns, nil
	}

	ns.stop()
	if readErr != nil && errors.Is(readErr, os.ErrDeadlineExceeded) {
		return nil, fmt.Errorf("namespace PID 1 did not report ready within %s", scanNamespaceReadyTimeout)
	}
	code := -1
	if !ns.alive() && cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	// Exit 96/97: the mounts failed. That is a property of this host, so
	// retrying for every command would only repeat it.
	return nil, permanentIsolationError{fmt.Errorf("namespace setup failed (exit %d): %s", code, line)}
}

// releaseScanNamespace ends contextID's namespace, killing every process the
// scan left running in it.
func releaseScanNamespace(contextID string) {
	contextID = normalizeContextID(contextID)
	scanNamespacesMu.Lock()
	ns := scanNamespaces[contextID]
	delete(scanNamespaces, contextID)
	scanNamespacesMu.Unlock()
	if ns != nil {
		ns.stop()
	}
}

func releaseScanNamespaceIfCurrent(contextID string, ns *scanNamespace) {
	scanNamespacesMu.Lock()
	current := scanNamespaces[contextID] == ns
	if current {
		delete(scanNamespaces, contextID)
	}
	scanNamespacesMu.Unlock()
	if current {
		ns.stop()
	}
}
