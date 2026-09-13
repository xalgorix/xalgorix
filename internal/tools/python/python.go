// Package python provides the python_action tool via subprocess.
package python

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	egressproxy "github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/iolimit"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// configureProcessGroupKill starts cmd in its own process group and installs a
// Cancel that SIGKILLs the whole group when the context is canceled/times out.
//
// Without this, exec.CommandContext's default cancel sends SIGKILL only to the
// direct python3 PID. Because the child runs in a new process group (Setpgid),
// any grandchild the script spawns (subprocess.Popen/os.system/fork) survives
// as an orphan and keeps the inherited stdout/stderr pipes open, so cmd.Wait()
// blocks well past the timeout. Killing the negative PID (the whole group)
// reaps those orphans and lets Wait() return. Mirrors internal/tools/terminal.
func configureProcessGroupKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return os.ErrProcessDone
	}
}

// Register adds the python_action tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "python_action",
		Description: "Execute Python code in a subprocess. Python 3 must be installed.",
		Parameters: []tools.Parameter{
			{Name: "code", Description: "Python code to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 1800 = 30 min)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executePythonForContext(r.GetScanContextID(), args)
		},
	})
}

func executePython(args map[string]string) (tools.Result, error) {
	return executePythonForContext(scanctx.Default().ID, args)
}

func executePythonForContext(contextID string, args map[string]string) (tools.Result, error) {
	if strings.TrimSpace(contextID) == "" {
		contextID = scanctx.Default().ID
	}

	code := args["code"]
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	timeoutSec := 1800 // 30 minutes — exploit scripts can run long
	if t := args["timeout"]; t != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return tools.Result{Error: fmt.Sprintf("invalid timeout value '%s': must be a number in seconds", t)}, nil
		}
		timeoutSec = parsed
		if timeoutSec <= 0 {
			timeoutSec = 1800
		}
		if timeoutSec > 7200 { // Cap at 2 hours
			timeoutSec = 7200
		}
	}

	// Find python3
	pythonBin := "python3"
	if _, err := exec.LookPath(pythonBin); err != nil {
		pythonBin = "python"
		if _, err := exec.LookPath(pythonBin); err != nil {
			return tools.Result{}, fmt.Errorf("python not found. Install python3")
		}
	}

	waitCtx := pythonWaitContext(contextID)
	lease, err := resources.AcquireToolLeaseContext(waitCtx, false, "python_action")
	if err != nil {
		return tools.Result{Output: fmt.Sprintf("[CANCELED] python_action launch canceled before starting: %v", err)}, nil
	}
	defer lease.Release()

	ctx, cancel := context.WithTimeout(waitCtx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-c", code)
	// Resolve the python child's working directory in this priority order so
	// the .tmp/.cache/.config/.local scratch dirs created by
	// preparePythonWorkspace land inside an Allow_List root (R8.7, R8.10):
	//
	//   1. sc.ScanDir — when a Scan_Context owns the invocation, all
	//      python-tool side effects must stay inside that scan's working
	//      directory.
	//   2. terminal.GetWorkDirForContext — honors any explicit cd performed
	//      via the terminal tool inside the same agent session, so python
	//      and shell stay in sync.
	//   3. cfg.WorkspaceRoot (= Data_Dir) — the CLI / no-Scan_Context
	//      fallback. Per R8.10, no Filesystem_Tool is allowed to fall back
	//      to $CWD here; WorkspaceRoot is always an Allow_List descendant.
	scanDir := ""
	if sc := scanctx.Get(contextID); sc != nil && sc.ScanDir != "" {
		scanDir = sc.ScanDir
	} else if wd := terminal.GetWorkDirForContext(contextID); wd != "" {
		scanDir = wd
	} else {
		scanDir = config.Get().WorkspaceRoot
	}
	cmd.Dir = filepath.Clean(scanDir)
	preparePythonWorkspace(cmd.Dir)
	// pythonWorkspaceEnv roots HOME, TMPDIR, and XDG_{CACHE,CONFIG,DATA}_HOME
	// at cmd.Dir, which is now guaranteed to be sc.ScanDir or
	// cfg.WorkspaceRoot — both Allow_List descendants. That satisfies R8.8.
	cmdEnv := pythonWorkspaceEnv(cmd.Dir)
	if config.Get().ProxyRequired || egressproxy.Required() {
		cmdEnv, err = egressproxy.Environment(cmdEnv)
		if err != nil {
			return tools.Result{}, fmt.Errorf("required proxy unavailable: %w", err)
		}
	}
	cmd.Env = cmdEnv
	configureProcessGroupKill(cmd)

	stdout := iolimit.New(1 << 20)
	stderr := iolimit.New(1 << 19)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to start python process: %v", err)}, nil
	}
	terminal.ApplyProcessLimitsWithLimit(cmd, true, lease.MemoryLimitBytes())

	// Register with terminal so watchdog knows we are active
	cleanCode := code
	if len(cleanCode) > 100 {
		cleanCode = cleanCode[:100] + "..."
	}
	terminal.TrackProcessForContext(contextID, cmd, cancel, "python: "+strings.ReplaceAll(cleanCode, "\n", " "))
	defer terminal.UntrackProcessForContext(contextID, cmd)

	waitErr := cmd.Wait()

	var b strings.Builder
	if stdout.Len() > 0 {
		out := stdout.String()
		if len(out) > 15000 {
			out = out[:15000] + "\n... [OUTPUT TRUNCATED]"
		}
		b.WriteString(out)
		if stdout.Truncated() {
			b.WriteString("\n... [OUTPUT TRUNCATED: exceeded 1MB]")
		}
	}

	if stderr.Len() > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		errOut := stderr.String()
		if len(errOut) > 5000 {
			errOut = errOut[:5000] + "\n... [TRUNCATED]"
		}
		b.WriteString(errOut)
		if stderr.Truncated() {
			b.WriteString("\n... [STDERR TRUNCATED: exceeded 512KB]")
		}
	}

	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			b.WriteString(fmt.Sprintf("\n[TIMEOUT: exceeded %ds]", timeoutSec))
		} else {
			exitErr := &exec.ExitError{}
			if errors.As(waitErr, &exitErr) {
				b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitErr.ExitCode()))
			}
		}
	}

	if b.Len() == 0 {
		b.WriteString("(no output)")
	}

	return tools.Result{Output: b.String()}, nil
}

func pythonWaitContext(contextID string) context.Context {
	if sc := scanctx.Get(contextID); sc != nil && sc.Ctx != nil {
		return sc.Ctx
	}
	return context.Background()
}

// preparePythonWorkspace creates the .tmp/.cache/.config/.local/share scratch
// dirs that pythonWorkspaceEnv exports to the child via HOME, TMPDIR, and
// XDG_*. Callers MUST pass a workDir that is an Allow_List descendant
// (sc.ScanDir or cfg.WorkspaceRoot per R8.7, R8.10); this function does not
// validate the path itself and would otherwise leak directories into $CWD.
func preparePythonWorkspace(workDir string) {
	_ = os.MkdirAll(filepath.Join(workDir, ".tmp"), 0o700)
	_ = os.MkdirAll(filepath.Join(workDir, ".cache"), 0o700)
	_ = os.MkdirAll(filepath.Join(workDir, ".config"), 0o700)
	_ = os.MkdirAll(filepath.Join(workDir, ".local", "share"), 0o700)
}

func pythonWorkspaceEnv(workDir string) []string {
	replace := map[string]bool{
		"HOME":                    true,
		"TMPDIR":                  true,
		"XDG_CACHE_HOME":          true,
		"XDG_CONFIG_HOME":         true,
		"XDG_DATA_HOME":           true,
		"XALGORIX_WORKSPACE":      true,
		"PYTHONDONTWRITEBYTECODE": true,
	}
	env := make([]string, 0, len(os.Environ())+7)
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && replace[key] {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"HOME="+workDir,
		"TMPDIR="+filepath.Join(workDir, ".tmp"),
		"XDG_CACHE_HOME="+filepath.Join(workDir, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(workDir, ".config"),
		"XDG_DATA_HOME="+filepath.Join(workDir, ".local", "share"),
		"XALGORIX_WORKSPACE="+workDir,
		"PYTHONDONTWRITEBYTECODE=1",
	)
}
