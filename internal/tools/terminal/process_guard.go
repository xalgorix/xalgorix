package terminal

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// processGuardReason returns why command must not run, or "" when it may. It
// refuses commands aimed at processes or services that are never a scan's own:
// signaling every process, stopping or restarting the host's services, and
// pkill/killall aimed at the host's daemons or the engine itself.
//
// The per-scan PID namespace (scan_namespace_linux.go) is the real boundary
// for kill, pkill and killall, because inside it they cannot reach anything
// outside the scan. This guard covers what the namespace does not: the
// service manager is reached over a socket, not by PID. It also covers hosts
// where the namespace is unavailable. isolated reports whether the command
// will run in the namespace. When it will not, a kill driven by a ps listing
// is refused too. A model once ran exactly that as root, taking the host's
// unrelated services for its own leftovers:
// "ps aux | awk '{print $2}' | head -300 | xargs kill -9".
//
// Like isBlockedCommand this is a best-effort check on the command text, not a
// security boundary: it does not look inside quoted scripts (bash -c "..."),
// eval, or interpreters.
func processGuardReason(command string, isolated bool) string {
	for _, simple := range shellSegments(command) {
		chain, word, args := parseInvokedCommand(simple)
		if len(chain) == 0 {
			continue
		}
		switch name := chain[len(chain)-1]; name {
		case "kill":
			if killTargetsEveryProcess(args) {
				return "kill -1 signals every process the user can reach, not just this scan's"
			}
		case "killall5":
			return "killall5 signals every process on the machine"
		case "pkill", "killall":
			if target := hostDaemonTarget(args); target != "" {
				return fmt.Sprintf("%s %s targets a host service or the scanner itself, never a process this scan started", name, target)
			}
		case "systemctl":
			if verb := firstMatchingArg(args, systemctlHostVerbs); verb != "" {
				return fmt.Sprintf("systemctl %s changes the host's services or power state", verb)
			}
		case "service", "rc-service", "initctl":
			if action := firstMatchingArg(args, serviceStopActions); action != "" {
				return fmt.Sprintf("%s ... %s stops or restarts a host service", name, action)
			}
		case "telinit":
			return "telinit changes the host's runlevel"
		default:
			if strings.Contains(word, "/init.d/") || strings.Contains(word, "/rc.d/") {
				if action := firstMatchingArg(args, serviceStopActions); action != "" {
					return fmt.Sprintf("%s %s stops or restarts a host service", word, action)
				}
			}
		}
	}
	if !isolated && commandInvokesTool(command, "ps") && commandInvokesTool(command, "kill") {
		return "killing processes picked from a ps listing can hit the host's services, the scanner, or other scans, because this command does not run in an isolated process namespace"
	}
	return ""
}

// killTargetsEveryProcess reports whether kill's arguments name PID -1, which
// signals every process the caller may signal. "kill -1" alone sends signal 1
// (SIGHUP) to no one; "kill -9 -1", "kill -s KILL -1" and "kill -- -1" target
// everything. A negative PID other than -1 is one process group, so it is left
// alone.
func killTargetsEveryProcess(args []string) bool {
	i := 0
	for i < len(args) {
		a := unquoteWord(args[i])
		switch {
		case a == "--":
			i++
			return containsWord(args[i:], "-1")
		case a == "-s" || a == "-n" || a == "--signal":
			i += 2
		case strings.HasPrefix(a, "--signal="):
			i++
		case a == "-l" || a == "-L" || a == "--list" || a == "--table" || strings.HasPrefix(a, "--list="):
			return false
		case i == 0 && strings.HasPrefix(a, "-") && len(a) > 1:
			i++ // the first -N / -NAME is the signal
		default:
			return containsWord(args[i:], "-1")
		}
	}
	return false
}

// hostDaemons are programs that belong to the host or to the scanner itself,
// never to a scan. Any systemd-* daemon counts too.
var hostDaemons = map[string]bool{
	"xalgorix": true, "sshd": true, "nginx": true, "dockerd": true,
	"containerd": true, "cloudflared": true, "init": true,
}

var leadingProgramNameRE = regexp.MustCompile(`^[a-z0-9_-]+`)

// hostDaemonTarget returns the first pkill/killall pattern whose program name
// is a host daemon. Only the program name counts (the first word, without a
// leading ^ or directory), so "pkill -f /root/.xalgorix/data/.../server.py"
// is the scan's own server, while "pkill nginx", "pkill -f '^/usr/sbin/sshd'"
// and "killall -9 xalgorix" are not.
func hostDaemonTarget(args []string) string {
	for _, a := range args {
		a = unquoteWord(a)
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		first := strings.Fields(a)[0]
		first = path.Base(strings.TrimLeft(first, "^"))
		name := leadingProgramNameRE.FindString(strings.ToLower(first))
		if hostDaemons[name] || strings.HasPrefix(name, "systemd") {
			return a
		}
	}
	return ""
}

var systemctlHostVerbs = map[string]bool{
	"stop": true, "kill": true, "restart": true, "try-restart": true,
	"reload-or-restart": true, "try-reload-or-restart": true, "condrestart": true,
	"force-reload": true, "disable": true, "mask": true, "isolate": true,
	"freeze": true, "halt": true, "poweroff": true, "reboot": true, "kexec": true,
	"soft-reboot": true, "suspend": true, "hibernate": true, "hybrid-sleep": true,
	"suspend-then-hibernate": true, "rescue": true, "emergency": true,
	"exit": true, "switch-root": true,
}

var serviceStopActions = map[string]bool{
	"stop": true, "restart": true, "force-reload": true, "force-restart": true,
	"try-restart": true, "condrestart": true, "kill": true, "force-stop": true,
}

func firstMatchingArg(args []string, set map[string]bool) string {
	for _, a := range args {
		if a = strings.ToLower(unquoteWord(a)); set[a] {
			return a
		}
	}
	return ""
}

func containsWord(args []string, want string) bool {
	for _, a := range args {
		if unquoteWord(a) == want {
			return true
		}
	}
	return false
}

func unquoteWord(s string) string {
	return strings.Trim(strings.TrimRight(s, ";&|)"), `"'`)
}
