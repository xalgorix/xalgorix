package terminal

import "testing"

func TestProcessGuardBlocksHostWideProcessCommands(t *testing.T) {
	blocked := []string{
		"kill -9 -1",
		"kill -KILL -1",
		"kill -s KILL -1",
		"kill --signal=9 -1",
		"kill -- -1",
		"kill -9 -- -1",
		"sudo kill -9 -1",
		"echo cleanup; kill -9 -1 2>/dev/null",
		"killall5 -9",
		"pkill nginx",
		"pkill -9 -f '^/usr/sbin/sshd'",
		"killall -9 xalgorix",
		"pkill -f 'xalgorix.*--web'",
		"pkill systemd-resolved",
		"systemctl stop nginx",
		"systemctl --no-block restart ssh",
		"sudo systemctl kill xalgorix",
		"systemctl reboot",
		"service nginx stop",
		"service ssh restart",
		"/etc/init.d/nginx stop",
		"telinit 1",
	}
	for _, cmd := range blocked {
		for _, isolated := range []bool{true, false} {
			if reason := processGuardReason(cmd, isolated); reason == "" {
				t.Errorf("processGuardReason(%q, isolated=%v) allowed it; want blocked", cmd, isolated)
			}
		}
	}
}

func TestProcessGuardAllowsScanOwnProcessCommands(t *testing.T) {
	allowed := []string{
		"kill 1234",
		"kill -9 1234",
		"kill -1 1234",  // SIGHUP to one process
		"kill -1",       // a signal with no PID: kill errors out, signals no one
		"kill -9 -1234", // one process group
		"kill %1",       // a job of this shell
		"kill -l",       // list signal names
		"pkill -f 'python3 -m http.server 8000'",
		"pkill -f /root/.xalgorix/data/target/work/server.py",
		"pkill -f init_db.py",
		"killall ncat",
		"systemctl status nginx",
		"systemctl list-units --type=service",
		"service --status-all",
		"service nginx status",
		"curl -s https://example.com/api/stop",
		"grep -r 'systemctl stop' .",
		"echo kill -9 -1",
		"nmap -p 22 example.com",
	}
	for _, cmd := range allowed {
		for _, isolated := range []bool{true, false} {
			if reason := processGuardReason(cmd, isolated); reason != "" {
				t.Errorf("processGuardReason(%q, isolated=%v) = %q; want allowed", cmd, isolated, reason)
			}
		}
	}
}

// A model once ran the first command as root and killed unrelated host
// services. Inside the scan's PID namespace ps lists only the scan's own
// processes, so it can only hurt the scan. Without the namespace it reaches
// the whole machine and is refused.
func TestProcessGuardPSListingKillDependsOnIsolation(t *testing.T) {
	cmds := []string{
		`ps aux 2>/dev/null | awk 'NR>1 {print $2}' | head -300 | xargs -r kill -9 2>/dev/null; sleep 2; echo "remaining: $(ps aux 2>/dev/null | wc -l)"`,
		`kill -9 $(ps -eo pid= | head -50)`,
		`for p in $(ps -eo pid=); do kill $p; done`,
		`ps aux | grep server.py | awk '{print $2}' | xargs kill`,
	}
	for _, cmd := range cmds {
		if reason := processGuardReason(cmd, true); reason != "" {
			t.Errorf("isolated: processGuardReason(%q) = %q; want allowed", cmd, reason)
		}
		if reason := processGuardReason(cmd, false); reason == "" {
			t.Errorf("not isolated: processGuardReason(%q) allowed it; want blocked", cmd)
		}
	}
	// A listing alone, or a kill by PID alone, is fine either way.
	for _, cmd := range []string{"ps aux | head", "ps -ef | grep nuclei", "kill 4242"} {
		if reason := processGuardReason(cmd, false); reason != "" {
			t.Errorf("not isolated: processGuardReason(%q) = %q; want allowed", cmd, reason)
		}
	}
}
