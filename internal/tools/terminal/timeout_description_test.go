package terminal

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// terminalExecuteDescription returns the terminal_execute description the
// model reads.
func terminalExecuteDescription(t *testing.T) string {
	t.Helper()
	reg := tools.NewRegistry()
	Register(reg)
	tool, ok := reg.Get("terminal_execute")
	if !ok {
		t.Fatal("terminal_execute is not registered")
	}
	return tool.Description
}

// TestTerminalExecuteDescriptionMatchesTimeouts keeps the timeout figures in
// the terminal_execute description in step with the code that enforces them
// (issue #931). The heavy-tool figure is the agent watchdog's limit, which
// internal/agent checks; here it only has to fit inside this package's own
// heavy-tool deadline.
func TestTerminalExecuteDescriptionMatchesTimeouts(t *testing.T) {
	desc := terminalExecuteDescription(t)

	wantDefault := fmt.Sprintf("%d-minute timeout by default", int(defaultCmdTimeout/time.Minute))
	if !strings.Contains(desc, wantDefault) {
		t.Errorf("description does not state the default timeout %q:\n%s", wantDefault, desc)
	}

	heavy := regexp.MustCompile(`up to (\d+) minutes for heavy tools like ([a-z/]+)`).FindStringSubmatch(desc)
	if heavy == nil {
		t.Fatalf("description does not state a heavy-tool limit:\n%s", desc)
	}
	minutes, err := strconv.Atoi(heavy[1])
	if err != nil {
		t.Fatalf("heavy-tool limit %q: %v", heavy[1], err)
	}
	if stated := time.Duration(minutes) * time.Minute; stated > heavyCmdTimeout {
		t.Errorf("description gives heavy tools %s, but the terminal deadline for them is %s", stated, heavyCmdTimeout)
	}
	for _, name := range strings.Split(heavy[2], "/") {
		command := name + " -u http://target.test/"
		if computeTimeout(command) != heavyCmdTimeout {
			t.Errorf("description names %q as a heavy tool, but %q gets %s, not the heavy-tool deadline",
				name, command, computeTimeout(command))
		}
	}

	discovery := regexp.MustCompile(`A command that runs content discovery \(([^)]*)\) gets at most about (\d+) minutes per discovery run in it \(less with a smaller ffuf -maxtime\), for the whole command`).FindStringSubmatch(desc)
	if discovery == nil {
		t.Fatalf("description does not state the content-discovery cap:\n%s", desc)
	}
	named := strings.Split(discovery[1], ", ")
	want := append([]string(nil), contentDiscoveryTools...)
	sort.Strings(named)
	sort.Strings(want)
	if strings.Join(named, ",") != strings.Join(want, ",") {
		t.Errorf("description lists content-discovery tools %v, code caps %v", named, want)
	}
	perRun := time.Duration(dirbusterRuntimeCapSeconds)*time.Second + dirbusterGrace
	if capMinutes := int((perRun + 30*time.Second) / time.Minute); discovery[2] != strconv.Itoa(capMinutes) {
		t.Errorf("description gives about %s minutes per discovery run, code allows %s (about %d minutes)",
			discovery[2], perRun, capMinutes)
	}
	for _, name := range contentDiscoveryTools {
		command := name + " -u http://target.test/FUZZ -w words.txt"
		if got := computeTimeout(command); got != perRun {
			t.Errorf("one %s run gets %s, want the per-run cap %s the description states", name, got, perRun)
		}
	}

	// The discovery deadline covers the whole command, including a heavy scan
	// chained in front of it, which is why the description says to run heavy
	// scans separately.
	chained := "nmap -p- target.test | tee ports.txt; ffuf -u http://target.test/FUZZ -w words.txt"
	if got := computeTimeout(chained); got != perRun {
		t.Errorf("%q gets %s, want the one-run discovery deadline %s the description warns about", chained, got, perRun)
	}
	smaller := "nmap -p- target.test; ffuf -u http://target.test/FUZZ -w words.txt -maxtime 60"
	if got, want := computeTimeout(smaller), 60*time.Second+dirbusterGrace; got != want {
		t.Errorf("%q gets %s, want %s: a smaller ffuf -maxtime shortens the whole command, as the description says", smaller, got, want)
	}
	twoRuns := "ffuf -u http://target.test/FUZZ -w words.txt; gobuster dir -u http://target.test/ -w words.txt"
	if got := computeTimeout(twoRuns); got != 2*perRun {
		t.Errorf("%q gets %s, want %s (about %s minutes per discovery run)", twoRuns, got, 2*perRun, discovery[2])
	}

	const loopClaim = "A loop, xargs or parallel over discovery runs shares the heavy-tool limit."
	if !strings.Contains(desc, loopClaim) {
		t.Errorf("description does not say %q:\n%s", loopClaim, desc)
	}
	for _, repeated := range []string{
		"for h in a b; do gobuster dir -u http://$h/ -w words.txt; done",
		"cat hosts.txt | xargs -I{} ffuf -u {}/FUZZ -w words.txt",
		"parallel ffuf -u {}/FUZZ -w words.txt ::: http://a.test http://b.test",
	} {
		if got := computeTimeout(repeated); got != heavyCmdTimeout {
			t.Errorf("%q gets %s, want the heavy-tool deadline %s the description states", repeated, got, heavyCmdTimeout)
		}
	}
}
