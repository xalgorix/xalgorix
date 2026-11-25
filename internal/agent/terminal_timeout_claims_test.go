package agent

import (
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// TestTerminalExecuteDescriptionStatesWatchdogLimit ties the heavy-tool limit
// in the terminal_execute description to the watchdog that enforces it during
// a scan (issue #931). The terminal tool's own heavy-tool deadline is longer,
// so the watchdog limit is the one the model actually gets.
func TestTerminalExecuteDescriptionStatesWatchdogLimit(t *testing.T) {
	reg := tools.NewRegistry()
	terminal.Register(reg)
	tool, ok := reg.Get("terminal_execute")
	if !ok {
		t.Fatal("terminal_execute is not registered")
	}
	match := regexp.MustCompile(`up to (\d+) minutes for heavy tools`).FindStringSubmatch(tool.Description)
	if match == nil {
		t.Fatalf("description does not state a heavy-tool limit:\n%s", tool.Description)
	}
	minutes, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("heavy-tool limit %q: %v", match[1], err)
	}
	if stated := time.Duration(minutes) * time.Minute; stated != watchdogProcessMaxDuration {
		t.Errorf("description gives heavy tools %s, but the watchdog kills commands after %s",
			stated, watchdogProcessMaxDuration)
	}
}
