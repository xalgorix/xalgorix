package terminal

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestHasToolCommandMatchesInvocationsOnly(t *testing.T) {
	invokes := []struct{ cmd, tool string }{
		{"arjun -u https://t.test/x", "arjun"},
		{"timeout 300 arjun -u https://t.test/x --stable", "arjun"},
		{"timeout -k 5 300 nmap -sV t.test", "nmap"},
		{"sudo nmap -sV t.test", "nmap"},
		{"FOO=1 ffuf -u https://t.test/FUZZ", "ffuf"},
		{"nohup ffuf -u https://t.test/FUZZ -w w.txt > l 2>&1", "ffuf"},
		{"/root/venv/bin/arjun -u https://t.test/x", "arjun"},
		{"cat urls | xargs -P4 -I{} ffuf -u {}", "ffuf"},
		{"cat urls | xargs -P4 -I{} ffuf -u {}", "xargs"},
		{"for u in a b; do ffuf -u $u; done", "ffuf"},
		{"(cd d && ffuf -u x)", "ffuf"},
		{"mkdir -p tmp\nnuclei -u https://t.test", "nuclei"},
	}
	for _, tc := range invokes {
		if !hasToolCommand(tc.cmd, tc.tool) {
			t.Errorf("hasToolCommand(%q, %q) = false, want true", tc.cmd, tc.tool)
		}
	}
	mentions := []struct{ cmd, tool string }{
		{"which arjun", "arjun"},
		{"arjun_out=1", "arjun"},
		{`echo "=== ffuf root results ==="`, "ffuf"},
		{"for t in ffuf nmap arjun", "ffuf"},
		{"command -v ffuf", "ffuf"},
		{"grep nuclei out.txt", "nuclei"},
		{"cat arjun_user.json", "arjun"},
		{"tr ' ' '\\n' < tmp/prefixes.txt", "ffuf"},
	}
	for _, tc := range mentions {
		if hasToolCommand(tc.cmd, tc.tool) {
			t.Errorf("hasToolCommand(%q, %q) = true, want false (mentioned, not invoked)", tc.cmd, tc.tool)
		}
	}
}

func TestShellSegmentsSplitting(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"newline", "a\nb", []string{"a", "b"}},
		{"background", "ffuf -u x > l 2>&1 & echo y", []string{"ffuf -u x > l 2>&1 ", " echo y"}},
		{"redirections are not separators", "cmd 2>&1 &> f >| g", []string{"cmd 2>&1 &> f >| g"}},
		{"pipe stderr", "a |& b", []string{"a ", " b"}},
		{"quoted operators", `echo "a; b | c" && d`, []string{`echo "a; b | c" `, " d"}},
		{"line continuation", "ffuf -u x \\\n  -w y", []string{"ffuf -u x \\\n  -w y"}},
		{"comment apostrophe does not open a quote", "ffuf -u x # don't\necho y", []string{"ffuf -u x # don't", "echo y"}},
		{"heredoc body is not a command", "cat > f <<'EOF'\nffuf\nnmap; x\nEOF\necho done", []string{"cat > f <<'EOF'", "echo done"}},
		{"tab-stripped heredoc", "cat <<-END\n\tffuf\n\tEND\necho done", []string{"cat <<-END", "echo done"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shellSegments(tc.cmd); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("shellSegments(%q)\n got: %q\nwant: %q", tc.cmd, got, tc.want)
			}
			if got := rewriteShellSegments(tc.cmd, func(s string) string { return s }); got != tc.cmd {
				t.Errorf("identity rewrite changed the command: %q", got)
			}
		})
	}
}

func TestCapDirbusterRuntimePlacement(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ffuf -u http://t/FUZZ -w w.txt # root pass", "ffuf -u http://t/FUZZ -w w.txt -maxtime 180 -noninteractive # root pass"},
		{"(cd d && ffuf -u http://t/FUZZ -w w.txt)", "(cd d && ffuf -u http://t/FUZZ -w w.txt -maxtime 180 -noninteractive)"},
		{"echo start\nffuf -u http://t/FUZZ -w w.txt\necho end", "echo start\nffuf -u http://t/FUZZ -w w.txt -maxtime 180 -noninteractive\necho end"},
		// From a real scan: a tool-availability loop and a banner echo were
		// rewritten with ffuf flags, breaking both.
		{"for t in ffuf nmap arjun whatweb; do command -v $t >/dev/null && echo OK $t; done", "for t in ffuf nmap arjun whatweb; do command -v $t >/dev/null && echo OK $t; done"},
		{`echo "=== ffuf root results ==="; cat ffuf_root.json`, `echo "=== ffuf root results ==="; cat ffuf_root.json`},
		{"cat > w.txt <<'EOF'\nffuf\nEOF", "cat > w.txt <<'EOF'\nffuf\nEOF"},
	}
	for _, tc := range cases {
		if got := CapDirbusterRuntime(tc.in); got != tc.want {
			t.Errorf("CapDirbusterRuntime(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
		}
	}
}

func withRatePolicy(t *testing.T, rps float64) string {
	t.Helper()
	sc := scanctx.New("term-rate-"+t.Name(), t.TempDir())
	sc.SetRequestRatePolicy(scanctx.RequestRatePolicy{MaxRPS: rps, Source: "test"})
	scanctx.Activate(sc)
	t.Cleanup(func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	})
	return sc.ID
}

func TestRatePolicyArjunUsesRealFlags(t *testing.T) {
	id := withRatePolicy(t, 3)
	cases := []struct {
		name string
		cmd  string
		want []string
		bad  []string
	}{
		{"adds -t and --rate-limit, never --threads", "timeout 300 arjun -u https://t.test/api --stable -o out.json 2>&1 | tail -20",
			[]string{"--rate-limit 3", "-t 3", "| tail -20"}, []string{"--threads"}},
		{"caps an existing -t", "arjun -u https://t.test/api -t 20", []string{"-t 3"}, []string{"-t 20"}},
		{"keeps -T (timeout) untouched", "arjun -u https://t.test/api -T 15", []string{"-T 15", "-t 3"}, []string{"--threads"}},
		{"multi-line script rewrites only the arjun line",
			"UA=x\necho \"=== arjun on /api ===\"\ntimeout 300 arjun -u https://t.test/api -q",
			[]string{"echo \"=== arjun on /api ===\"\n", "-q --rate-limit 3 -t 3"}, []string{"=== --", "===\" --"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := NormalizeCommandForRequestRatePolicy(id, tc.cmd)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("got %q, missing %q", got, w)
				}
			}
			for _, b := range tc.bad {
				if strings.Contains(got, b) {
					t.Errorf("got %q, must not contain %q", got, b)
				}
			}
		})
	}
	// Mentions of arjun are never rewritten.
	for _, cmd := range []string{"which arjun", "arjun -h 2>&1 | grep rate", "arjun --version"} {
		got, _ := NormalizeCommandForRequestRatePolicy(id, cmd)
		if strings.Contains(got, "--threads") {
			t.Errorf("%q rewritten with an invalid flag: %q", cmd, got)
		}
	}
	if got, _ := NormalizeCommandForRequestRatePolicy(id, "which arjun"); got != "which arjun" {
		t.Errorf("which arjun was rewritten: %q", got)
	}
}

// << inside (( )) or $(( )) is a left shift, not a here-document: treating it
// as one swallowed the rest of the script as a body, so later tool lines were
// never rewritten.
func TestShellSegmentsArithmeticShiftIsNotHeredoc(t *testing.T) {
	for _, cmd := range []string{
		"n=$((1 << 4))\nffuf -u https://t.test/FUZZ -w w.txt",
		"(( mask = 1<<3 ))\nffuf -u https://t.test/FUZZ -w w.txt",
	} {
		segs := shellSegments(cmd)
		if len(segs) != 2 || !strings.Contains(segs[1], "ffuf") {
			t.Errorf("shellSegments(%q) = %q, want the ffuf line as its own segment", cmd, segs)
		}
	}
	// A real here-document body is still copied through, not split.
	segs := shellSegments("cat <<EOF > f\nffuf -u x\nEOF\nnuclei -u https://t.test")
	if want := []string{"cat <<EOF > f", "nuclei -u https://t.test"}; !reflect.DeepEqual(segs, want) {
		t.Errorf("here-document handling changed: %q", segs)
	}
}

// Single-letter flags are case-sensitive: feroxbuster -T is the timeout and
// xargs -p is the interactive prompt, so capping -t / -P must not touch them.
func TestRatePolicyShortFlagsAreCaseSensitive(t *testing.T) {
	id := withRatePolicy(t, 5)
	got, _ := NormalizeCommandForRequestRatePolicy(id, "feroxbuster -u https://t.test -T 7 -t 50")
	if !strings.Contains(got, "-T 7") || !strings.Contains(got, "-t 5") || strings.Count(got, "-t 5") != 1 {
		t.Errorf("feroxbuster -T/-t rewrite = %q, want -T 7 kept and -t capped once", got)
	}
	got, _ = NormalizeCommandForRequestRatePolicy(id, "cat hosts | xargs -p -I{} curl -s {}")
	if !strings.Contains(got, "xargs -p -I{} curl") {
		t.Errorf("xargs -p (prompt) was rewritten: %q", got)
	}
	got, _ = NormalizeCommandForRequestRatePolicy(id, "cat hosts | xargs -P8 -I{} curl -s {}")
	if !strings.Contains(got, "-P 1") {
		t.Errorf("xargs -P8 not capped: %q", got)
	}
}
