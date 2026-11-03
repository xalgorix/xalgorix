package terminal

import (
	"testing"
	"time"
)

func TestCapDirbusterRuntime(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "ffuf without maxtime gets capped",
			in:   "ffuf -u http://t/FUZZ -w wl.txt -mc 200",
			want: "ffuf -u http://t/FUZZ -w wl.txt -mc 200 -maxtime 180 -noninteractive",
		},
		{
			name: "ffuf piped to head caps the ffuf stage only",
			in:   "ffuf -u http://t/FUZZ -w wl.txt | head -60",
			want: "ffuf -u http://t/FUZZ -w wl.txt -maxtime 180 -noninteractive | head -60",
		},
		{
			name: "ffuf with explicit maxtime is preserved",
			in:   "ffuf -u http://t/FUZZ -w wl.txt -maxtime 30",
			want: "ffuf -u http://t/FUZZ -w wl.txt -maxtime 30 -noninteractive",
		},
		{
			name: "ffuf excessive maxtime is reduced",
			in:   "ffuf -u http://t/FUZZ -w wl.txt -maxtime 900 -noninteractive",
			want: "ffuf -u http://t/FUZZ -w wl.txt -maxtime 180 -noninteractive",
		},
		{
			name: "feroxbuster without time-limit gets capped",
			in:   "feroxbuster -u http://t -w wl.txt -x php",
			want: "feroxbuster -u http://t -w wl.txt -x php --time-limit 180s",
		},
		{
			name: "feroxbuster with time-limit preserved",
			in:   "feroxbuster -u http://t --time-limit 60s",
			want: "feroxbuster -u http://t --time-limit 60s",
		},
		{
			name: "dirsearch without max-time gets capped",
			in:   "dirsearch -u http://t -w wl.txt",
			want: "dirsearch -u http://t -w wl.txt --max-time 180",
		},
		{
			name: "non-dirbuster command untouched",
			in:   "curl -sk http://t/login",
			want: "curl -sk http://t/login",
		},
		{
			name: "sqlmap is not capped",
			in:   "sqlmap -u http://t --batch --dump",
			want: "sqlmap -u http://t --batch --dump",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapDirbusterRuntime(tc.in); got != tc.want {
				t.Errorf("CapDirbusterRuntime(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestContentDiscoveryCommandTimeout(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want time.Duration
		ok   bool
	}{
		{name: "ffuf explicit shorter limit", cmd: "ffuf -u http://t/FUZZ -maxtime 60 -noninteractive | head", want: 75 * time.Second, ok: true},
		{name: "ffuf default cap", cmd: "ffuf -u http://t/FUZZ -w wl.txt", want: 195 * time.Second, ok: true},
		{name: "gobuster process backstop", cmd: "gobuster dir -u http://t -w wl.txt", want: 195 * time.Second, ok: true},
		{name: "ordinary command", cmd: "curl -sk http://t", ok: false},
		// Each run is bounded by its own -maxtime; the command deadline covers
		// all of them instead of killing the loop after the first.
		{name: "two sequential ffuf runs", cmd: "ffuf -u http://t/a/FUZZ -w w.txt; ffuf -u http://t/b/FUZZ -w w.txt", want: 390 * time.Second, ok: true},
		{name: "ffuf in a for loop", cmd: "for p in a b c d; do ffuf -u http://t/$p/FUZZ -w w.txt -maxtime 60; done", want: heavyCmdTimeout, ok: true},
		{name: "ffuf in a while-read loop", cmd: "while read u; do\n  ffuf -u $u/FUZZ -w w.txt\ndone < urls.txt", want: heavyCmdTimeout, ok: true},
		{name: "ffuf under xargs", cmd: "cat urls | xargs -I{} ffuf -u {}/FUZZ -w w.txt", want: heavyCmdTimeout, ok: true},
		{name: "loop before a single ffuf", cmd: "for p in a b; do echo $p; done; ffuf -u http://t/FUZZ -w w.txt", want: 195 * time.Second, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := contentDiscoveryCommandTimeout(tc.cmd)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("contentDiscoveryCommandTimeout(%q) = %s, %v; want %s, %v", tc.cmd, got, ok, tc.want, tc.ok)
			}
		})
	}
}
