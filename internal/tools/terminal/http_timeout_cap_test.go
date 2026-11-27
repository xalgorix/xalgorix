package terminal

import "testing"

func TestCapHTTPRequestTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare curl gets connect-timeout and max-time",
			in:   "curl -s http://t/",
			want: "curl -s http://t/ --connect-timeout 10 --max-time 180",
		},
		{
			name: "explicit --connect-timeout is preserved, only max-time added",
			in:   "curl --connect-timeout 3 http://t/",
			want: "curl --connect-timeout 3 http://t/ --max-time 180",
		},
		{
			name: "explicit --max-time is preserved, only connect added",
			in:   "curl --max-time 60 http://t/",
			want: "curl --max-time 60 http://t/ --connect-timeout 10",
		},
		{
			name: "short -m max-time is preserved",
			in:   "curl -m 90 http://t/",
			want: "curl -m 90 http://t/ --connect-timeout 10",
		},
		{
			name: "both already set leaves the command unchanged",
			in:   "curl --connect-timeout 5 --max-time 45 http://t/",
			want: "curl --connect-timeout 5 --max-time 45 http://t/",
		},
		{
			name: "non-curl command is untouched",
			in:   "wget http://t/ -O out",
			want: "wget http://t/ -O out",
		},
		{
			name: "curl stage in a pipe gets flags, downstream stage untouched",
			in:   "curl -s http://t/ | grep token",
			want: "curl -s http://t/ --connect-timeout 10 --max-time 180 | grep token",
		},
		{
			name: "curl inside a shell loop body is bounded",
			in:   "for u in a b c; do curl -s http://t/$u; done",
			want: "for u in a b c; do curl -s http://t/$u --connect-timeout 10 --max-time 180; done",
		},
		{
			name: "a --max-time query param in the URL is not mistaken for the flag",
			in:   "curl -s 'http://t/?x=--max-time'",
			want: "curl -s 'http://t/?x=--max-time' --connect-timeout 10 --max-time 180",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapHTTPRequestTimeout(tc.in); got != tc.want {
				t.Errorf("CapHTTPRequestTimeout(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

// A time-based injection payload delays the RESPONSE, not the connection. The
// injected --connect-timeout must never shorten such a request, so coverage of
// time-based classes is preserved; only the loose --max-time backstop is added,
// and it sits far above any realistic payload delay.
func TestCapHTTPRequestTimeout_PreservesTimeBasedPayloads(t *testing.T) {
	in := "curl -s 'http://t/?id=1%27%20OR%20SLEEP(25)--'"
	got := CapHTTPRequestTimeout(in)
	if got != in+" --connect-timeout 10 --max-time 180" {
		t.Fatalf("unexpected rewrite: %q", got)
	}
	if httpRequestMaxTimeSeconds <= 25 {
		t.Errorf("max-time backstop %d would truncate a 25s time-based payload", httpRequestMaxTimeSeconds)
	}
}
