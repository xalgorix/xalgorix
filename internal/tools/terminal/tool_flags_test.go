package terminal

import (
	"strings"
	"testing"
)

func TestNormalizeToolFlagsArjun(t *testing.T) {
	cases := []struct{ in, want string }{
		// From a real scan: each of these made arjun exit with
		// "unrecognized arguments" and produce no output file.
		{"arjun -u https://t.test/Api/user --stable --rate-limit 3 --threads 2 --chunk 5 -q",
			"arjun -u https://t.test/Api/user --stable --rate-limit 3 -t 2 -c 5 -q"},
		{"timeout 300 arjun -u https://t.test/Api/user --stable --stable-sleep 2 -o tmp/a.json",
			"timeout 300 arjun -u https://t.test/Api/user --stable -d 2 -o tmp/a.json"},
		{"arjun -u https://t.test/api/otp --stable -m GET -oJ arjun_otp.json",
			"arjun -u https://t.test/api/otp --stable -m GET -o arjun_otp.json"},
		{"arjun --url https://t.test/x --timeout=15 --method POST --wordlist w.txt --output o.json --quiet",
			"arjun -u https://t.test/x -T 15 -m POST -w w.txt -o o.json -q"},
		// Valid flags are left alone, including -T (timeout) and --rate-limit.
		{"arjun -u https://t.test/x -t 2 -T 15 -c 5 --rate-limit 3", "arjun -u https://t.test/x -t 2 -T 15 -c 5 --rate-limit 3"},
		// Only commands that invoke arjun are touched.
		{"echo --threads 2", "echo --threads 2"},
		{"which arjun; echo --chunk 5", "which arjun; echo --chunk 5"},
		{"ffuf -u https://t.test/FUZZ --threads 3", "ffuf -u https://t.test/FUZZ --threads 3"},
	}
	for _, tc := range cases {
		got, note := NormalizeToolFlags(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeToolFlags(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
		}
		if (got != tc.in) != (note != "") {
			t.Errorf("NormalizeToolFlags(%q): notice %q does not match whether the command changed", tc.in, note)
		}
		if note != "" && !strings.Contains(note, "arjun") {
			t.Errorf("notice should name the tool: %q", note)
		}
	}
}
