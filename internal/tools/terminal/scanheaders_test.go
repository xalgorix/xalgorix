package terminal

import "testing"

func TestInjectScanHeaders(t *testing.T) {
	one := []string{"X-Bug-Bounty: ulises2k"}
	two := []string{"X-Bug-Bounty: ulises2k", "X-Scan-ID: e-42"}
	withUA := []string{"X-Bug-Bounty: ulises2k", "User-Agent: Xalgorix-run"}
	tests := []struct {
		name    string
		cmd     string
		headers []string
		want    string
	}{
		{
			name:    "no headers configured is a no-op",
			cmd:     "httpx -silent -u https://t.com",
			headers: nil,
			want:    "httpx -silent -u https://t.com",
		},
		{
			name:    "httpx gets the header",
			cmd:     "httpx -silent -u https://t.com",
			headers: one,
			want:    "httpx -silent -u https://t.com -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "nuclei gets the header",
			cmd:     "nuclei -u https://t.com -severity high",
			headers: one,
			want:    "nuclei -u https://t.com -severity high -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "non-HTTP tool is untouched",
			cmd:     "nmap -sV t.com",
			headers: one,
			want:    "nmap -sV t.com",
		},
		{
			name:    "a tool only mentioned as an argument is untouched",
			cmd:     "grep -c curl notes.txt",
			headers: one,
			want:    "grep -c curl notes.txt",
		},
		{
			name:    "curl gets the header",
			cmd:     "curl -s https://t.com",
			headers: one,
			want:    "curl -s https://t.com -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "wget gets the header through --header, never -H",
			cmd:     "wget -q https://t.com",
			headers: one,
			want:    "wget -q https://t.com --header='X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "curl in a pipe is rewritten",
			cmd:     "cat hosts.txt | curl -s -K -",
			headers: one,
			want:    "cat hosts.txt | curl -s -K - -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "curl behind xargs is rewritten",
			cmd:     "cat urls.txt | xargs -I{} curl -s {}",
			headers: one,
			want:    "cat urls.txt | xargs -I{} curl -s {} -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "curl in a loop body is rewritten",
			cmd:     "for u in $(cat urls.txt); do curl -s \"$u\"; done",
			headers: one,
			want:    "for u in $(cat urls.txt); do curl -s \"$u\" -H 'X-Bug-Bounty: ulises2k'; done",
		},
		{
			name:    "an existing curl header is not duplicated",
			cmd:     `curl -s https://t.com -H 'x-bug-bounty: someoneelse'`,
			headers: one,
			want:    `curl -s https://t.com -H 'x-bug-bounty: someoneelse'`,
		},
		{
			name:    "an existing wget --header is not duplicated",
			cmd:     `wget -q https://t.com --header="X-Bug-Bounty: someoneelse"`,
			headers: one,
			want:    `wget -q https://t.com --header="X-Bug-Bounty: someoneelse"`,
		},
		{
			name:    "curl -A keeps the agent's User-Agent",
			cmd:     `curl -s -A "() { :; }; echo vulnerable" https://t.com`,
			headers: withUA,
			want:    `curl -s -A "() { :; }; echo vulnerable" https://t.com -H 'X-Bug-Bounty: ulises2k'`,
		},
		{
			name:    "curl --user-agent keeps the agent's User-Agent",
			cmd:     "curl --user-agent=probe https://t.com",
			headers: withUA,
			want:    "curl --user-agent=probe https://t.com -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "wget -U keeps the agent's User-Agent",
			cmd:     "wget -q -U probe https://t.com",
			headers: withUA,
			want:    "wget -q -U probe https://t.com --header='X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "curl without a User-Agent option gets the operator one",
			cmd:     "curl -s https://t.com",
			headers: withUA,
			want:    "curl -s https://t.com -H 'X-Bug-Bounty: ulises2k' -H 'User-Agent: Xalgorix-run'",
		},
		{
			name:    "a wrapper option before curl is not read as curl's",
			cmd:     "stdbuf -eL curl -s https://t.com",
			headers: []string{"Referer: https://scan.example"},
			want:    "stdbuf -eL curl -s https://t.com -H 'Referer: https://scan.example'",
		},
		{
			name:    "curl and wget stages each use their own syntax",
			cmd:     "curl -s https://t.com/a | wget -q -i -",
			headers: one,
			want:    "curl -s https://t.com/a -H 'X-Bug-Bounty: ulises2k' | wget -q -i - --header='X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "only the httpx stage of a pipe is rewritten",
			cmd:     "cat subs.txt | httpx -silent -status-code",
			headers: one,
			want:    "cat subs.txt | httpx -silent -status-code -H 'X-Bug-Bounty: ulises2k'",
		},
		{
			name:    "multiple headers each get a -H",
			cmd:     "httpx -u https://t.com",
			headers: two,
			want:    "httpx -u https://t.com -H 'X-Bug-Bounty: ulises2k' -H 'X-Scan-ID: e-42'",
		},
		{
			name:    "an already-present header is not duplicated",
			cmd:     `httpx -u https://t.com -H "X-Bug-Bounty: someoneelse"`,
			headers: one,
			want:    `httpx -u https://t.com -H "X-Bug-Bounty: someoneelse"`,
		},
		{
			name:    "both httpx and nuclei stages are rewritten",
			cmd:     "httpx -silent | nuclei -silent",
			headers: one,
			want:    "httpx -silent -H 'X-Bug-Bounty: ulises2k' | nuclei -silent -H 'X-Bug-Bounty: ulises2k'",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := injectScanHeaders(tc.cmd, tc.headers)
			if got != tc.want {
				t.Fatalf("injectScanHeaders(%q) =\n  %q\nwant\n  %q", tc.cmd, got, tc.want)
			}
		})
	}
}
