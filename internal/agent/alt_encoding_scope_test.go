package agent

import (
	"errors"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func altEncodingGuardAgent(t *testing.T) *Agent {
	t.Helper()
	withScopeguardLookupHost(t, func(string) ([]string, error) {
		return nil, errors.New("no such host")
	})
	a := &Agent{localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9137}}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
	return a
}

// Gated tools connect with curl, Python and a browser, which read these
// spellings as this machine. Before, the guard classified them as
// unresolvable names and let the call through.
func TestShouldBlockForOutOfScope_AlternateLoopbackSpellings(t *testing.T) {
	a := altEncodingGuardAgent(t)
	cases := []struct {
		tool string
		args map[string]string
	}{
		{"terminal_execute", map[string]string{"command": "curl -s http://2130706433:9137/api/settings"}},
		{"terminal_execute", map[string]string{"command": "curl 2130706433:9137"}},
		{"terminal_execute", map[string]string{"command": "curl http://0x7f.0.0.1:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl http://0177.0.0.1:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl http://127.1:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl 0x7f000001:9137"}},
		{"terminal_execute", map[string]string{"command": "curl http://0:9137/"}},
		{"terminal_execute", map[string]string{"command": "nc 0177.0.0.1 9137"}},
		{"terminal_execute", map[string]string{"command": "curl http://127.000.000.001:8080/"}},
		{"terminal_execute", map[string]string{"command": "curl http://foo.localhost:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl 'http://%31%32%37.0.0.1:9137/'"}},
		{"terminal_execute", map[string]string{"command": "curl http://[::ffff:127.0.0.1]:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl http://user@[::1]:8080/"}},
		{"python_action", map[string]string{"code": "requests.get('http://2130706433:9137/api/version')"}},
		{"browser_action", map[string]string{"action": "goto", "url": "http://１２７.０.０.１:9137/"}},
		{"browser_action", map[string]string{"action": "goto", "url": "http://127.0.0.1.:9137/"}},
		// URL spellings browsers, curl and Python accept.
		{"browser_action", map[string]string{"action": "goto", "url": "http:/127.0.0.1:9137/api/settings"}},
		{"browser_action", map[string]string{"action": "goto", "url": "http://1\t27.0.0.1:9137/"}},
		{"terminal_execute", map[string]string{"command": "curl http:///127.0.0.1:9137/api/settings"}},
		{"terminal_execute", map[string]string{"command": `curl 'http://x.com\@127.0.0.1/'`}},
		{"python_action", map[string]string{"code": `urllib.request.urlopen('http://loc\talhost:9137/api/settings')`}},
		// Schemeless host/path and bare IPv6.
		{"terminal_execute", map[string]string{"command": "curl 127.0.0.1/"}},
		{"terminal_execute", map[string]string{"command": "curl -s localhost/api/settings"}},
		{"terminal_execute", map[string]string{"command": "wget -qO- 127.0.0.1/admin"}},
		{"terminal_execute", map[string]string{"command": "curl 127.0.0.1:9137/api/settings"}},
		{"terminal_execute", map[string]string{"command": "curl user@127.0.0.1/"}},
		// Other schemes curl accepts with one slash, bracketed IPv6 outside
		// URLs, escaped tabs and zero-width joiners.
		{"terminal_execute", map[string]string{"command": "curl gopher:/127.0.0.1:9137/_GET%20/api/settings"}},
		{"terminal_execute", map[string]string{"command": "curl dict:/127.0.0.1:9137/info"}},
		{"terminal_execute", map[string]string{"command": "curl -g '[::1]:9137/'"}},
		{"terminal_execute", map[string]string{"command": "curl -g '[::ffff:127.0.0.1]:9137/api/settings'"}},
		{"terminal_execute", map[string]string{"command": "curl --resolve pentest-ground.com:443:[::ffff:127.0.0.1] https://pentest-ground.com/"}},
		{"terminal_execute", map[string]string{"command": "socat - TCP6:[::ffff:127.0.0.1]:9137"}},
		{"terminal_execute", map[string]string{"command": "socat - TCP:127.0.0.1:9137"}},
		{"terminal_execute", map[string]string{"command": "curl 127.0.0.1/1 && curl -s localhost/123"}},
		{"terminal_execute", map[string]string{"command": "nmap -sV 127.0.0.1/32"}},
		{"terminal_execute", map[string]string{"command": "scp notes.txt root@127.0.0.1:/tmp/"}},
		{"terminal_execute", map[string]string{"command": "rsync -a ./out/ 127.0.0.1:/srv/www/"}},
		{"browser_action", map[string]string{"action": "goto", "url": "http:/loc\talhost:9137/"}},
		{"browser_action", map[string]string{"action": "goto", "url": "http://loc\talhost%2e:9137/"}},
		{"python_action", map[string]string{"code": `urlopen('http://loc\x09alhost:9137/api/settings')`}},
		{"python_action", map[string]string{"code": `urlopen('http://1\01127.0.0.1:9137/api/settings')`}},
		{"terminal_execute", map[string]string{"command": "curl 'http://local" + string(rune(0x200d)) + "host:9137/api/settings'"}},
		{"terminal_execute", map[string]string{"command": "nc ::1 9137"}},
		{"terminal_execute", map[string]string{"command": "nc -6 :: 9137"}},
		{"terminal_execute", map[string]string{"command": "nc ::ffff:127.0.0.1 9137"}},
		{"python_action", map[string]string{"code": "socket.create_connection(('::1', 9137))"}},
		// curl options that name the address to connect to.
		{"terminal_execute", map[string]string{"command": "curl --resolve pentest-ground.com:443:127.0.0.1 https://pentest-ground.com/"}},
		{"terminal_execute", map[string]string{"command": "curl --connect-to pentest-ground.com:443:2130706433:9137 https://pentest-ground.com/"}},
	}
	for _, tc := range cases {
		if blocked, _ := a.shouldBlockForOutOfScope(tc.tool, tc.args); !blocked {
			t.Errorf("%s %v: want blocked", tc.tool, tc.args)
		}
	}
}

// Numbers before a colon in ordinary code, times and ratios, numeric
// versions, and numeric forms of public addresses stay allowed.
func TestShouldBlockForOutOfScope_NumericTokensThatAreNotLocalHosts(t *testing.T) {
	a := altEncodingGuardAgent(t)
	cases := []struct {
		tool string
		args map[string]string
	}{
		{"python_action", map[string]string{"code": "print(resp.text[0:500])"}},
		{"python_action", map[string]string{"code": "rows = data[0:]\nrev = data[::1]"}},
		{"python_action", map[string]string{"code": "x = 0.0\ny = 127.0"}},
		{"terminal_execute", map[string]string{"command": "date -d 08:30 && echo 00:1a:2b"}},
		{"terminal_execute", map[string]string{"command": "ffmpeg -aspect 16:9 -ss 00:00:05 in.mp4 out.mp4"}},
		{"terminal_execute", map[string]string{"command": "searchsploit 10.0.19041.1"}},
		{"terminal_execute", map[string]string{"command": "echo key 1731470000000:session"}},
		{"terminal_execute", map[string]string{"command": "curl http://134744072/ http://0x08080808/"}},
		{"terminal_execute", map[string]string{"command": "curl https://pentest-ground.com/"}},
		{"python_action", map[string]string{"code": "hdr = data[0x0:0x10]\nchunk = mem[0x7fffffff:0x80000000]"}},
		{"python_action", map[string]string{"code": "df = données_brutes.head()\nfrom naïve_bayes.model import fit\nb = a[::]"}},
		{"terminal_execute", map[string]string{"command": "cat rapport_été.docx | head"}},
		{"terminal_execute", map[string]string{"command": "echo $((10/20)) 12:30:45 00:1a:2b:3c:4d:5e 'std::vector<int>' x[1:2:3]"}},
		{"terminal_execute", map[string]string{"command": "printf 'a\\tb\\n' && cat /etc/hosts && ls ./dir/file"}},
		{"python_action", map[string]string{"code": "print(\"Scanning http://10.10.10.5\n80/tcp open\")\nhdr = data[0x0:0x10:2]"}},
		{"report_vulnerability", map[string]string{"description": "Target: http://10.10.10.5\n443/tcp open https. Security group allows 0.0.0.0/0 on port 22."}},
		{"terminal_execute", map[string]string{"command": "lspci -s 0000:00:1f.3; exiftool -AllDates='0000:00:00 00:00:00' img.jpg"}},
		{"terminal_execute", map[string]string{"command": "aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0,::/0"}},
		{"terminal_execute", map[string]string{"command": "nmap -sn 10.0.0.0/8"}},
		{"python_action", map[string]string{"code": "half = 2147483647/2\nrow = arr[0, ::]\ncol = a[::1, 0]"}},
	}
	for _, tc := range cases {
		if blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args); blocked {
			t.Errorf("%s %v: blocked: %s", tc.tool, tc.args, reason)
		}
	}
}

func TestExtractBracketedURLHosts(t *testing.T) {
	got := extractBracketedURLHosts("curl http://[::1]:80/ http://u@[::FFFF:127.0.0.1]/ x[::1] [::2] //[ ::1]")
	want := []string{"::1", "::ffff:127.0.0.1"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}
