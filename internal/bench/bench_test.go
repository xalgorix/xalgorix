package bench

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func challengeByName(t *testing.T, name string) Challenge {
	t.Helper()
	for _, c := range Builtin() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no builtin challenge %q", name)
	return Challenge{}
}

// noRedirectClient captures 3xx instead of following them.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestBuiltinChallengesExhibitVuln(t *testing.T) {
	// reflected-xss: payload reflected unescaped.
	xss := challengeByName(t, "reflected-xss").Start()
	defer xss.Close()
	if body := httpGet(t, xss.URL+"/search?q=<script>alert(1)</script>"); !strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("reflected-xss did not reflect payload: %q", body)
	}

	// idor: arbitrary id returns a populated record.
	idor := challengeByName(t, "idor").Start()
	defer idor.Close()
	if body := httpGet(t, idor.URL+"/api/orders/999"); !strings.Contains(body, "user-999") {
		t.Fatalf("idor did not serve arbitrary id: %q", body)
	}

	// open-redirect: 302 to attacker url.
	orc := challengeByName(t, "open-redirect").Start()
	defer orc.Close()
	resp, err := noRedirectClient().Get(orc.URL + "/redirect?url=https://evil.example/")
	if err != nil {
		t.Fatalf("open-redirect request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://evil.example/" {
		t.Fatalf("open-redirect: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// error-sqli: quote triggers a SQL error.
	sqli := challengeByName(t, "error-sqli").Start()
	defer sqli.Close()
	if body := httpGet(t, sqli.URL+"/product?id=1'"); !strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("error-sqli did not leak a SQL error: %q", body)
	}
	// error-sqli must expose ONLY the SQLi signal — no reflected-XSS red herring.
	// The id is HTML-escaped in both the normal and the SQL-error path, so a
	// <script> payload is never reflected raw (which would distract a scanner
	// onto XSS instead of the SQL injection this challenge tests).
	if body := httpGet(t, sqli.URL+"/product?id=<script>alert(1)</script>"); strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("error-sqli must HTML-escape id (no XSS red herring), got %q", body)
	}
	if body := httpGet(t, sqli.URL+"/product?id='<script>alert(1)</script>"); strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("error-sqli must HTML-escape id in the SQL-error path too, got %q", body)
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestClassifyFinding(t *testing.T) {
	cases := []struct {
		title, desc, cwe, want string
	}{
		{"Reflected XSS in search", "", "", "xss"},
		{"Injection issue", "SQL injection via id", "", "sqli"},
		{"Open Redirect on /redirect", "", "", "open_redirect"},
		{"Access another user's order", "insecure direct object reference", "", "idor"},
		{"SSRF in the fetch endpoint", "", "", "ssrf"},
		{"Server-Side Template Injection via name", "template injection", "", "ssti"},
		{"Path traversal in download", "local file inclusion", "", "lfi"},
		{"Command injection in ping", "os command executed", "", "rce"},
		// NoSQL must win over sqli despite "nosql injection" containing "sql
		// inject" (nosqli is ordered before sqli in classKeywords).
		{"NoSQL injection authentication bypass", "operator injection with $ne bypassed login", "", "nosqli"},
		{"Auth bypass via MongoDB operator", "password[$ne] matched any password", "", "nosqli"},
		{"Login bypass", "", "CWE-943", "nosqli"},
		// Regression: a plain SQLi must STILL classify as sqli, not nosqli.
		{"SQL injection in id parameter", "union select 1,2,3", "", "sqli"},
		// CORS: the specific wording classifies as cors, and — critically — wins
		// over a GENERIC access-control CWE (CWE-284) an agent might attach, which
		// would otherwise map to idor. CWE-942/346 also map to cors.
		{"CORS misconfiguration allows credential theft", "reflects arbitrary Origin with Access-Control-Allow-Credentials: true", "CWE-942", "cors"},
		{"Cross-Origin Resource Sharing misconfiguration", "any origin is reflected", "", "cors"},
		{"Reflected Access-Control-Allow-Origin with credentials", "attacker origin can read the response", "CWE-284", "cors"},
		{"Origin validation error on /api/account", "cors policy reflects any origin", "CWE-346", "cors"},
		// Regression: a genuine access-control finding WITHOUT CORS wording must
		// still classify as idor (the CORS override must not steal it).
		{"Broken access control on /api/orders", "unauthorized access to another user's order", "CWE-284", "idor"},
		{"Broken Function Level Authorization on /api/admin/users", "regular user reached admin function", "CWE-862", "idor"},
		{"Business logic flaw in checkout", "negative quantity yields a negative total", "", "business_logic"},
		{"Price manipulation at checkout", "", "CWE-840", "business_logic"},
		// The exact phrasing a real agent produced for this challenge (no CWE) —
		// must classify as business_logic via the "quantity tampering"/"store
		// credit" keywords, not fall through to unclassified.
		{"Negative / zero / overflow quantity accepted at checkout (price/quantity tampering → store credit & overflow)", "", "", "business_logic"},
		{"Mystery bug", "no class keyword", "CWE-79", "xss"},   // CWE fallback
		{"Mystery bug", "no class keyword", "CWE-639", "idor"}, // CWE fallback
		{"Mystery bug", "no class keyword", "CWE-99999", ""},   // unmapped
		{"Mystery bug", "no class keyword", "", ""},            // nothing
		// An SSTI finding whose description mentions the RCE it can escalate to
		// must classify as ssti via its CWE, not rce via the "remote code
		// execution" keyword (which precedes ssti in classKeywords).
		{"Server-Side Template Injection via name", "confirmed {{7*7}}=49; can be escalated to remote code execution", "CWE-1336", "ssti"},
		// CWE wins over a conflicting description keyword generally.
		{"Template injection", "the payload triggers command injection style impact", "CWE-1336", "ssti"},
	}
	for _, c := range cases {
		got := classifyFinding(reporting.Vulnerability{Title: c.title, Description: c.desc, CWE: c.cwe})
		if got != c.want {
			t.Errorf("classifyFinding(%q,%q,%q) = %q, want %q", c.title, c.desc, c.cwe, got, c.want)
		}
	}
}

func TestSolved(t *testing.T) {
	// Right class → solved (endpoint/path is not part of the criterion).
	f := []reporting.Vulnerability{{ID: "XALG-1", Title: "Reflected XSS", Endpoint: "https://h/?q=x"}}
	if ok, id := Solved("xss", f); !ok || id != "XALG-1" {
		t.Fatalf("expected an xss finding to solve, got ok=%v id=%q", ok, id)
	}
	// Canonicalization: a BOLA finding solves the idor challenge.
	if ok, _ := Solved("idor", []reporting.Vulnerability{{ID: "XALG-2", Title: "BOLA", Description: "broken object level authorization"}}); !ok {
		t.Fatal("expected a BOLA finding to solve the idor challenge")
	}
	// Wrong class → not solved.
	if ok, _ := Solved("xss", []reporting.Vulnerability{{Title: "SQL injection in id"}}); ok {
		t.Fatal("a sqli finding must not solve an xss challenge")
	}
	// No findings → not solved.
	if ok, _ := Solved("xss", nil); ok {
		t.Fatal("no findings must not solve")
	}
}

func TestRunWithFakeScanFunc(t *testing.T) {
	// Fake solves xss and idor, leaves open-redirect and error-sqli unsolved,
	// and errors on nothing.
	fake := func(_ context.Context, target, _, scanID string, _ Auth) ([]reporting.Vulnerability, error) {
		switch scanID {
		case "bench-reflected-xss":
			return []reporting.Vulnerability{{ID: "XALG-1", Title: "Reflected XSS in search", Endpoint: target + "/search"}}, nil
		case "bench-idor":
			return []reporting.Vulnerability{{ID: "XALG-1", Title: "IDOR", Description: "insecure direct object reference", Endpoint: target + "/api/orders/1042"}}, nil
		default:
			return nil, nil
		}
	}

	card := Run(context.Background(), Builtin(), fake)
	if card.Total() != len(Builtin()) {
		t.Fatalf("expected %d challenges, got %d", len(Builtin()), card.Total())
	}
	// Solved = 2 positives (reflected-xss + idor) + every negative control
	// (all correctly clean, since the fake reports nothing on them).
	negatives := card.NegativeCount()
	if want := 2 + negatives; card.SolvedCount() != want {
		t.Fatalf("expected %d solved (xss+idor+%d clean negatives), got %d\n%s", want, negatives, card.SolvedCount(), card.String())
	}
	if card.FalsePositives() != 0 {
		t.Fatalf("expected 0 false positives (fake reports nothing on negatives), got %d\n%s", card.FalsePositives(), card.String())
	}
	byClass := card.ByClass()
	// Each class now pairs its positive challenge(s) with a negative control.
	// xss = reflected-xss (solved) + safe-search (clean) = 2/2. idor = idor
	// (solved) + safe-idor (clean) = 2/2.
	if byClass["xss"] != [2]int{2, 2} {
		t.Fatalf("expected xss 2/2, got %v", byClass)
	}
	// idor = idor (solved) + bola + bfla (positives, unsolved by this fake) +
	// safe-idor + safe-bola + safe-bfla (three clean negatives) => 4/6.
	if byClass["idor"] != [2]int{4, 6} {
		t.Fatalf("expected idor 4/6, got %v", byClass["idor"])
	}
	// open_redirect and ssrf each have a positive (unsolved by this fake) plus a
	// negative control (correctly clean) => 1/2.
	for _, c := range []string{"open_redirect", "ssrf"} {
		if byClass[c] != [2]int{1, 2} {
			t.Fatalf("expected %s 1/2, got %v", c, byClass[c])
		}
	}
	// rce = cmdi + whitebox-cmdi + whitebox-node-rce (positives) + safe-cmdi
	// (clean) => 1/4. sqli = error-sqli + whitebox-sqli (positives) + safe-sqli
	// (clean) => 1/3. ssti = ssti + whitebox-ssti + safe-ssti => 1/3. lfi = lfi
	// + whitebox-lfi + safe-lfi => 1/3. The one "solved" in each is the clean
	// negative control (this fake finds none of these positives).
	if byClass["rce"] != [2]int{1, 4} {
		t.Fatalf("expected rce 1/4, got %v", byClass["rce"])
	}
	if byClass["sqli"] != [2]int{1, 3} {
		t.Fatalf("expected sqli 1/3, got %v", byClass["sqli"])
	}
	if byClass["ssti"] != [2]int{1, 3} {
		t.Fatalf("expected ssti 1/3, got %v", byClass["ssti"])
	}
	if byClass["lfi"] != [2]int{1, 3} {
		t.Fatalf("expected lfi 1/3, got %v", byClass["lfi"])
	}
	// xxe = xxe (positive, unsolved by this fake) + safe-import (negative, clean) => 1/2.
	if byClass["xxe"] != [2]int{1, 2} {
		t.Fatalf("expected xxe 1/2, got %v", byClass["xxe"])
	}
	// csrf = csrf (positive, unsolved by this fake) + safe-account (negative, clean) => 1/2.
	if byClass["csrf"] != [2]int{1, 2} {
		t.Fatalf("expected csrf 1/2, got %v", byClass["csrf"])
	}
}

func TestNewBuiltinChallengesExhibitVuln(t *testing.T) {
	// ssrf: an internal-target url returns metadata-like secret content.
	ssrf := challengeByName(t, "ssrf").Start()
	defer ssrf.Close()
	if body := httpGet(t, ssrf.URL+"/fetch?url=http://169.254.169.254/latest/meta-data/"); !strings.Contains(body, "security-credentials") {
		t.Fatalf("ssrf did not return internal metadata: %q", body)
	}

	// ssti: {{7*7}} evaluates to 49.
	ssti := challengeByName(t, "ssti").Start()
	defer ssti.Close()
	if body := httpGet(t, ssti.URL+"/greet?name={{7*7}}"); !strings.Contains(body, "Hello, 49!") {
		t.Fatalf("ssti did not evaluate the template expression: %q", body)
	}
	// ssti exposes ONLY the template-injection signal — a <script> payload is
	// HTML-escaped, so there is no reflected-XSS red herring to pull a scanner
	// off the SSTI onto the easier (browser-confirmable) XSS.
	if body := httpGet(t, ssti.URL+"/greet?name=<script>alert(1)</script>"); strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("ssti must HTML-escape name (no XSS red herring), got %q", body)
	}

	// lfi: path traversal to passwd returns fabricated passwd content.
	lfi := challengeByName(t, "lfi").Start()
	defer lfi.Close()
	if body := httpGet(t, lfi.URL+"/download?file=../../../../etc/passwd"); !strings.Contains(body, "root:x:0:0:") {
		t.Fatalf("lfi did not leak passwd content: %q", body)
	}

	// cmdi: a shell metacharacter yields command output.
	cmdi := challengeByName(t, "cmdi").Start()
	defer cmdi.Close()
	if body := httpGet(t, cmdi.URL+"/ping?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0(root)") {
		t.Fatalf("cmdi did not execute the injected command: %q", body)
	}
}

func TestRunWithTimeoutMarksTimedOut(t *testing.T) {
	// A scan that blocks past the per-challenge deadline is stopped and marked
	// timed out (and, with no findings, not solved).
	blocking := func(ctx context.Context, _, _, _ string, _ Auth) ([]reporting.Vulnerability, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	card := RunWithTimeout(context.Background(), []Challenge{Builtin()[0]}, blocking, 50*time.Millisecond)
	if len(card.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(card.Results))
	}
	if !card.Results[0].TimedOut {
		t.Fatalf("expected the challenge to be marked timed out, got %+v", card.Results[0])
	}
	if card.Results[0].Solved {
		t.Fatal("a timed-out scan with no findings must not be solved")
	}
}

func TestWhiteboxChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-cmdi")

	// The whitebox source carries the sink and the (unlinked) vulnerable route
	// in the same file, so the source→route↔sink bridge can find it.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-cmdi must ship app.py source")
	}
	if !strings.Contains(src, "os.popen") || !strings.Contains(src, "/internal/run-check") {
		t.Fatalf("app.py must contain the os.popen sink and the /internal/run-check route:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// The vulnerable route executes injected commands (shell metacharacter).
	if body := httpGet(t, srv.URL+"/internal/run-check?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0(root)") {
		t.Fatalf("whitebox route did not execute the injected command: %q", body)
	}
	// A benign host does not.
	if body := httpGet(t, srv.URL+"/internal/run-check?host=127.0.0.1"); strings.Contains(body, "uid=0(root)") {
		t.Fatalf("benign host must not yield command output: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route — black-box crawling can't
	// reach it, so the win genuinely requires whitebox source discovery.
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/run-check") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestHarnessMaterializesSourceFiles(t *testing.T) {
	// Capture the sourceDir handed to each challenge's scan.
	seen := map[string]string{}
	fake := func(_ context.Context, _, sourceDir, scanID string, _ Auth) ([]reporting.Vulnerability, error) {
		seen[scanID] = sourceDir
		// While the scan runs, each of the challenge's OWN declared source files
		// must exist on disk (language-agnostic: app.py for Flask, app.js for
		// Express, etc.).
		if sourceDir != "" {
			name := strings.TrimPrefix(scanID, "bench-")
			for _, c := range Builtin() {
				if c.Name != name {
					continue
				}
				for f := range c.SourceFiles {
					if _, err := os.Stat(filepath.Join(sourceDir, f)); err != nil {
						t.Errorf("expected %s in materialized source dir %q: %v", f, sourceDir, err)
					}
				}
			}
		}
		return nil, nil
	}

	Run(context.Background(), Builtin(), fake)

	if seen["bench-whitebox-cmdi"] == "" {
		t.Fatal("whitebox-cmdi must receive a non-empty, materialized source dir")
	}
	localTempPrefix := filepath.Clean(TempRoot) + string(os.PathSeparator)
	if got := filepath.Clean(seen["bench-whitebox-cmdi"]); !strings.HasPrefix(got, localTempPrefix) {
		t.Fatalf("whitebox source must be materialized below project tmp/, got %q", got)
	}
	if seen["bench-reflected-xss"] != "" {
		t.Fatalf("a black-box challenge must receive an empty source dir, got %q", seen["bench-reflected-xss"])
	}
}

func TestWhiteboxSqliChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-sqli")

	// The whitebox source carries the sqli sink (a raw SELECT built by string
	// concatenation) inside the unlinked reporting route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-sqli must ship app.py source")
	}
	if !strings.Contains(src, "/internal/report") || !strings.Contains(src, "SELECT id, name FROM users") {
		t.Fatalf("app.py must contain the /internal/report route and the raw SELECT sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A quote in uid triggers a SQL syntax error (injectable).
	if body := httpGet(t, srv.URL+"/internal/report?uid=1%27"); !strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("whitebox-sqli did not leak a SQL error on quote injection: %q", body)
	}
	// A benign uid does not.
	if body := httpGet(t, srv.URL+"/internal/report?uid=1"); strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("benign uid must not yield a SQL error: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/report") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxSstiChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-ssti")

	// The whitebox source carries the template sink (render_template_string over
	// concatenated user input) inside the unlinked preview route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-ssti must ship app.py source")
	}
	if !strings.Contains(src, "/internal/preview") || !strings.Contains(src, "render_template_string") {
		t.Fatalf("app.py must contain the /internal/preview route and the render_template_string sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A {{7*7}} expression is evaluated server-side to 49 (template injection).
	if body := httpGet(t, srv.URL+"/internal/preview?name=%7B%7B7*7%7D%7D"); !strings.Contains(body, "49") {
		t.Fatalf("whitebox-ssti did not evaluate the template expression to 49: %q", body)
	}
	// A benign name is echoed literally, not evaluated.
	if body := httpGet(t, srv.URL+"/internal/preview?name=alice"); !strings.Contains(body, "alice") || strings.Contains(body, "49") {
		t.Fatalf("benign name must be echoed literally, not evaluated: %q", body)
	}
	// Exposes ONLY the SSTI signal — a <script> payload is HTML-escaped (no XSS red herring).
	if body := httpGet(t, srv.URL+"/internal/preview?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("whitebox-ssti must HTML-escape name (no XSS red herring), got %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/preview") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxLfiChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-lfi")

	// The whitebox source carries the file-read sink (open() over a concatenated
	// user path) inside the unlinked log-viewer route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-lfi must ship app.py source")
	}
	if !strings.Contains(src, "/internal/logs") || !strings.Contains(src, "open('/var/log/app/'") {
		t.Fatalf("app.py must contain the /internal/logs route and the open() file-read sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A ../ traversal to /etc/passwd leaks the passwd file (path traversal).
	if body := httpGet(t, srv.URL+"/internal/logs?file=../../../../etc/passwd"); !strings.Contains(body, "root:") {
		t.Fatalf("whitebox-lfi did not leak /etc/passwd on traversal: %q", body)
	}
	// A benign file name returns ordinary log lines, not passwd.
	if body := httpGet(t, srv.URL+"/internal/logs?file=app.log"); strings.Contains(body, "root:") {
		t.Fatalf("benign file must not leak passwd: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/logs") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxNodeRceChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-node-rce")

	// The whitebox source is a Node/Express app: the command-exec sink
	// (child_process exec over concatenated user input) lives inside the unlinked
	// diagnostics route's handler, discovered via the Express route pattern.
	src, ok := wb.SourceFiles["app.js"]
	if !ok {
		t.Fatal("whitebox-node-rce must ship app.js source")
	}
	if !strings.Contains(src, "child_process") || !strings.Contains(src, "app.get('/internal/ping'") {
		t.Fatalf("app.js must contain the Express /internal/ping route and the child_process exec sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A shell metacharacter in host triggers simulated command execution.
	if body := httpGet(t, srv.URL+"/internal/ping?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0") {
		t.Fatalf("whitebox-node-rce did not execute the injected command: %q", body)
	}
	// A benign host does not.
	if body := httpGet(t, srv.URL+"/internal/ping?host=localhost"); strings.Contains(body, "uid=0") {
		t.Fatalf("benign host must not yield command output: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/ping") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

// TestBlackboxChallengesDiscoverable verifies every black-box challenge exposes
// its vulnerable endpoint (and, for query-parameter bugs, the parameter name)
// from its "/" index, so a crawling scanner can discover the attack surface the
// way it would on a real app — the benchmark measures crawl-then-detect, not
// parameter-name guessing. Whitebox challenges are exempt (discovered via source).
func TestBlackboxChallengesDiscoverable(t *testing.T) {
	for _, c := range Builtin() {
		if c.SourceFiles != nil {
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			srv := c.Start()
			defer srv.Close()
			body := httpGet(t, srv.URL+"/")
			if !strings.Contains(body, c.Endpoint) {
				t.Errorf("index must link endpoint %q so a crawler finds it; got %q", c.Endpoint, body)
			}
			// The IDOR/BOLA challenges' object id is a path segment
			// (/api/orders/1042), not a query parameter, so they are exempt from
			// the param-name check (the index still links the object, exposing the
			// surface).
			pathIDChallenge := c.Name == "idor" || c.Name == "safe-idor" || c.Name == "bola" || c.Name == "safe-bola"
			if !pathIDChallenge && c.Param != "" && !strings.Contains(body, c.Param) {
				t.Errorf("index must expose parameter %q (form/link); got %q", c.Param, body)
			}
		})
	}
}

// TestNegativeControlsScoring verifies the precision scoring: reporting a class
// on a negative control is a false positive (that challenge FAILs and is
// counted), while reporting nothing keeps every negative control clean.
func TestNegativeControlsScoring(t *testing.T) {
	// A scan that (wrongly) reports XSS on the safe-search negative control.
	fpFake := func(_ context.Context, target, _, scanID string, _ Auth) ([]reporting.Vulnerability, error) {
		if scanID == "bench-safe-search" {
			return []reporting.Vulnerability{{ID: "XALG-9", Title: "Reflected XSS", CWE: "CWE-79", Endpoint: target + "/search"}}, nil
		}
		return nil, nil
	}
	card := Run(context.Background(), Builtin(), fpFake)
	if card.FalsePositives() < 1 {
		t.Fatalf("expected >=1 false positive on safe-search, got %d\n%s", card.FalsePositives(), card.String())
	}
	var ss Result
	for _, r := range card.Results {
		if r.Name == "safe-search" {
			ss = r
		}
	}
	if !ss.Negative {
		t.Fatal("safe-search must be a negative control")
	}
	if ss.Solved {
		t.Fatal("safe-search must FAIL (false positive) when the scan reports XSS on it")
	}

	// A scan that reports nothing keeps every negative control clean.
	cleanFake := func(context.Context, string, string, string, Auth) ([]reporting.Vulnerability, error) {
		return nil, nil
	}
	clean := Run(context.Background(), Builtin(), cleanFake)
	if clean.FalsePositives() != 0 {
		t.Fatalf("expected 0 false positives when nothing is reported, got %d", clean.FalsePositives())
	}
	if clean.NegativeCount() < 4 {
		t.Fatalf("expected at least 4 negative controls, got %d", clean.NegativeCount())
	}
}

// TestNegativeControlsAreSafe confirms each negative-control app actually
// handles its input securely — so a finding of its class really would be a
// false positive, not a genuine bug the benchmark mislabeled.
func TestNegativeControlsAreSafe(t *testing.T) {
	// safe-search: reflection is HTML-escaped (no raw <script>).
	ss := challengeByName(t, "safe-search").Start()
	defer ss.Close()
	if body := httpGet(t, ss.URL+"/search?q=<script>alert(1)</script>"); strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("safe-search must escape the payload, got %q", body)
	}

	// safe-redirect: an external absolute URL is rejected; a relative path is allowed.
	sr := challengeByName(t, "safe-redirect").Start()
	defer sr.Close()
	respExt, err := noRedirectClient().Get(sr.URL + "/redirect?url=https://evil.example/")
	if err != nil {
		t.Fatalf("safe-redirect request: %v", err)
	}
	defer respExt.Body.Close()
	if respExt.StatusCode == http.StatusFound && respExt.Header.Get("Location") == "https://evil.example/" {
		t.Fatal("safe-redirect must not redirect to an external URL")
	}
	respRel, err := noRedirectClient().Get(sr.URL + "/redirect?url=/welcome")
	if err != nil {
		t.Fatalf("safe-redirect relative request: %v", err)
	}
	defer respRel.Body.Close()
	if respRel.StatusCode != http.StatusFound || respRel.Header.Get("Location") != "/welcome" {
		t.Fatalf("safe-redirect must allow a relative path, got status=%d loc=%q", respRel.StatusCode, respRel.Header.Get("Location"))
	}

	// safe-sqli: a quote yields a generic error, NOT a SQL error string.
	sq := challengeByName(t, "safe-sqli").Start()
	defer sq.Close()
	if body := httpGet(t, sq.URL+"/product?id=1'"); strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("safe-sqli must not leak a SQL error, got %q", body)
	}

	// safe-fetch: an internal metadata host is blocked (no metadata content).
	sf := challengeByName(t, "safe-fetch").Start()
	defer sf.Close()
	if body := httpGet(t, sf.URL+"/fetch?url=http://169.254.169.254/latest/meta-data/"); strings.Contains(body, "security-credentials") {
		t.Fatalf("safe-fetch must block internal metadata, got %q", body)
	}

	// safe-lfi: a traversal payload is rejected (no passwd content).
	sl := challengeByName(t, "safe-lfi").Start()
	defer sl.Close()
	if body := httpGet(t, sl.URL+"/download?file=../../../../etc/passwd"); strings.Contains(body, "root:") {
		t.Fatalf("safe-lfi must reject traversal, got %q", body)
	}

	// safe-cmdi: a shell metacharacter is rejected (no command output).
	sc := challengeByName(t, "safe-cmdi").Start()
	defer sc.Close()
	if body := httpGet(t, sc.URL+"/ping?host=127.0.0.1%3Bid"); strings.Contains(body, "uid=0") {
		t.Fatalf("safe-cmdi must reject shell metacharacters, got %q", body)
	}

	// safe-ssti: a template expression is echoed literally, never evaluated.
	st := challengeByName(t, "safe-ssti").Start()
	defer st.Close()
	if body := httpGet(t, st.URL+"/greet?name=%7B%7B7*7%7D%7D"); strings.Contains(body, "49") {
		t.Fatalf("safe-ssti must not evaluate the template, got %q", body)
	}

	// safe-idor: any order object is forbidden (no card/owner record leaked).
	si := challengeByName(t, "safe-idor").Start()
	defer si.Close()
	if body := httpGet(t, si.URL+"/api/orders/1042"); strings.Contains(body, "card_last4") || strings.Contains(body, `"owner"`) {
		t.Fatalf("safe-idor must not return an order record, got %q", body)
	}

	// safe-import: an XXE payload does not resolve any external entity (no file content).
	simp := challengeByName(t, "safe-import").Start()
	defer simp.Close()
	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	if body := httpPost(t, simp.URL+"/import", xxePayload); strings.Contains(body, "root:") {
		t.Fatalf("safe-import must not resolve external entities, got %q", body)
	}

	// safe-account: the change-email form embeds an anti-CSRF token and a
	// tokenless POST is refused (no state change).
	sa := challengeByName(t, "safe-account").Start()
	defer sa.Close()
	if body := httpGet(t, sa.URL+"/"); !strings.Contains(body, "csrf_token") {
		t.Fatalf("safe-account form must embed an anti-CSRF token, got %q", body)
	}
	if status, body := httpPostForm(t, sa.URL+"/account/email", "email=attacker@evil.example"); status != http.StatusForbidden || strings.Contains(body, "updated") {
		t.Fatalf("safe-account must refuse a tokenless POST, got status=%d body=%q", status, body)
	}
}

// httpPost sends an XML body to url and returns the response body as a string.
func httpPost(t *testing.T, url, body string) string {
	t.Helper()
	resp, err := http.Post(url, "application/xml", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestXxeChallengeExhibitsVuln(t *testing.T) {
	xxe := challengeByName(t, "xxe").Start()
	defer xxe.Close()

	// An external-entity payload resolves the referenced local file.
	payload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	if body := httpPost(t, xxe.URL+"/import", payload); !strings.Contains(body, "root:") {
		t.Fatalf("xxe did not resolve the external entity: %q", body)
	}
	// A benign XML document does not leak file content.
	if body := httpPost(t, xxe.URL+"/import", `<?xml version="1.0"?><records><r>ok</r></records>`); strings.Contains(body, "root:") {
		t.Fatalf("benign XML must not leak file content: %q", body)
	}
	// The index advertises the import endpoint so a crawler discovers it.
	if body := httpGet(t, xxe.URL+"/"); !strings.Contains(body, "/import") {
		t.Fatalf("index must link the import endpoint, got %q", body)
	}
}

// httpPostForm submits form-encoded data and returns the status code and body.
func httpPostForm(t *testing.T, url, data string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestCsrfChallengeExhibitsVuln(t *testing.T) {
	csrf := challengeByName(t, "csrf").Start()
	defer csrf.Close()

	// The change-email form is discoverable and carries NO anti-CSRF token.
	body := httpGet(t, csrf.URL+"/")
	if !strings.Contains(body, "/account/email") {
		t.Fatalf("index must expose the change-email endpoint, got %q", body)
	}
	if strings.Contains(strings.ToLower(body), "csrf") {
		t.Fatalf("vulnerable change-email form must carry no anti-CSRF token, got %q", body)
	}
	// The state change is accepted with no token (cross-site forgeable).
	status, resp := httpPostForm(t, csrf.URL+"/account/email", "email=attacker@evil.example")
	if status != http.StatusOK || !strings.Contains(resp, "updated") {
		t.Fatalf("csrf endpoint must accept a tokenless state change, got status=%d body=%q", status, resp)
	}
}

// TestBOLAChallengeBehavior locks in the two-account authorization behavior of
// the bola positive and safe-bola negative control: role B (bob) reading role
// A's (alice's) object is the flaw, anonymous is always refused, and the
// negative control enforces per-object ownership.
func TestBOLAChallengeBehavior(t *testing.T) {
	get := func(base, path, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Positive BOLA: bob (role B) reads alice's order 1001 and gets HER data.
	bola := challengeByName(t, "bola").Start()
	defer bola.Close()
	if st, body := get(bola.URL, "/api/orders/1001", "bob-token-b2"); st != 200 || !strings.Contains(body, `"owner":"alice"`) {
		t.Fatalf("bola: bob must read alice's order 1001; status=%d body=%q", st, body)
	}
	if st, _ := get(bola.URL, "/api/orders/1001", ""); st != http.StatusUnauthorized {
		t.Fatalf("bola: anonymous must be 401, got %d", st)
	}
	if st, body := get(bola.URL, "/api/orders/1001", "alice-token-a1"); st != 200 || !strings.Contains(body, `"owner":"alice"`) {
		t.Fatalf("bola: alice must read her own order 1001; status=%d body=%q", st, body)
	}

	// Negative control: per-object ownership is enforced — bob is denied alice's
	// order, so there is no BOLA to report.
	safe := challengeByName(t, "safe-bola").Start()
	defer safe.Close()
	if st, _ := get(safe.URL, "/api/orders/1001", "bob-token-b2"); st != http.StatusForbidden {
		t.Fatalf("safe-bola: bob reading alice's order must be 403, got %d", st)
	}
	if st, body := get(safe.URL, "/api/orders/1001", "alice-token-a1"); st != 200 || !strings.Contains(body, `"owner":"alice"`) {
		t.Fatalf("safe-bola: alice must read her own order; status=%d body=%q", st, body)
	}
	if st, _ := get(safe.URL, "/api/orders/1001", ""); st != http.StatusUnauthorized {
		t.Fatalf("safe-bola: anonymous must be 401, got %d", st)
	}
}

// TestHarnessPassesChallengeAuth verifies the harness plumbs a challenge's
// seeded identities through to the ScanFunc, so an authenticated challenge's
// role A / role B credentials actually reach the scan (and stateless challenges
// pass an empty Auth).
func TestHarnessPassesChallengeAuth(t *testing.T) {
	seen := map[string]Auth{}
	fake := func(_ context.Context, _, _, scanID string, auth Auth) ([]reporting.Vulnerability, error) {
		seen[scanID] = auth
		return nil, nil
	}
	Run(context.Background(), Builtin(), fake)

	if a := seen["bench-bola"]; a.A["Authorization"] != "Bearer alice-token-a1" || a.B["Authorization"] != "Bearer bob-token-b2" {
		t.Fatalf("bola challenge auth not passed to scan: %+v", a)
	}
	if s := seen["bench-reflected-xss"]; s.A != nil || s.B != nil {
		t.Fatalf("stateless challenge must pass an empty Auth, got %+v", s)
	}
}

// TestBFLAChallengeBehavior locks in the two-account behavior of the bfla
// positive and safe-bfla negative control: a regular user (role B) reaching the
// admin-only function is the flaw, anonymous is always refused, and the negative
// control enforces the role check.
func TestBFLAChallengeBehavior(t *testing.T) {
	get := func(base, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+"/api/admin/users", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/admin/users: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Positive BFLA: a regular user (role B) reaches the admin-only function and
	// gets the privileged data.
	bfla := challengeByName(t, "bfla").Start()
	defer bfla.Close()
	if st, body := get(bfla.URL, "user-token-b2"); st != 200 || !strings.Contains(body, "ssn_last4") {
		t.Fatalf("bfla: a regular user must reach the admin function; status=%d body=%q", st, body)
	}
	if st, _ := get(bfla.URL, ""); st != http.StatusUnauthorized {
		t.Fatalf("bfla: anonymous must be 401, got %d", st)
	}

	// Negative control: the role check is enforced — a regular user is refused.
	safe := challengeByName(t, "safe-bfla").Start()
	defer safe.Close()
	if st, _ := get(safe.URL, "user-token-b2"); st != http.StatusForbidden {
		t.Fatalf("safe-bfla: a regular user must be 403, got %d", st)
	}
	if st, body := get(safe.URL, "admin-token-a1"); st != 200 || !strings.Contains(body, "ssn_last4") {
		t.Fatalf("safe-bfla: admin must reach the function; status=%d body=%q", st, body)
	}
	if st, _ := get(safe.URL, ""); st != http.StatusUnauthorized {
		t.Fatalf("safe-bfla: anonymous must be 401, got %d", st)
	}
}

// TestBusinessLogicChallengeBehavior locks in the negative-quantity business
// logic flaw: the positive challenge accepts a negative quantity and returns a
// negative total, while the negative control rejects it with 400.
func TestBusinessLogicChallengeBehavior(t *testing.T) {
	// Positive: a negative quantity produces a negative order total.
	bl := challengeByName(t, "business-logic-negative-qty").Start()
	defer bl.Close()
	if body := httpGet(t, bl.URL+"/checkout?item=widget&quantity=-5"); !strings.Contains(body, "total $-500.00") {
		t.Fatalf("business-logic: negative quantity must yield a negative total; got %q", body)
	}
	// A normal order is still priced correctly (so the flaw is specifically the
	// missing non-negative check, not a broken endpoint).
	if body := httpGet(t, bl.URL+"/checkout?item=widget&quantity=2"); !strings.Contains(body, "total $200.00") {
		t.Fatalf("business-logic: a normal order must price correctly; got %q", body)
	}

	// Negative control: a non-positive quantity is rejected with 400.
	safe := challengeByName(t, "safe-checkout").Start()
	defer safe.Close()
	resp, err := http.Get(safe.URL + "/checkout?item=widget&quantity=-5")
	if err != nil {
		t.Fatalf("safe-checkout request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("safe-checkout: negative quantity must be 400, got %d", resp.StatusCode)
	}
	if body := httpGet(t, safe.URL+"/checkout?item=widget&quantity=2"); !strings.Contains(body, "total $200.00") {
		t.Fatalf("safe-checkout: a valid order must still succeed; got %q", body)
	}
}

// TestNoSQLiChallengeBehavior locks in the NoSQL operator-injection auth bypass:
// the positive challenge authenticates on an operator payload (without the
// password) but rejects normal wrong credentials, while the negative control
// rejects the operator payload with 400.
func TestNoSQLiChallengeBehavior(t *testing.T) {
	post := func(base, body string) (int, string) {
		t.Helper()
		resp, err := http.Post(base+"/api/login", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST /api/login: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Positive: operator injection authenticates without knowing the password.
	nl := challengeByName(t, "nosqli-auth-bypass").Start()
	defer nl.Close()
	if st, body := post(nl.URL, `{"username":"admin","password":{"$ne":null}}`); st != 200 || !strings.Contains(body, `"authenticated":true`) {
		t.Fatalf("nosqli: operator injection must authenticate; status=%d body=%q", st, body)
	}
	// Normal wrong credentials are rejected — so the only way in is the injection.
	if st, _ := post(nl.URL, `{"username":"admin","password":"wrong"}`); st != http.StatusUnauthorized {
		t.Fatalf("nosqli: normal wrong credentials must be 401, got %d", st)
	}
	// The bracketed form-encoding also bypasses (Express qs style).
	if resp, err := http.Post(nl.URL+"/api/login", "application/x-www-form-urlencoded", strings.NewReader("username=admin&password[$ne]=x")); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("nosqli: bracketed operator form must authenticate, got %d", resp.StatusCode)
		}
	}

	// Negative control: the operator payload is rejected (400) — no bypass.
	safe := challengeByName(t, "safe-login").Start()
	defer safe.Close()
	if st, _ := post(safe.URL, `{"username":"admin","password":{"$ne":null}}`); st != http.StatusBadRequest {
		t.Fatalf("safe-login: operator injection must be 400, got %d", st)
	}
}

// TestCORSChallengeBehavior locks in the CORS misconfiguration: the positive
// challenge reflects an ARBITRARY attacker Origin into
// Access-Control-Allow-Origin together with Access-Control-Allow-Credentials:
// true (a credentialed cross-origin read of authenticated data), while the
// negative control reflects ONLY a single fixed trusted origin.
func TestCORSChallengeBehavior(t *testing.T) {
	getOrigin := func(base, origin string) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+"/api/account", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/account: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// Positive: an arbitrary attacker origin is reflected WITH credentials, so
	// the attacker page can read the authenticated response (the api_token).
	cors := challengeByName(t, "cors-credentialed-reflect").Start()
	defer cors.Close()
	st, hdr, body := getOrigin(cors.URL, "https://evil.example")
	if st != 200 {
		t.Fatalf("cors: expected 200, got %d", st)
	}
	if hdr.Get("Access-Control-Allow-Origin") != "https://evil.example" {
		t.Fatalf("cors: attacker Origin must be reflected into ACAO, got %q", hdr.Get("Access-Control-Allow-Origin"))
	}
	if hdr.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("cors: ACAC must be true, got %q", hdr.Get("Access-Control-Allow-Credentials"))
	}
	if !strings.Contains(body, "api_token") {
		t.Fatalf("cors: response must carry the authenticated data an attacker steals, got %q", body)
	}
	// The index links the account API so a crawler discovers the surface.
	if idx := httpGet(t, cors.URL+"/"); !strings.Contains(idx, "/api/account") {
		t.Fatalf("cors: index must link /api/account, got %q", idx)
	}

	// Negative control: an arbitrary attacker origin is NOT reflected (only the
	// one trusted origin is ever allowed), so there is no CORS flaw.
	safe := challengeByName(t, "safe-cors").Start()
	defer safe.Close()
	if _, shdr, _ := getOrigin(safe.URL, "https://evil.example"); shdr.Get("Access-Control-Allow-Origin") == "https://evil.example" || shdr.Get("Access-Control-Allow-Origin") == "*" {
		t.Fatalf("safe-cors: must NOT reflect an arbitrary origin, got ACAO=%q", shdr.Get("Access-Control-Allow-Origin"))
	}
	// The one trusted origin IS allowed, so it is a working API (not just broken).
	if _, thdr, _ := getOrigin(safe.URL, "https://app.corp.example"); thdr.Get("Access-Control-Allow-Origin") != "https://app.corp.example" {
		t.Fatalf("safe-cors: the trusted origin must be allowed, got ACAO=%q", thdr.Get("Access-Control-Allow-Origin"))
	}
}
