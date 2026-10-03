package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func verifierOracleAgent(t *testing.T) *Agent {
	t.Helper()
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(sctx.Close)
	return &Agent{ID: "oracle", cfg: &config.Config{}, scanCtx: sctx,
		ctx: context.Background(), localGuard: scopeguard.Config{AllowLocalTargets: true}}
}

func verifierOracleServer(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("XALGORIX_REQUIRE_ORACLE") == "1" {
			t.Fatal("required application oracle runtime is unavailable")
		}
		t.Skip("application oracle requires Python 3")
	}
	cmd := exec.Command(python, "-I", "-u", "testdata/verifier_oracle.py")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var base string
	select {
	case base = <-ready:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("application oracle did not become ready")
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("invalid loopback oracle address %q", base)
	}
	t.Cleanup(func() {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get(base + "/shutdown")
		if err == nil {
			_ = response.Body.Close()
		} else {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return base
}

func oracleRead(t *testing.T, rawURL string) string {
	t.Helper()
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func checkOracleVerdict(t *testing.T, a *Agent, result tools.Result, err error, class string, want bool) {
	t.Helper()
	if err != nil || result.Error != "" {
		t.Fatalf("tool error: %v / %s", err, result.Error)
	}
	got, present := result.Metadata[class+"_confirmed"].(bool)
	if !present || got != want {
		t.Errorf("%s confirmed=%v want=%v; %s", class, got, want, result.Output)
	}
	if !want && a.ledger().Len() != 0 {
		t.Errorf("negative control gained %d purported exploit hypotheses", a.ledger().Len())
	}
	if want && got {
		id, _ := result.Metadata["hypothesis_id"].(string)
		hypothesis, ok := a.ledger().Get(id)
		if !ok || hypothesis.VulnClass != class || len(hypothesis.Evidence) == 0 {
			t.Fatal("positive confirmation did not retain its class and independent evidence")
		}
	}
}

func TestVerifierApplicationOracleSQLi(t *testing.T) {
	base := verifierOracleServer(t)
	for _, test := range []struct {
		name string
		want bool
	}{{"vulnerable", true}, {"patched", false}, {"validator", false}, {"reflection", false}} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "vulnerable" || test.name == "patched" {
				body := oracleRead(t, base+"/sql/"+test.name+"?q="+url.QueryEscape("nomatch' OR '1'='1"))
				if strings.Contains(body, "fixture account") != test.want {
					t.Fatal("independent SQL data-extraction ground truth disagreed with fixture manifest")
				}
			}
			a := verifierOracleAgent(t)
			result, err := a.verifySQLiTool(map[string]string{"url": base + "/sql/" + test.name, "parameter": "q"})
			checkOracleVerdict(t, a, result, err, "sqli", test.want)
		})
	}
}

func TestVerifierApplicationOracleSSTI(t *testing.T) {
	base := verifierOracleServer(t)
	if !strings.Contains(oracleRead(t, base+"/capabilities"), `"jinja": true`) {
		if os.Getenv("XALGORIX_REQUIRE_ORACLE") == "1" {
			t.Fatal("required template application oracle dependency is unavailable")
		}
		t.Skip("template application oracle requires Jinja2")
	}
	for _, test := range []struct {
		name string
		want bool
	}{{"vulnerable", true}, {"patched", false}} {
		t.Run(test.name, func(t *testing.T) {
			body := oracleRead(t, base+"/ssti/"+test.name+"?q="+url.QueryEscape("{{ 713 * 809 }}"))
			if strings.Contains(body, "576817") != test.want {
				t.Fatal("independent template-evaluation ground truth disagreed with fixture manifest")
			}
			a := verifierOracleAgent(t)
			result, err := a.verifySSTITool(map[string]string{"url": base + "/ssti/" + test.name, "parameter": "q"})
			checkOracleVerdict(t, a, result, err, "ssti", test.want)
		})
	}
}

func TestVerifierApplicationOracleXXE(t *testing.T) {
	base := verifierOracleServer(t)
	for _, test := range []struct {
		name string
		want bool
	}{{"vulnerable", true}, {"patched", false}} {
		t.Run(test.name, func(t *testing.T) {
			a := verifierOracleAgent(t)
			result, err := a.verifyXXETool(map[string]string{"url": base + "/xxe/" + test.name, "file": "/oracle/passwd"})
			checkOracleVerdict(t, a, result, err, "xxe", test.want)
		})
	}
	// This positive uses a different file format, outside the passwd detector's
	// documented recognizable-content scope. Keep that limitation explicit.
	t.Run("custom-file-detection-limit", func(t *testing.T) {
		a := verifierOracleAgent(t)
		result, err := a.verifyXXETool(map[string]string{"url": base + "/xxe/vulnerable", "file": "/oracle/canary"})
		checkOracleVerdict(t, a, result, err, "xxe", false)
	})
}

func TestVerifierHTTPOracleCSRF(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		mutate bool
		want   bool
		ctype  string
	}{
		{"vulnerable", 200, "account setting saved", true, false, ""},
		{"origin-protected", 403, "origin rejected", false, false, ""},
		{"token-protected", 419, "invalid csrf token", false, false, ""},
		{"successful-no-op", 200, "OK", false, false, ""},
		{"login-redirect", 302, "", false, false, ""},
		{"json-only-no-cors", 200, "account setting saved", true, false, "application/json"},
		{"csrf-word-in-success", 200, "setting saved; csrf audit recorded", true, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var state atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Cookie") != "sid=fixture" {
					http.Error(w, "authentication required", http.StatusUnauthorized)
					return
				}
				if request.Method == http.MethodOptions {
					// No CORS permission for a non-simple browser request.
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if test.ctype != "" && request.Header.Get("Content-Type") != test.ctype {
					w.WriteHeader(http.StatusUnsupportedMediaType)
					return
				}
				if request.Header.Get("Origin") != "https://csrf-attacker.example" {
					t.Error("the forged request did not use an independent origin")
				}
				if test.status == 302 {
					w.Header().Set("Location", "/login")
				}
				if test.mutate {
					state.Add(1)
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			if test.ctype != "" {
				client := &http.Client{Timeout: time.Second}
				// A safelisted form request cannot reach this JSON-only action.
				request, err := http.NewRequest(http.MethodPost, server.URL+"/setting", strings.NewReader("setting=changed"))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Cookie", "sid=fixture")
				request.Header.Set("Origin", "https://csrf-attacker.example")
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusUnsupportedMediaType || state.Load() != 0 {
					t.Fatal("JSON-only negative control accepted a browser form")
				}
				// A non-simple browser request requires a successful preflight.
				request, err = http.NewRequest(http.MethodOptions, server.URL+"/setting", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Origin", "https://csrf-attacker.example")
				request.Header.Set("Access-Control-Request-Method", "POST")
				request.Header.Set("Access-Control-Request-Headers", "content-type")
				response, err = client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.Header.Get("Access-Control-Allow-Origin") != "" || state.Load() != 0 {
					t.Fatal("negative control unexpectedly granted cross-site JSON permission")
				}
			}
			a := verifierOracleAgent(t)
			a.targetAuth = "Cookie: sid=fixture"
			result, err := a.verifyCSRFTool(map[string]string{"url": server.URL + "/setting", "data": "setting=changed", "content_type": test.ctype})
			checkOracleVerdict(t, a, result, err, "csrf", test.want)
			wantMutation := test.mutate && test.ctype == ""
			if (state.Load() > 0) != wantMutation {
				t.Fatal("fixture state did not follow the declared action")
			}
			if wantMutation {
				candidate, _ := result.Metadata["csrf_candidate"].(bool)
				if !candidate {
					t.Fatal("accepted positive must remain a candidate for state/browser verification")
				}
			}
		})
	}
}

func TestVerifierHTTPGuardsPreventRequests(t *testing.T) {
	for _, name := range []string{"sqli", "ssti", "xxe", "csrf"} {
		for _, guard := range []string{"canceled", "passive", "local"} {
			t.Run(name+"/"+guard, func(t *testing.T) {
				var requests atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					_, _ = io.WriteString(w, "fixture response")
				}))
				defer server.Close()
				a := verifierOracleAgent(t)
				a.targetAuth = "Cookie: sid=fixture"
				switch guard {
				case "canceled":
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					a.ctx = ctx
				case "passive":
					a.scanIntensity = "passive"
				case "local":
					a.localGuard.AllowLocalTargets = false
				}
				registry := tools.NewRegistry()
				a.registerVerifySQLiTool(registry)
				a.registerVerifySSTITool(registry)
				a.registerVerifyXXETool(registry)
				a.registerVerifyCSRFTool(registry)
				result, err := registry.Execute("verify_"+name, map[string]string{"url": server.URL, "parameter": "q", "data": "setting=changed"})
				if err != nil || result.Error == "" || requests.Load() != 0 || a.ledger().Len() != 0 {
					t.Fatalf("guard failed: requests=%d err=%v tool_error=%s", requests.Load(), err, result.Error)
				}
			})
		}
	}
}

func scriptedVerifierAgent(t *testing.T, responses ...string) *Agent {
	t.Helper()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(calls.Add(1) - 1)
		if index >= len(responses) {
			index = len(responses) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": responses[index]}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
		})
	}))
	t.Cleanup(server.Close)
	a := verifierOracleAgent(t)
	a.client = llm.NewClient(a.cfg, llm.WithResolver(llm.NewFixedResolver(llm.Endpoint{
		URL: server.URL, Model: "scripted-fixture", HeaderStyle: "openai", Auth: llm.AuthAPIKey, APIKey: "fixture"})))
	a.client.SetContext(a.ctx)
	return a
}

func oracleToolCall(name string, args map[string]string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "<function=%s>\n", name)
	for key, value := range args {
		fmt.Fprintf(&out, "<parameter=%s>%s</parameter>\n", key, value)
	}
	out.WriteString("</function>")
	return out.String()
}

func TestSecondaryVerifierWrongClassOrReflectedOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fixed documentation text; this application executes no user input.
		_, _ = io.WriteString(w, "Manual example: uid=0(root) gid=0(root). No code was executed.")
	}))
	defer server.Close()
	for _, cwe := range []string{"CWE-89", "CWE-78", "CWE-79"} {
		t.Run(cwe, func(t *testing.T) {
			a := scriptedVerifierAgent(t,
				oracleToolCall("http_request", map[string]string{"url": server.URL + "/documentation"}),
				oracleToolCall("submit_verdict", map[string]string{"verdict": "inconclusive", "reason": "fixed example text is not reproduced exploitation"}))
			result := a.verifyFinding(reporting.VerificationRequest{
				Title: "Controlled candidate", CWE: cwe, Target: server.URL, Endpoint: "/candidate", HTTPMethod: "GET"})
			if result.Confirmed || !result.Inconclusive {
				t.Fatalf("benign wrong-route output overrode inconclusive verdict: %+v", result)
			}
		})
	}
}

func TestSecondaryVerifierDecisionAndGuards(t *testing.T) {
	t.Run("confirmation-without-retest", func(t *testing.T) {
		a := scriptedVerifierAgent(t, oracleToolCall("submit_verdict", map[string]string{"verdict": "confirmed", "reason": "claimed without reproducing"}))
		result := a.verifyFinding(reporting.VerificationRequest{Title: "Controlled candidate"})
		if result.Confirmed || !result.Inconclusive {
			t.Fatalf("confirmation without independent re-test was accepted: %+v", result)
		}
	})
	for _, verdict := range []string{"rejected", "inconclusive", "malformed"} {
		t.Run(verdict, func(t *testing.T) {
			a := scriptedVerifierAgent(t, oracleToolCall("submit_verdict", map[string]string{"verdict": verdict, "reason": "controlled decision"}))
			result := a.verifyFinding(reporting.VerificationRequest{Title: "Controlled candidate"})
			if result.Confirmed || result.Inconclusive != (verdict != "rejected") {
				t.Fatalf("unexpected decision: %+v", result)
			}
		})
	}
	t.Run("deadline-before-execution", func(t *testing.T) {
		a := verifierOracleAgent(t)
		registry := tools.NewRegistry()
		var calls atomic.Int64
		registry.Register(&tools.Tool{Name: "fixture", Execute: func(map[string]string) (tools.Result, error) {
			calls.Add(1)
			return tools.Result{Output: "executed"}, nil
		}})
		result := a.execVerifierToolGuarded(registry, "fixture", nil, time.Now().Add(-time.Second))
		time.Sleep(10 * time.Millisecond)
		if result.Error == "" || calls.Load() != 0 {
			t.Fatalf("expired deadline launched tool work: calls=%d error=%s", calls.Load(), result.Error)
		}
	})
	t.Run("local-target-guard", func(t *testing.T) {
		a := verifierOracleAgent(t)
		a.localGuard.AllowLocalTargets = false
		result := a.execVerifierToolGuarded(tools.NewRegistry(), "http_request", map[string]string{"url": "http://127.0.0.1:1"}, time.Now().Add(time.Second))
		if !strings.Contains(result.Output, "BLOCKED") {
			t.Fatalf("verifier bypassed local scope guard: %+v", result)
		}
	})
	t.Run("canceled-before-execution", func(t *testing.T) {
		a := verifierOracleAgent(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a.ctx = ctx
		registry := tools.NewRegistry()
		var calls atomic.Int64
		registry.Register(&tools.Tool{Name: "fixture", Execute: func(map[string]string) (tools.Result, error) {
			calls.Add(1)
			return tools.Result{Output: "executed"}, nil
		}})
		result := a.execVerifierToolGuarded(registry, "fixture", nil, time.Now().Add(time.Second))
		if result.Error == "" || calls.Load() != 0 {
			t.Fatalf("canceled verifier launched work: calls=%d error=%s", calls.Load(), result.Error)
		}
	})
	t.Run("worker-panic", func(t *testing.T) {
		a := verifierOracleAgent(t)
		registry := tools.NewRegistry()
		registry.Register(&tools.Tool{Name: "fixture", Execute: func(map[string]string) (tools.Result, error) {
			panic("controlled fixture panic")
		}})
		result := a.execVerifierToolGuarded(registry, "fixture", nil, time.Now().Add(time.Second))
		if !strings.Contains(result.Error, "panicked") {
			t.Fatalf("worker panic was not contained: %+v", result)
		}
	})
}
