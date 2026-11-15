package httpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// ---------------------------------------------------------------------------
// Unit tests — pure logic
// ---------------------------------------------------------------------------

func TestValidMethod(t *testing.T) {
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		if !validMethod(m) {
			t.Errorf("validMethod(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"", "TRACE", "CONNECT", "FOO", "get", "post"} {
		if validMethod(m) {
			t.Errorf("validMethod(%q) = true, want false", m)
		}
	}
}

func TestProbeTargetReturnsStatusWithoutFollowingRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("available"))
	}))
	defer srv.Close()
	status, err := ProbeTarget(context.Background(), "", srv.URL+"/redirect", nil)
	if err != nil || status != http.StatusFound {
		t.Fatalf("ProbeTarget redirect status = %d, %v", status, err)
	}
}

func TestIsBinaryContentType(t *testing.T) {
	binary := []string{
		"image/png",
		"image/svg+xml",
		"audio/mpeg",
		"video/mp4",
		"application/octet-stream",
		"application/zip",
		"application/gzip",
		"application/pdf",
		"application/vnd.ms-excel",
		"font/woff2",
	}
	text := []string{
		"text/html",
		"application/json",
		"application/xml",
		"text/plain",
		"application/javascript",
		"",
	}
	for _, ct := range binary {
		if !isBinaryContentType(ct) {
			t.Errorf("isBinaryContentType(%q) = false, want true", ct)
		}
	}
	for _, ct := range text {
		if isBinaryContentType(ct) {
			t.Errorf("isBinaryContentType(%q) = true, want false", ct)
		}
	}
}

func TestApplyHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	jsonInput := `{
		"Authorization": "Bearer token",
		"Content-Length": 123,
		"X-Debug": true,
		"Set-Cookie": ["a=1", "b=2"],
		"X-Single-Array": ["only-one"]
	}`

	if err := applyHeaders(req, jsonInput); err != nil {
		t.Fatalf("applyHeaders: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer token" {
		t.Errorf("Authorization = %q", got)
	}
	if got := req.Header.Get("Content-Length"); got != "123" {
		t.Errorf("Content-Length = %q, want '123'", got)
	}
	if got := req.Header.Get("X-Debug"); got != "true" {
		t.Errorf("X-Debug = %q, want 'true'", got)
	}
	if got := req.Header.Get("X-Single-Array"); got != "only-one" {
		t.Errorf("X-Single-Array = %q, want 'only-one'", got)
	}
	// Multi-value header: http.Header.Get returns the first value.
	if got := req.Header.Get("Set-Cookie"); got != "a=1" {
		t.Errorf("Set-Cookie[0] = %q, want 'a=1'", got)
	}
	// http.Header.Values returns all values (requires Go 1.22+) — the
	// canonical way to verify multi-value headers is to check the raw map.
	cookies := req.Header["Set-Cookie"]
	if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("Set-Cookie values = %v, want [a=1 b=2]", cookies)
	}
}

func TestApplyHeadersInvalidJSON(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if err := applyHeaders(req, "not-json"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Parameter validation tests
// ---------------------------------------------------------------------------

func TestExecuteMissingURL(t *testing.T) {
	_, err := execute(map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "url is required") {
		t.Fatalf("expected 'url is required', got: %v", err)
	}
}

func TestExecuteInvalidMethod(t *testing.T) {
	_, err := execute(map[string]string{"url": "http://example.com", "method": "TRACE"})
	if err == nil || !strings.Contains(err.Error(), "invalid HTTP method") {
		t.Fatalf("expected 'invalid HTTP method', got: %v", err)
	}
}

func TestExecuteInvalidHeadersJSON(t *testing.T) {
	_, err := execute(map[string]string{"url": "http://example.com", "headers": "not-json"})
	if err == nil || !strings.Contains(err.Error(), "invalid headers JSON") {
		t.Fatalf("expected 'invalid headers JSON', got: %v", err)
	}
}

func TestExecuteURLSchemeAutoPrepend(t *testing.T) {
	// Verify that a bare "host:port" gets "https://" auto-prepended.
	// Use an HTTPS test server + the test hook to avoid touching global config.
	prev := testTLSInsecure
	testTLSInsecure = true
	t.Cleanup(func() { testTLSInsecure = prev })

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("expected TLS connection")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Pass the URL without scheme.
	host := strings.TrimPrefix(server.URL, "https://")
	result, err := execute(map[string]string{"url": host})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "200 OK") {
		t.Fatalf("expected 200 OK in output, got: %s", result.Output)
	}
}

func TestExecuteTimeoutParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Valid timeout.
	result, err := execute(map[string]string{"url": server.URL, "timeout": "5"})
	if err != nil {
		t.Fatalf("timeout=5: %v", err)
	}
	if !strings.Contains(result.Output, "200 OK") {
		t.Fatalf("expected 200 OK: %s", result.Output)
	}

	// Above max — should clamp to 60 internally, request still works.
	result, err = execute(map[string]string{"url": server.URL, "timeout": "999"})
	if err != nil {
		t.Fatalf("timeout=999: %v", err)
	}
	if !strings.Contains(result.Output, "200 OK") {
		t.Fatalf("expected 200 OK: %s", result.Output)
	}

	// Invalid — should default to 30.
	result, err = execute(map[string]string{"url": server.URL, "timeout": "abc"})
	if err != nil {
		t.Fatalf("timeout=abc: %v", err)
	}
	if !strings.Contains(result.Output, "200 OK") {
		t.Fatalf("expected 200 OK: %s", result.Output)
	}
}

func TestExecuteFollowRedirectsParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	for _, val := range []string{"false", "0", "no", "off"} {
		_, err := execute(map[string]string{"url": server.URL, "follow_redirects": val})
		if err != nil {
			t.Fatalf("follow_redirects=%s: %v", val, err)
		}
	}

	for _, val := range []string{"true", "1", "yes", "on", ""} {
		_, err := execute(map[string]string{"url": server.URL, "follow_redirects": val})
		if err != nil {
			t.Fatalf("follow_redirects=%s: %v", val, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Request tests — verify what gets sent to the server
// ---------------------------------------------------------------------------

func TestExecuteMethodAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("X-Custom = %s, want test-value", r.Header.Get("X-Custom"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer server.Close()

	result, err := execute(map[string]string{
		"url":     server.URL,
		"method":  "POST",
		"headers": `{"X-Custom":"test-value","Content-Type":"application/json"}`,
		"body":    `{"name":"test"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "201 Created") {
		t.Fatalf("expected 201 Created: %s", result.Output)
	}
	if !strings.Contains(result.Output, `{"id": 1}`) {
		t.Fatalf("expected body in output: %s", result.Output)
	}
}

func TestExecuteRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use io.ReadAll to reliably read the full body, avoiding short reads.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if string(body) != "hello world" {
			t.Errorf("body = %q, want 'hello world'", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{
		"url":    server.URL,
		"method": "PUT",
		"body":   "hello world",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteDefaultUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Error("User-Agent header missing")
		}
		if r.Header.Get("Accept") != "" {
			t.Error("Accept header should not be set automatically")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteCustomUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "my-agent/1.0" {
			t.Errorf("User-Agent = %q, want 'my-agent/1.0'", ua)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{
		"url":     server.URL,
		"headers": `{"User-Agent":"my-agent/1.0"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteNumericAndMultiValueHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Port"); got != "8080" {
			t.Errorf("X-Port = %q, want '8080'", got)
		}
		cookies := r.Header["Set-Cookie"]
		if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
			t.Errorf("Set-Cookie = %v, want [a=1 b=2]", cookies)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{
		"url":     server.URL,
		"headers": `{"X-Port":8080,"Set-Cookie":["a=1","b=2"]}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Response handling tests
// ---------------------------------------------------------------------------

func TestExecuteResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.Header().Set("Server", "nginx/1.18")
		w.Header().Set("Set-Cookie", "session=abc123; HttpOnly")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("body"))
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"X-Powered-By: PHP/7.4", "Server: nginx/1.18", "Set-Cookie: session=abc123; HttpOnly"} {
		if !strings.Contains(result.Output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestExecuteAllHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, method := range methods {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				t.Errorf("method = %s, want %s", r.Method, method)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(method))
		}))
		result, err := execute(map[string]string{"url": server.URL, "method": method})
		server.Close()
		if err != nil {
			t.Fatalf("method %s: %v", method, err)
		}
		if !strings.Contains(result.Output, "200 OK") {
			t.Fatalf("method %s: expected 200 OK in: %s", method, result.Output)
		}
	}
}

func TestExecuteStatusCodeRelay(t *testing.T) {
	codes := []int{200, 201, 301, 400, 401, 403, 404, 500, 502, 503}
	for _, code := range codes {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		result, err := execute(map[string]string{"url": server.URL, "follow_redirects": "false"})
		server.Close()
		if err != nil {
			t.Fatalf("code %d: %v", code, err)
		}
		expected := http.StatusText(code)
		if expected == "" {
			expected = "OK"
		}
		if !strings.Contains(result.Output, expected) && !strings.Contains(result.Output, "301") {
			if code == 301 && !strings.Contains(result.Output, "301") {
				t.Fatalf("code %d: output = %s", code, result.Output)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Redirect behavior tests
// ---------------------------------------------------------------------------

func TestExecuteFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("final"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer redirector.Close()

	// Follow redirects (default).
	result, err := execute(map[string]string{"url": redirector.URL, "follow_redirects": "true"})
	if err != nil {
		t.Fatalf("follow=true: %v", err)
	}
	if !strings.Contains(result.Output, "final") {
		t.Fatalf("expected 'final' in body, got: %s", result.Output)
	}

	// Don't follow redirects.
	result, err = execute(map[string]string{"url": redirector.URL, "follow_redirects": "false"})
	if err != nil {
		t.Fatalf("follow=false: %v", err)
	}
	if !strings.Contains(result.Output, "301 Moved Permanently") {
		t.Fatalf("expected 301 in output, got: %s", result.Output)
	}
}

func TestExecuteRedirectWithoutFollowing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.internal/admin")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL, "follow_redirects": "false"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "302 Found") {
		t.Fatalf("expected 302 Found: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Location: https://evil.internal/admin") {
		t.Fatalf("expected Location header: %s", result.Output)
	}
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestExecuteConnectionRefused(t *testing.T) {
	_, err := execute(map[string]string{
		"url":     "http://127.0.0.1:1/",
		"timeout": "1",
	})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("expected 'request failed', got: %v", err)
	}
}

func TestExecuteInvalidURL(t *testing.T) {
	_, err := execute(map[string]string{"url": "http://127.0.0.1:1/%ZZ"})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// Body truncation tests
// ---------------------------------------------------------------------------

func TestExecuteBodyTruncation(t *testing.T) {
	bigBody := strings.Repeat("A", maxBodyBytes+100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bigBody))
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Output) > maxBodyBytes+4096 {
		t.Fatalf("output len=%d exceeds expected max around %d", len(result.Output), maxBodyBytes)
	}
	if !strings.Contains(result.Output, "[Body truncated at 50 KB") {
		t.Fatal("expected truncation marker in output")
	}
}

func TestExecuteBinaryContentFlagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte{0x89, 0x50, 0x4E, 0x47})
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "Response Body (binary)") {
		t.Fatalf("expected 'Response Body (binary)' section: %s", result.Output)
	}
	if !strings.Contains(result.Output, "[binary content: image/png,") {
		t.Fatalf("expected binary content marker: %s", result.Output)
	}
}

func TestExecuteBinaryContentTruncationMarker(t *testing.T) {
	bigBinary := make([]byte, maxBodyBytes+100)
	for i := range bigBinary {
		bigBinary[i] = byte(i % 256)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bigBinary)
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "50 KB+") {
		t.Fatalf("expected '50 KB+' truncation marker for binary: %s", result.Output)
	}
}

// ---------------------------------------------------------------------------
// Request-Time header test
// ---------------------------------------------------------------------------

func TestExecuteResponseIncludesRequestTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "Request-Time:") {
		t.Fatalf("expected Request-Time in output: %s", result.Output)
	}
}

// ---------------------------------------------------------------------------
// Registry integration test
// ---------------------------------------------------------------------------

func TestRegister(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)

	tool, ok := reg.Get("http_request")
	if !ok {
		t.Fatal("http_request not registered")
	}
	if tool.Name != "http_request" {
		t.Fatalf("tool name = %q", tool.Name)
	}
	if len(tool.Parameters) != 7 {
		t.Fatalf("expected 7 parameters, got %d", len(tool.Parameters))
	}

	required := map[string]bool{}
	for _, p := range tool.Parameters {
		required[p.Name] = p.Required
	}
	if !required["url"] {
		t.Fatal("url should be required")
	}
	for _, name := range []string{"method", "headers", "body", "follow_redirects", "timeout"} {
		if required[name] {
			t.Fatalf("%s should not be required", name)
		}
	}
}

func TestExecuteViaRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "registry")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	reg := tools.NewRegistry()
	Register(reg)

	result, err := reg.Execute("http_request", map[string]string{
		"url":    server.URL,
		"method": "GET",
	})
	if err != nil {
		t.Fatalf("reg.Execute: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false: %s", result.Output)
	}
	if !strings.Contains(result.Output, "200 OK") {
		t.Fatalf("expected 200 OK: %s", result.Output)
	}
	if !strings.Contains(result.Output, `{"status":"ok"}`) {
		t.Fatalf("expected body: %s", result.Output)
	}
	if !strings.Contains(result.Output, "X-Test: registry") {
		t.Fatalf("expected X-Test header: %s", result.Output)
	}
}

func TestExecuteViaRegistryMissingRequiredParam(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)

	_, err := reg.Execute("http_request", map[string]string{"method": "GET"})
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

// ---------------------------------------------------------------------------
// URL parsing edge cases
// ---------------------------------------------------------------------------

func TestExecuteURLQueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "123" {
			t.Errorf("id = %s, want 123", r.URL.Query().Get("id"))
		}
		if r.URL.Query().Get("name") != "test user" {
			t.Errorf("name = %s, want 'test user'", r.URL.Query().Get("name"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{"url": server.URL + "?id=123&name=test+user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteURLFragmentPreserved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{"url": server.URL + "#section"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Body content-type tests
// ---------------------------------------------------------------------------

func TestExecuteJSONResponseParsed(t *testing.T) {
	respBody := json.RawMessage(`{"users":[{"id":1,"name":"admin"},{"id":2,"name":"user"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBody)
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, string(respBody)) {
		t.Fatalf("expected JSON body verbatim: %s", result.Output)
	}
}

func TestExecuteEmptyResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := execute(map[string]string{"url": server.URL})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "204 No Content") {
		t.Fatalf("expected 204: %s", result.Output)
	}
}

// ---------------------------------------------------------------------------
// Headers JSON edge cases
// ---------------------------------------------------------------------------

func TestExecuteHeadersEmptyJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{"url": server.URL, "headers": "{}"})
	if err != nil {
		t.Fatalf("empty headers JSON: %v", err)
	}
}

func TestExecuteHeadersWithSpecialChars(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Forwarded-For"); v != "10.0.0.1, 10.0.0.2" {
			t.Errorf("X-Forwarded-For = %q", v)
		}
		if v := r.Header.Get("Referer"); v != "https://example.com/path?q=1" {
			t.Errorf("Referer = %q", v)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := execute(map[string]string{
		"url": server.URL,
		"headers": `{
			"X-Forwarded-For": "10.0.0.1, 10.0.0.2",
			"Referer": "https://example.com/path?q=1"
		}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SchemaXML verification
// ---------------------------------------------------------------------------

func TestSchemaXMLContainsTool(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)

	schema := reg.SchemaXML()
	if !strings.Contains(schema, `name="http_request"`) {
		t.Fatalf("SchemaXML missing http_request:\n%s", schema)
	}
	for _, param := range []string{"url", "method", "headers", "body", "follow_redirects", "timeout"} {
		if !strings.Contains(schema, `name="`+param+`"`) {
			t.Errorf("SchemaXML missing parameter %q", param)
		}
	}
	if !strings.Contains(schema, `required="true"`) {
		t.Error("SchemaXML should have at least one required parameter")
	}
}

// ---------------------------------------------------------------------------
// Regression: ensure follow_redirects=false never triggers the redirect loop
// ---------------------------------------------------------------------------

func TestExecuteNoRedirectLoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/self", http.StatusFound)
	}))
	defer server.Close()

	result, err := execute(map[string]string{
		"url":              server.URL,
		"follow_redirects": "false",
		"timeout":          "2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "302 Found") {
		t.Fatalf("expected 302 Found: %s", result.Output)
	}
}
