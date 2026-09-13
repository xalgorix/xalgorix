// Package httpclient provides a structured HTTP client tool for the agent.
// Unlike raw terminal curl, this tool returns structured output (status code,
// headers, body) that the LLM can reason about precisely. It respects the
// global proxy and TLS-skip-verify configuration.
package httpclient

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/scanheaders"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const maxBodyBytes = 50 * 1024      // default cap — keeps the context window manageable
const maxBodyBytesHard = 512 * 1024 // hard ceiling when a caller raises max_bytes (e.g. to read JS bundles)

// Register adds the http_request tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "http_request",
		Description: "Make a structured HTTP request. Use this instead of terminal curl/wget for any HTTP call — it returns status code, response headers, and body in a clean format the agent can reason about. Perfect for: API testing, auth bypass attempts, JWT manipulation, SSRF probing, parameter fuzzing, cookie inspection, redirect chain analysis, and any HTTP-based recon.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Target URL (include protocol, e.g. https://example.com/api/users)", Required: true},
			{Name: "method", Description: "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS (default: GET)", Required: false},
			{Name: "headers", Description: `JSON object of request headers. Values may be strings, numbers, or arrays of strings for multi-value headers. e.g. {"Authorization":"Bearer eyJ...","Content-Type":"application/json","X-Ids":[1,2,3]}`, Required: false},
			{Name: "body", Description: "Request body (for POST/PUT/PATCH). Pass the raw string to send.", Required: false},
			{Name: "follow_redirects", Description: "Follow HTTP redirects (default: true). Set to false to inspect 3xx responses directly — useful for open redirect and SSRF testing.", Required: false},
			{Name: "timeout", Description: "Request timeout in seconds (default: 30, max: 60)", Required: false},
			{Name: "max_bytes", Description: "Max response body bytes to return (default 51200, max 524288). Raise it to read large client-side JS bundles when hunting hidden API endpoints, routes, and secrets on SPAs.", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executeWithContext(r.GetScanContextID(), args)
		},
	})
}

func execute(args map[string]string) (tools.Result, error) {
	return executeWithContext("", args)
}

func executeWithContext(contextID string, args map[string]string) (tools.Result, error) {
	targetURL := strings.TrimSpace(args["url"])
	if targetURL == "" {
		return tools.Result{}, fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	if !validMethod(method) {
		return tools.Result{}, fmt.Errorf("invalid HTTP method: %s", method)
	}

	timeout := 30
	if s := strings.TrimSpace(args["timeout"]); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			timeout = n
			if timeout > 60 {
				timeout = 60
			}
		}
	}

	followRedirects := true
	if s := strings.TrimSpace(args["follow_redirects"]); s != "" {
		switch strings.ToLower(s) {
		case "false", "0", "no", "off":
			followRedirects = false
		}
	}

	var bodyReader io.Reader
	if body := strings.TrimSpace(args["body"]); body != "" {
		bodyReader = strings.NewReader(body)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid URL %q: %w", targetURL, err)
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	req, err := http.NewRequest(method, parsedURL.String(), bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Parse and set custom headers. Accepts map[string]any so callers can
	// pass string, numeric, or []string values.
	hdrsProvided := map[string]struct{}{}
	blankOverride := map[string]struct{}{}
	headersStr := strings.TrimSpace(args["headers"])
	if headersStr != "" {
		if err := applyHeaders(req, headersStr); err != nil {
			return tools.Result{}, err
		}
		// Record which headers the caller set explicitly, so authenticated-
		// session credentials never clobber a deliberate override. A header
		// set to an EMPTY value is a deliberate "send this request WITHOUT
		// that credential" override (used to prove IDOR / broken access
		// control) — track those separately so we can OMIT the header
		// entirely rather than sending a malformed blank one.
		var rawHdrs map[string]any
		if json.Unmarshal([]byte(headersStr), &rawHdrs) == nil {
			for k, v := range rawHdrs {
				lk := strings.ToLower(strings.TrimSpace(k))
				hdrsProvided[lk] = struct{}{}
				if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
					blankOverride[lk] = struct{}{}
				}
			}
		}
	}

	// Apply authenticated-session credentials for this scan, but never
	// override a header the caller set explicitly — so the agent can still
	// send the SAME request unauthenticated (e.g. to prove an IDOR / auth
	// bypass) by passing an empty/blank value for that header.
	if contextID != "" {
		for name, val := range getSessionAuth(contextID) {
			if _, explicit := hdrsProvided[strings.ToLower(name)]; explicit {
				continue
			}
			if req.Header.Get(name) == "" {
				req.Header.Set(name, val)
			}
		}
	}

	// Apply operator-configured scan/attribution headers (XALGORIX_SCAN_HEADERS
	// / -H). Like session auth, they identify authorized scan traffic and are
	// never allowed to override a header the caller set explicitly.
	scanheaders.Apply(req.Header, config.Get().ScanHeaders)

	// Blank overrides: DELETE the header so the request is sent with no such
	// credential at all. Middleware/apps can treat an empty Authorization or
	// Cookie as malformed rather than absent, which would mask a real broken-
	// access-control finding when the agent diffs authed vs unauthenticated.
	for name := range blankOverride {
		req.Header.Del(name)
	}

	// Set default User-Agent if caller didn't provide one.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}

	client, err := buildClient(timeout, followRedirects, config.Get().TLSSkipVerify)
	if err != nil {
		return tools.Result{}, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return tools.Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))
	out.WriteString(fmt.Sprintf("Request-Time: %.0fms\n\n", float64(elapsed.Microseconds())/1000))

	// Print response headers in a readable format.
	out.WriteString("--- Response Headers ---\n")
	for k, vals := range resp.Header {
		for _, v := range vals {
			out.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}

	// Read body (capped). Callers can raise the cap (up to maxBodyBytesHard)
	// to read large JS bundles when hunting hidden endpoints/secrets on SPAs.
	bodyCap := maxBodyBytes
	if s := strings.TrimSpace(args["max_bytes"]); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			bodyCap = n
			if bodyCap > maxBodyBytesHard {
				bodyCap = maxBodyBytesHard
			}
		}
	}
	// Use LimitReader + io.ReadAll so we always get the full (truncated)
	// content without short reads.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(bodyCap)+1))
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to read response body: %w", err)
	}
	truncated := len(bodyBytes) > bodyCap
	bodyLen := len(bodyBytes) // original length (may be bodyCap+1)
	if truncated {
		bodyBytes = bodyBytes[:bodyCap]
	}

	contentType := resp.Header.Get("Content-Type")
	isBinary := isBinaryContentType(contentType)

	if isBinary {
		out.WriteString("\n--- Response Body (binary) ---\n")
		sizeNote := fmt.Sprintf("%d bytes", bodyLen)
		if truncated {
			sizeNote = fmt.Sprintf("%d KB+ (truncated)", bodyCap/1024)
		}
		out.WriteString(fmt.Sprintf("[binary content: %s, %s]\n", contentType, sizeNote))
	} else {
		out.WriteString("\n--- Response Body (text) ---\n")
		out.WriteString(string(bodyBytes))
		if truncated {
			out.WriteString(fmt.Sprintf("\n\n[Body truncated at %d KB — raise max_bytes to read more (e.g. a full JS bundle)]", bodyCap/1024))
		}
	}

	return tools.Result{Output: out.String()}, nil
}

// applyHeaders parses a JSON object and applies each entry as an HTTP header.
// Values may be strings, numbers (coerced via fmt.Sprint), or []any (each
// element emitted as a separate header line for multi-value headers like
// Set-Cookie).
func applyHeaders(req *http.Request, rawJSON string) error {
	var hdrs map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &hdrs); err != nil {
		return fmt.Errorf("invalid headers JSON: %w", err)
	}
	for k, v := range hdrs {
		switch val := v.(type) {
		case string:
			req.Header.Set(k, val)
		case float64:
			req.Header.Set(k, fmt.Sprint(val))
		case bool:
			req.Header.Set(k, strconv.FormatBool(val))
		case []any:
			// Multi-value header — add each element, then use Add for
			// subsequent values so Set + Add produces all values.
			for i, elem := range val {
				s := fmt.Sprint(elem)
				if i == 0 {
					req.Header.Set(k, s)
				} else {
					req.Header.Add(k, s)
				}
			}
		default:
			req.Header.Set(k, fmt.Sprint(val))
		}
	}
	return nil
}

func validMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func isBinaryContentType(ct string) bool {
	ct = strings.ToLower(ct)
	binaryPrefixes := []string{
		"image/", "audio/", "video/", "application/octet-stream",
		"application/zip", "application/gzip", "application/pdf",
		"application/vnd.", "font/",
	}
	for _, p := range binaryPrefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// testTLSInsecure is a test-only hook that forces TLS verification to be
// skipped. Set only from tests to avoid mutating the shared global config.
var testTLSInsecure bool

func buildClient(timeoutSec int, followRedirects bool, tlsSkipVerify bool) (*http.Client, error) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		tr = tr.Clone()
	} else {
		tr = &http.Transport{}
	}
	if tlsSkipVerify || testTLSInsecure {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} //nolint:gosec
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}

	// A proxy-required scan must never inherit DefaultTransport's direct or
	// environment route when proxy initialization failed.
	if config.Get().ProxyRequired && !proxy.Required() {
		return nil, fmt.Errorf("proxy-required mode is not initialized")
	}
	if proxy.Enabled() {
		p := proxy.GetProxy()
		if p == nil {
			if proxy.Required() {
				return nil, fmt.Errorf("proxy-required mode has no upstream")
			}
		} else {
			proxyURL, err := p.URL()
			if err != nil {
				return nil, fmt.Errorf("invalid configured proxy: %w", err)
			}
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return c, nil
}
