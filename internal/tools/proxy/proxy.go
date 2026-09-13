// Package proxy provides Caido proxy integration tools.
package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/ratelimit"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// globalLimiter is initialized once from config when the package is loaded.
// It is replaced by initLimiter() so tests can override it cleanly.
var globalLimiter *ratelimit.Limiter

func init() {
	initLimiter()
}

func initLimiter() {
	cfg := config.Get()
	rps := cfg.RateLimitRPS
	burst := cfg.RateLimitBurst
	if rps <= 0 {
		rps = 10
	}
	if burst <= 0 {
		burst = 20
	}
	globalLimiter = ratelimit.New(rps, burst)
}

// Register adds proxy tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "send_request",
		Description: "Send an HTTP request using the configured outbound proxy when enabled. Proxy-required mode never falls back to a direct request. Large responses (>10KB) are saved to a temporary file; use terminal_execute to inspect it.",
		Parameters: []tools.Parameter{
			{Name: "method", Description: "HTTP method (GET, POST, PUT, DELETE, etc.)", Required: true},
			{Name: "url", Description: "Target URL", Required: true},
			{Name: "headers", Description: "Request headers as JSON object", Required: false},
			{Name: "body", Description: "Request body", Required: false},
		},
		Execute: sendRequest,
	})

	r.Register(&tools.Tool{
		Name:        "list_requests",
		Description: "List HTTP requests captured by Caido proxy.",
		Parameters: []tools.Parameter{
			{Name: "count", Description: "Number of requests to list (default: 20)", Required: false},
			{Name: "filter", Description: "Filter by URL substring", Required: false},
		},
		Execute: listRequests,
	})
}

// httpClient returns the configured client. Proxy-required mode never falls
// back to a direct connection when initialization failed.
func httpClient() (*http.Client, error) {
	cfg := config.Get()
	if cfg.ProxyRequired && !proxy.Required() {
		return nil, fmt.Errorf("proxy-required mode is not initialized")
	}
	// A settings edit cannot disable the live required route before restart.
	if proxy.Required() {
		return proxy.GetClient()
	}
	if cfg.UseProxy {
		return proxy.GetClient()
	}
	return proxy.NewDirectClient(cfg.TLSSkipVerify), nil
}

func parseHeaders(headersJSON string) (map[string]string, error) {
	if strings.TrimSpace(headersJSON) == "" {
		return nil, nil
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, fmt.Errorf("invalid headers JSON: %w", err)
	}
	return headers, nil
}

func clampRequestCount(raw string) int {
	count := 20
	if strings.TrimSpace(raw) != "" {
		if _, err := fmt.Sscanf(raw, "%d", &count); err != nil {
			count = 20
		}
	}
	if count < 1 {
		return 1
	}
	if count > 100 {
		return 100
	}
	return count
}

func sendRequest(args map[string]string) (tools.Result, error) {
	targetURL := args["url"]
	method := strings.ToUpper(args["method"])

	// Rate-limit before sending — blocks until a token is available for
	// this domain. No-op when XALGORIX_RATE_RPS=0.
	globalLimiter.Wait(targetURL)

	var bodyReader io.Reader
	if body := args["body"]; body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid request: %w", err)
	}

	if headersJSON := args["headers"]; headersJSON != "" {
		headers, err := parseHeaders(headersJSON)
		if err != nil {
			return tools.Result{}, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	client, err := httpClient()
	if err != nil {
		return tools.Result{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return tools.Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var b strings.Builder
	viaProxy := proxy.Required() || (config.Get().UseProxy && proxy.Enabled())
	if viaProxy {
		b.WriteString("[via proxy pool]\n")
	} else {
		b.WriteString("[direct request]\n")
	}
	b.WriteString(fmt.Sprintf("HTTP/%s %s\n", resp.Proto, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	b.WriteString("\n")

	// For large responses, save the full body to a temp file so the agent
	// can grep/search it with terminal_execute instead of losing data.
	const previewLimit = 10000
	bodyStr := string(respBody)
	var savedPath string
	if len(bodyStr) > previewLimit {
		// Generate a deterministic filename from URL + method for caching.
		h := sha256.Sum256([]byte(method + " " + targetURL))
		hash := hex.EncodeToString(h[:8])
		savedPath = "/tmp/send_request_" + hash + ".txt"
		if err := os.WriteFile(savedPath, respBody, 0600); err != nil {
			// If file write fails, fall back to truncation.
			savedPath = ""
		}
	}

	if savedPath != "" {
		b.WriteString(bodyStr[:previewLimit])
		b.WriteString(fmt.Sprintf("\n\n... [RESPONSE TOO LARGE: %d bytes total]\n", len(bodyStr)))
		b.WriteString(fmt.Sprintf("💾 Full response saved to: %s\n", savedPath))
		b.WriteString("Use terminal_execute to search it: grep -oE 'pattern' " + savedPath + "\n")
	} else {
		b.WriteString(bodyStr)
	}

	meta := map[string]any{
		"status_code": resp.StatusCode,
		"url":         targetURL,
		"via_proxy":   viaProxy,
	}
	if savedPath != "" {
		meta["saved_to"] = savedPath
		meta["full_size"] = len(respBody)
	}

	return tools.Result{
		Output:   b.String(),
		Metadata: meta,
	}, nil
}

func listRequests(args map[string]string) (tools.Result, error) {
	cfg := config.Get()
	if cfg.CaidoAPIToken == "" {
		return tools.Result{Output: "Caido API token not configured. Set CAIDO_API_TOKEN in ~/.xalgorix.env"}, nil
	}

	count := clampRequestCount(args["count"])

	query := `query { requests(first: ` + strconv.Itoa(count) + `) { edges { node { id method url response { statusCode } } } } }`

	gqlReq := map[string]any{"query": query}
	body, err := json.Marshal(gqlReq)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to marshal GraphQL query: %v", err)}, nil
	}

	gqlURL := fmt.Sprintf("http://127.0.0.1:%d/graphql", caidoPort())
	req, err := http.NewRequest(http.MethodPost, gqlURL, bytes.NewReader(body))
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to create GraphQL request: %v", err)}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.CaidoAPIToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return tools.Result{Output: fmt.Sprintf("Failed to query Caido GraphQL API at %s: %v\nMake sure Caido is running and accessible.", gqlURL, err)}, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to read Caido response: %v", err)}, nil
	}
	return tools.Result{Output: string(respBody)}, nil
}

// caidoPort returns the configured or auto-detected Caido port.
func caidoPort() int {
	if p := config.Get().CaidoPort; p > 0 {
		return p
	}
	return 8080
}
