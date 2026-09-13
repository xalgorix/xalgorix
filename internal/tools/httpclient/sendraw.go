package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanheaders"
)

// defaultBrowserUA mirrors the User-Agent the http_request tool sends so raw
// replays look identical to normal scan traffic.
const defaultBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// RawRequest is a single explicit HTTP request for SendRaw.
//
// Unlike the http_request tool, SendRaw does NOT auto-inject the scan's session
// auth: the caller supplies the exact headers for the identity under test. This
// is what makes it usable for multi-role authorization testing, where the whole
// point is to control precisely which credentials each replay carries (role A,
// role B, or none). Operator attribution headers (scanheaders) are still
// applied so replays remain identifiable as authorized scan traffic, and the
// upstream proxy + TLS config are honored via the shared buildClient.
type RawRequest struct {
	Method          string
	URL             string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	TimeoutSec      int // <=0 → 30, capped at 60
	MaxBodyBytes    int // <=0 → default cap, capped at the hard ceiling
}

// RawResponse is the structured result of SendRaw.
type RawResponse struct {
	StatusCode int
	Status     string
	Proto      string
	Header     http.Header
	Body       []byte
	BodyLen    int // full body length observed before truncation
	Truncated  bool
	Elapsed    time.Duration
}

// SendRaw performs one HTTP request with exactly the supplied headers and
// returns a structured response. It reuses the package's client construction
// (proxy, TLS-skip-verify) and applies operator scan headers, but never adds
// per-scan session credentials — callers control the identity explicitly.
func SendRaw(req RawRequest) (*RawResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	if !validMethod(method) {
		return nil, fmt.Errorf("invalid HTTP method: %s", method)
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		return nil, fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	timeout := req.TimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 60 {
		timeout = 60
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range req.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	scanheaders.Apply(httpReq.Header, config.Get().ScanHeaders)
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", defaultBrowserUA)
	}

	client, err := buildClient(timeout, req.FollowRedirects, config.Get().TLSSkipVerify)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	bodyCap := req.MaxBodyBytes
	if bodyCap <= 0 {
		bodyCap = maxBodyBytes
	}
	if bodyCap > maxBodyBytesHard {
		bodyCap = maxBodyBytesHard
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(bodyCap)+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	truncated := len(raw) > bodyCap
	bodyLen := len(raw)
	if truncated {
		raw = raw[:bodyCap]
	}

	return &RawResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Proto:      resp.Proto,
		Header:     resp.Header,
		Body:       raw,
		BodyLen:    bodyLen,
		Truncated:  truncated,
		Elapsed:    elapsed,
	}, nil
}
