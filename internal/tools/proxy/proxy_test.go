package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// send_request is not routed through Caido: without an outbound proxy it
// connects straight to the target and never to the Caido port that
// list_requests reads. The agent prompts say so (#917); if send_request is
// ever wired through Caido, update those prompts together with this test.
func TestSendRequestDoesNotRouteThroughCaido(t *testing.T) {
	caido, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer caido.Close()
	var caidoConns atomic.Int32
	go func() {
		for {
			c, err := caido.Accept()
			if err != nil {
				return
			}
			caidoConns.Add(1)
			_ = c.Close()
		}
	}()

	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, "target-ok")
	}))
	defer target.Close()

	cfg := config.Get()
	oldPort, oldUseProxy, oldRequired := cfg.CaidoPort, cfg.UseProxy, cfg.ProxyRequired
	cfg.CaidoPort = caido.Addr().(*net.TCPAddr).Port
	cfg.UseProxy, cfg.ProxyRequired = false, false
	t.Cleanup(func() { cfg.CaidoPort, cfg.UseProxy, cfg.ProxyRequired = oldPort, oldUseProxy, oldRequired })
	if got := caidoPort(); got != cfg.CaidoPort {
		t.Fatalf("caidoPort() = %d, want the fake Caido port %d", got, cfg.CaidoPort)
	}

	res, err := sendRequest(map[string]string{"method": "GET", "url": target.URL})
	// The fake listener counts a connection before closing it, so a request
	// routed through the Caido port is reported here rather than as an EOF.
	if n := caidoConns.Load(); n != 0 {
		t.Fatalf("send_request opened %d connection(s) to the Caido port; update the agent prompts (#917)", n)
	}
	if err != nil {
		t.Fatalf("send_request failed: %v", err)
	}
	if !strings.Contains(res.Output, "target-ok") || targetHits.Load() != 1 {
		t.Fatalf("send_request did not reach the target directly (hits=%d): %q", targetHits.Load(), res.Output)
	}
}

func TestParseHeadersRejectsMalformedJSON(t *testing.T) {
	if _, err := parseHeaders(`{"X-Test":"ok"`); err == nil {
		t.Fatal("malformed headers JSON was accepted")
	}
	if _, err := sendRequest(map[string]string{
		"method":  "GET",
		"url":     "https://example.test",
		"headers": `{"X-Test":"ok"`,
	}); err == nil || !strings.Contains(err.Error(), "invalid headers JSON") {
		t.Fatalf("sendRequest malformed headers error = %v", err)
	}
}

func TestParseHeadersAndCountClamp(t *testing.T) {
	headers, err := parseHeaders(`{"X-Test":"ok","Accept":"application/json"}`)
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if headers["X-Test"] != "ok" || headers["Accept"] != "application/json" {
		t.Fatalf("unexpected headers: %#v", headers)
	}

	cases := map[string]int{
		"":    20,
		"abc": 20,
		"0":   1,
		"-5":  1,
		"1":   1,
		"200": 100,
		"100": 100,
		"42":  42,
	}
	for raw, want := range cases {
		if got := clampRequestCount(raw); got != want {
			t.Fatalf("clampRequestCount(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestSendRequestValidationErrorsBeforeNetwork(t *testing.T) {
	if _, err := sendRequest(map[string]string{"method": "BAD METHOD", "url": "https://example.test"}); err == nil {
		t.Fatal("invalid HTTP method was accepted")
	}
	if _, err := sendRequest(map[string]string{"method": "GET", "url": "://bad"}); err == nil {
		t.Fatal("invalid URL was accepted")
	}
}
