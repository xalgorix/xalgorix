package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestNotifyScanComplete_DefaultsOff verifies the scan-completion summary
// toggle defaults to false, so a fresh install sends no "Scan Finished"
// summary after a scan — only per-vulnerability alerts.
func TestNotifyScanComplete_DefaultsOff(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	if s.cfg.NotifyScanComplete {
		t.Fatalf("cfg.NotifyScanComplete should default to false")
	}
	if s.notifyScanComplete.Load() {
		t.Fatalf("runtime notifyScanComplete should default to false")
	}
}

// TestEnvironmentSettings_AppliesNotifyScanComplete verifies the toggle
// round-trips through the /api/settings/environment POST path into both
// cfg.NotifyScanComplete and the server runtime field, and is reported back
// (as "true") on the subsequent GET so the dashboard renders it.
func TestEnvironmentSettings_AppliesNotifyScanComplete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	body := `{"values":{"XALGORIX_NOTIFY_SCAN_COMPLETE":"true"}}`
	rr := httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !s.cfg.NotifyScanComplete || !s.notifyScanComplete.Load() {
		t.Fatalf("notify scan complete not applied: cfg=%v runtime=%v", s.cfg.NotifyScanComplete, s.notifyScanComplete.Load())
	}

	rr = httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment GET code = %d", rr.Code)
	}
	var resp environmentSettingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settings GET: %v", err)
	}
	found := false
	for _, v := range resp.Variables {
		if v.Key == "XALGORIX_NOTIFY_SCAN_COMPLETE" {
			found = true
			if v.Value != "true" {
				t.Fatalf("expected XALGORIX_NOTIFY_SCAN_COMPLETE value \"true\", got %q", v.Value)
			}
		}
	}
	if !found {
		t.Fatalf("XALGORIX_NOTIFY_SCAN_COMPLETE missing from settings GET response")
	}
}

// TestSendScanCompletionSummary_RespectsOptIn proves the actual queue-level
// notification path stays silent by default and reaches both configured
// channels only after the operator opts in.
func TestSendScanCompletionSummary_RespectsOptIn(t *testing.T) {
	var discordHits atomic.Int32
	discord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discordHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discord.Close()

	telegram := newTelegramStubServer(t)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	// The stub listens on loopback, which a caller-supplied per-scan webhook
	// may not reach; configure it as the operator's global webhook instead.
	s.discordWebhook = discord.URL
	s.telegramBotToken = "123456789:ABC-DEF"
	s.telegramChatID = "-1001234567890"
	previousTelegramBase := swapTelegramAPIBaseForTest(telegram.srv.URL)
	defer swapTelegramAPIBaseForTest(previousTelegramBase)

	// Default/off: neither channel receives a completion summary.
	s.notifyScanComplete.Store(false)
	s.sendScanCompletionSummary(discord.URL, 1, 0)
	time.Sleep(100 * time.Millisecond)
	telegram.mu.Lock()
	telegramHits := telegram.hits
	telegram.mu.Unlock()
	if got := discordHits.Load(); got != 0 || telegramHits != 0 {
		t.Fatalf("completion summary sent while disabled: discord=%d telegram=%d", got, telegramHits)
	}

	// Opted in: both configured channels receive exactly one summary.
	s.notifyScanComplete.Store(true)
	s.sendScanCompletionSummary(discord.URL, 1, 0)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		telegram.mu.Lock()
		telegramHits = telegram.hits
		telegram.mu.Unlock()
		if discordHits.Load() == 1 && telegramHits == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := discordHits.Load(); got != 1 || telegramHits != 1 {
		t.Fatalf("completion summary not sent after opt-in: discord=%d telegram=%d", got, telegramHits)
	}
}
