package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// swapTelegramAPIBaseForTest temporarily replaces the package-level
// telegramAPIBase so sendTelegram* tests can target a local
// httptest.Server stub instead of the real api.telegram.org. It
// returns the previous value so callers can restore it via defer.
// Production code never calls this.
func swapTelegramAPIBaseForTest(base string) string {
	prev := telegramAPIBase
	telegramAPIBase = base
	return prev
}

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{RateLimitRequests: 60, RateLimitWindow: 60}
	}
	if cfg.RateLimitRequests == 0 {
		cfg.RateLimitRequests = 60
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = 60
	}
	// NewServer now derives s.dataDir from cfg.DataDir (Task 3.6 / R6.4),
	// so seed a per-test temp dir BEFORE construction. Otherwise
	// rebuildInstancesFromDisk / loadSchedulesFromDisk would touch the
	// real ~/.xalgorix/data tree (or worse, the test's CWD).
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	s := NewServer(cfg, 0)
	// Backwards-compat for tests that override s.dataDir after construction:
	// if the caller didn't pre-pick a path, switch to a fresh TempDir so
	// existing tests that mutate s.dataDir keep working.
	s.dataDir = t.TempDir()
	t.Cleanup(func() {
		if s.rateLimiter != nil {
			defer func() { _ = recover() }()
			s.rateLimiter.Stop()
		}
	})
	return s
}

// bestEffortDataDir points s.dataDir at a temp dir cleaned up best-effort
// (errors ignored), for tests that POST /api/scan. handleScan acks immediately
// and runs the scan in a *detached* goroutine that keeps writing scan records
// under s.dataDir after the test returns. A plain t.TempDir() cleans up with a
// strict os.RemoveAll that races that late write and flakes with
// "directory not empty" (observed on TestHandleScanAckIsPendingNotStarted).
// A best-effort cleanup tolerates the leftover files instead.
func bestEffortDataDir(t *testing.T, s *Server) {
	t.Helper()
	dir, err := os.MkdirTemp("", "xalgorix-scan-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s.dataDir = dir
}

func resetAuthSessionsForTest() {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	authSessions = make(map[string]time.Time)
}

func TestGenerateReportResolvesUploadedLogoPath(t *testing.T) {
	s := newTestServer(t, nil)
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.MkdirAll(logosDir, 0755); err != nil {
		t.Fatal(err)
	}
	logoPath := filepath.Join(logosDir, "acme.png")
	writeTestPNG(t, logoPath)

	scanDir := filepath.Join(s.dataDir, "acme.example", "2026-05-14", "scan-logo")
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{
		ID:          "scan-logo",
		Name:        "Acme Security Review",
		Target:      "https://acme.example",
		StartedAt:   time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
		FinishedAt:  time.Now().Format(time.RFC3339),
		Status:      "finished",
		CompanyName: "Acme",
		LogoPath:    "/uploads/logos/acme.png",
		Vulns: []VulnSummary{{
			Title:       "SQL Injection in Search",
			Severity:    "critical",
			Endpoint:    "/search",
			CVSS:        9.1,
			Description: "Search input is injectable.",
			PoCScript:   strings.Repeat("curl -X POST https://acme.example/search -d 'q=test'\n", 80),
			Remediation: "Use parameterized queries.",
		}},
		Events: []WSEvent{{Type: "message", Content: "Tech stack detected: nginx"}},
	}

	logoData, logoType := s.loadReportLogo(rec.LogoPath)
	if len(logoData) == 0 || logoType != "png" {
		t.Fatalf("loadReportLogo() returned %d bytes, %q; want PNG data", len(logoData), logoType)
	}
	reportPath, err := s.generateReportAt(rec, scanDir)
	if err != nil {
		t.Fatalf("generateReportAt() error = %v", err)
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("generated report missing: %v", err)
	}
	if info.Size() < 1000 {
		t.Fatalf("generated report is unexpectedly small: %d bytes", info.Size())
	}
}

func writeTestPNG(t *testing.T, path string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: 16, G: 185, B: 129, A: 255})
		}
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastToInstanceReachesDashboardAndSubscribedClients(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "inst-1", Targets: "https://example.com", Status: "running"}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	dashboard := &wsClient{send: make(chan []byte, 1)}
	subscribed := &wsClient{send: make(chan []byte, 1), instanceID: inst.ID}
	other := &wsClient{send: make(chan []byte, 1), instanceID: "other"}
	s.mu.Lock()
	s.clients[dashboard] = true
	s.clients[subscribed] = true
	s.clients[other] = true
	s.mu.Unlock()

	s.broadcastToInstance(inst.ID, WSEvent{Type: "message", Content: "hello"})

	for name, ch := range map[string]<-chan []byte{
		"dashboard":  dashboard.send,
		"subscribed": subscribed.send,
	} {
		select {
		case raw := <-ch:
			var evt WSEvent
			if err := json.Unmarshal(raw, &evt); err != nil {
				t.Fatalf("%s received invalid event: %v", name, err)
			}
			if evt.InstanceID != inst.ID {
				t.Fatalf("%s event instance_id = %q, want %q", name, evt.InstanceID, inst.ID)
			}
			if evt.Content != "hello" {
				t.Fatalf("%s event content = %q, want hello", name, evt.Content)
			}
		default:
			t.Fatalf("%s client did not receive instance event", name)
		}
	}
	select {
	case <-other.send:
		t.Fatal("unrelated instance client received event")
	default:
	}

	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if len(inst.events) != 1 {
		t.Fatalf("buffered events = %d, want 1", len(inst.events))
	}
}

func TestRateLimitMiddleware_EnforcesLimitAndBypassesStaticAndWS(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	calls := 0
	handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/chat", nil)
	req.RemoteAddr = "127.0.0.1:1111"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/chat", nil)
	req.RemoteAddr = "127.0.0.1:2222"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr.Code)
	}

	staticBypassPaths := []string{
		"/ws",
		"/static/app.js",
		"/assets/logo.png",
		"/app.js",
		"/style.css",
		"/logo.png",
		"/chunks/app-123.js",
		"/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/scans/scan-1",
		"/api/instances",
		"/api/instances/scan-1",
		"/api/instances/scan-1/events",
		"/api/queue/status",
	}
	for _, path := range staticBypassPaths {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:3333"
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s bypass status = %d, want 200", path, rr.Code)
		}
	}
	if want := 1 + len(staticBypassPaths); calls != want {
		t.Fatalf("inner handler calls = %d, want %d", calls, want)
	}
}

func TestAuthMiddleware_AllowsReactShellAndAssetsBeforeSession(t *testing.T) {
	resetAuthSessionsForTest()
	mw := authMiddleware(&config.Config{Username: "admin", Password: "secret"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	publicPaths := []string{
		"/",
		"/login",
		"/scans",
		"/app.js",
		"/style.css",
		"/logo.png",
		"/chunks/app-123.js",
		"/api/auth/status",
	}
	for _, path := range publicPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d", path, rr.Code, http.StatusNoContent)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("protected API status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestIsStaticWebAssetPath_DoesNotClassifyDottedScanRoutes(t *testing.T) {
	staticPaths := []string{"/app.js", "/style.css", "/chunks/app-123.js", "/assets/logo.png", "/static/app.js"}
	for _, path := range staticPaths {
		if !isStaticWebAssetPath(path) {
			t.Fatalf("%s was not classified as a static asset", path)
		}
	}

	appRoutes := []string{"/scans/pentest-ground.com_4280_9286f18f", "/api/scans/pentest-ground.com_4280_9286f18f", "/ws"}
	for _, path := range appRoutes {
		if isStaticWebAssetPath(path) {
			t.Fatalf("%s was incorrectly classified as a static asset", path)
		}
	}
}

func TestIsDashboardReadPath_OnlyBypassesSafePollingReads(t *testing.T) {
	readPaths := []string{
		"/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/scans/scan-1",
		"/api/instances",
		"/api/instances/scan-1",
		"/api/instances/scan-1/events",
		"/api/queue/status",
	}
	for _, path := range readPaths {
		if !isDashboardReadPath(http.MethodGet, path) {
			t.Fatalf("%s was not classified as a dashboard read", path)
		}
	}

	writePaths := []string{
		"/api/scan",
		"/api/stop",
		"/api/chat",
		"/api/auth/login",
		"/api/instances/scan-1/stop",
	}
	for _, path := range writePaths {
		if isDashboardReadPath(http.MethodPost, path) {
			t.Fatalf("POST %s was incorrectly classified as a dashboard read", path)
		}
	}
}

func TestCanStartInstanceStatus(t *testing.T) {
	for _, status := range []string{"saved", "stopped", "failed", "finished", " Finished "} {
		if !canStartInstanceStatus(status) {
			t.Fatalf("%q should be startable", status)
		}
	}
	for _, status := range []string{"running", "pending", "paused", "", "unknown"} {
		if canStartInstanceStatus(status) {
			t.Fatalf("%q should not be startable", status)
		}
	}
}

func TestAuthHandlers_LoginStatusLogout(t *testing.T) {
	resetAuthSessionsForTest()
	s := newTestServer(t, &config.Config{
		Username:          "admin",
		Password:          "secret",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAuthStatus(rr, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if !strings.Contains(rr.Body.String(), `"auth_enabled":true`) || !strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("unexpected unauthenticated status body: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	loginBody := strings.NewReader(`{"username":"admin","password":"secret"}`)
	s.handleLogin(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%q", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("unexpected session cookie: %#v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleAuthStatus(rr, req)
	if !strings.Contains(rr.Body.String(), `"authenticated":true`) {
		t.Fatalf("authenticated status body: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rr.Code)
	}
	if isValidSession(cookie.Value) {
		t.Fatal("session remained valid after logout")
	}
}

func TestScanRequest_InternalFieldsIgnoredFromJSON(t *testing.T) {
	var req ScanRequest
	if err := json.Unmarshal([]byte(`{
		"targets":["https://example.test"],
		"instruction":"run",
		"instance_id":"spoofed",
		"is_resume":true
	}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.InstanceID != "" || req.IsResume {
		t.Fatalf("internal fields were set from JSON: %#v", req)
	}
}

func TestPhaseRestriction_ReconReportOnlyIsStrict(t *testing.T) {
	instruction := buildPhaseFilterInstruction([]int{1, 22})
	for _, want := range []string{
		"RECONNAISSANCE-ONLY SCOPE",
		"Do NOT run vulnerability scanners",
		"DNS records",
		"Open ports",
		"do not call report_vulnerability",
	} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("phase restriction missing %q:\n%s", want, instruction)
		}
	}
	if !isReconReportOnlyPhaseSelection([]int{1, 22}) {
		t.Fatal("recon/report-only phase selection was not detected")
	}
	if isReconReportOnlyPhaseSelection([]int{1, 6, 22}) {
		t.Fatal("vulnerability phase selection was incorrectly treated as recon-only")
	}
}

func TestInferCurrentPhase_DoesNotTreatSessionFinishedAsFinalReport(t *testing.T) {
	allowed := []int{1, 8, 22}

	if got := inferCurrentPhase(WSEvent{Type: "finished", Content: "Agent session complete"}, allowed); got != 0 {
		t.Fatalf("session finished inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "tool_call", ToolName: "finish"}, allowed); got != 0 {
		t.Fatalf("finish tool inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "tool_call", ToolName: "report_vulnerability"}, allowed); got != 0 {
		t.Fatalf("report_vulnerability inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "queue_finished", Content: "Scan queue ended"}, allowed); got != 22 {
		t.Fatalf("queue_finished inferred phase %d, want 22", got)
	}
	// Ubiquitous HTTP tokens in tool args must NOT infer a late phase. An
	// authenticated scan sends an "Authorization" header (and hits "/api/")
	// from the very first recon request, which used to false-jump the progress
	// bar to "8. IDOR/BAC" during reconnaissance. Regression guard.
	if got := inferCurrentPhase(WSEvent{
		Type:     "tool_call",
		ToolName: "terminal_execute",
		ToolArgs: map[string]string{
			"cmd": "curl -H 'Authorization: Bearer x' https://t/api/account",
		},
	}, allowed); got != 0 {
		t.Fatalf("ubiquitous-token tool call inferred phase %d, want 0", got)
	}
	// The agent's explicit phase narration IS a real signal and still advances.
	if got := inferCurrentPhase(WSEvent{
		Type:    "thinking",
		Content: "Phase 8: starting IDOR/BAC testing now",
	}, allowed); got != 8 {
		t.Fatalf("phase narration inferred %d, want 8", got)
	}
	// Strong, dedicated tool signals still map (recon tool → phase 1).
	if got := inferCurrentPhase(WSEvent{
		Type:     "tool_call",
		ToolName: "terminal_execute",
		ToolArgs: map[string]string{"cmd": "subfinder -d example.com"},
	}, allowed); got != 1 {
		t.Fatalf("recon tool inferred %d, want 1", got)
	}
}

func TestHandleGetScan_ReturnsLiveInstanceMetadata(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID:             "inst-meta",
		Name:           "Recon pass",
		Targets:        "https://meta.test",
		Status:         "running",
		StartedAt:      "2026-05-10T10:00:00Z",
		ScanMode:       "single",
		Instruction:    "recon only",
		SeverityFilter: []string{"high"},
		Phases:         []int{1, 22},
		CurrentPhase:   1,
		CompanyName:    "ACME",
		events: []WSEvent{{
			Type:         "target_started",
			Content:      "Scanning target",
			CurrentPhase: 1,
		}},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/inst-meta", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}

	var rec ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode scan record: %v", err)
	}
	if rec.Name != "Recon pass" || rec.Instruction != "recon only" || rec.CurrentPhase != 1 || len(rec.Phases) != 2 {
		t.Fatalf("live instance metadata not preserved: %#v", rec)
	}
}

func TestHandleChat_RoutesRunningInstanceByInstanceID(t *testing.T) {
	s := newTestServer(t, nil)
	events := make(chan agent.Event, 4)
	sctx := scanctx.New("chat-running", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "test-agent", events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0}, sctx)
	inst := &ScanInstance{
		ID:      "inst-running",
		Targets: "https://running.test",
		Status:  "running",
		agent:   agnt,
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()
	t.Cleanup(func() {
		agnt.Stop()
		sctx.Close()
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-running","message":"continue checking auth"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "next iteration") {
		t.Fatalf("unexpected running chat response: %s", rr.Body.String())
	}
}

func TestHandleChat_AllowsFinishedInstancePostScanChat(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	var gotMessages []string
	s.postScanChatFn = func(_ *config.Config, messages []llm.Message) (string, error) {
		for _, msg := range messages {
			gotMessages = append(gotMessages, msg.Content)
		}
		return "The scan found one high severity issue.", nil
	}
	inst := &ScanInstance{
		ID:          "inst-finished",
		Targets:     "https://done.test",
		Status:      "finished",
		StartedAt:   "2026-05-10T10:00:00Z",
		FinishedAt:  "2026-05-10T10:30:00Z",
		ScanMode:    "single",
		Iterations:  2,
		ToolCalls:   3,
		VulnCount:   1,
		TotalTokens: 100,
		Vulns: []VulnSummary{{
			ID:          "v1",
			Title:       "SQL injection",
			Severity:    "high",
			Endpoint:    "/login",
			Description: "Authentication endpoint reflected SQL errors.",
		}},
		events: []WSEvent{
			{Type: "target_started", Target: "https://done.test", Content: "Scanning https://done.test"},
			{Type: "finished", Content: "Completed with one finding"},
		},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-finished","message":"what did we find?"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "one high severity issue") {
		t.Fatalf("unexpected post-scan chat response: %s", rr.Body.String())
	}
	joinedMessages := strings.Join(gotMessages, "\n")
	if !strings.Contains(joinedMessages, "post-scan chat mode") ||
		!strings.Contains(joinedMessages, "SQL injection") ||
		!strings.Contains(joinedMessages, "what did we find?") {
		t.Fatalf("LLM prompt missing completed scan context or user message: %s", joinedMessages)
	}
}

func TestHandleChat_WithoutInstanceIDUsesLatestCompletedInstance(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	s.postScanChatFn = func(_ *config.Config, messages []llm.Message) (string, error) {
		if got := messages[len(messages)-1].Content; got != "test for any api endpoint" {
			t.Fatalf("chat message = %q", got)
		}
		return "The scan is complete; here are the API-related findings from the completed scan.", nil
	}
	inst := &ScanInstance{
		ID:         "inst-latest-finished",
		Targets:    "https://done.test",
		Status:     "finished",
		StartedAt:  "2026-05-10T10:00:00Z",
		FinishedAt: "2026-05-10T10:30:00Z",
		ScanMode:   "single",
		events: []WSEvent{
			{Type: "queue_finished", Content: "Scan queue ended"},
		},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"message":"test for any api endpoint"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "API-related findings") {
		t.Fatalf("unexpected no-instance post-scan chat response: %s", rr.Body.String())
	}
}

func TestHandleChat_WithoutInstanceIDIgnoresStaleFinishedAgent(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	events := make(chan agent.Event, 4)
	sctx := scanctx.New("stale-agent", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "stale-agent", events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0}, sctx)
	t.Cleanup(func() {
		agnt.Stop()
		sctx.Close()
	})

	s.mu.Lock()
	s.currentScanID = "stale-scan"
	s.currentAgents["stale-scan"] = agnt
	s.mu.Unlock()
	s.running.Store(false)

	s.postScanChatFn = func(_ *config.Config, _ []llm.Message) (string, error) {
		return "Post-scan context answer.", nil
	}
	inst := &ScanInstance{
		ID:         "inst-finished-after-stale-agent",
		Targets:    "https://done.test",
		Status:     "finished",
		StartedAt:  "2026-05-10T10:00:00Z",
		FinishedAt: "2026-05-10T10:30:00Z",
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"message":"what did we find?"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "next iteration") {
		t.Fatalf("stale agent handled post-scan chat: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Post-scan context answer") {
		t.Fatalf("unexpected post-scan response: %s", rr.Body.String())
	}
}

func TestUploadHandlers_ParseTargetsAndInstructions(t *testing.T) {
	s := newTestServer(t, nil)

	body, contentType := multipartBody(t, "file", "targets.txt", "https://a.test\n# ignored\n\nhttps://b.test\n")
	req := httptest.NewRequest(http.MethodPost, "/api/upload-targets", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	s.handleUploadTargets(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload targets status = %d body=%q", rr.Code, rr.Body.String())
	}
	var targetsResp struct {
		Targets []string `json:"targets"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &targetsResp); err != nil {
		t.Fatalf("decode targets response: %v", err)
	}
	if targetsResp.Count != 2 || strings.Join(targetsResp.Targets, ",") != "https://a.test,https://b.test" {
		t.Fatalf("unexpected targets response: %#v", targetsResp)
	}

	body, contentType = multipartBody(t, "file", "instructions.txt", "focus on auth flows")
	req = httptest.NewRequest(http.MethodPost, "/api/upload-instructions", body)
	req.Header.Set("Content-Type", contentType)
	rr = httptest.NewRecorder()
	s.handleUploadInstructions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload instructions status = %d body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "focus on auth flows") {
		t.Fatalf("unexpected instructions response: %s", rr.Body.String())
	}
}

func multipartBody(t *testing.T, field, name, content string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, err := w.CreateFormFile(field, name)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("write multipart: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &body, w.FormDataContentType()
}

func TestQueueStateHandlers_StatusAndClear(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(1, ScanRequest{Targets: []string{"https://a.test", "https://b.test"}, Instruction: "notes", ScanMode: "dast"})

	rr := httptest.NewRecorder()
	s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue status code = %d", rr.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode queue status: %v", err)
	}
	if status["available"] != true || status["remaining"].(float64) != 1 || status["scan_mode"] != "dast" {
		t.Fatalf("unexpected queue status: %#v", status)
	}

	rr = httptest.NewRecorder()
	s.handleQueueClear(rr, httptest.NewRequest(http.MethodPost, "/api/queue/clear", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue clear code = %d", rr.Code)
	}
	if state := s.loadQueueState(); state != nil {
		t.Fatalf("queue state still exists after clear: %#v", state)
	}
}

func TestQueueStateHandlers_ClearInvalidAndCompletedState(t *testing.T) {
	cases := []struct {
		name  string
		write func(*testing.T, *Server)
	}{
		{
			name: "corrupt JSON",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				if err := os.WriteFile(s.queueStatePath(), []byte("{not-json"), 0o644); err != nil {
					t.Fatalf("write corrupt queue: %v", err)
				}
			},
		},
		{
			name: "negative index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState(-1, ScanRequest{Targets: []string{"https://a.test"}, ScanMode: "single"})
			},
		},
		{
			name: "completed index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState(1, ScanRequest{Targets: []string{"https://a.test"}, ScanMode: "single"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			tc.write(t, s)

			rr := httptest.NewRecorder()
			s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("queue status code = %d", rr.Code)
			}
			var status map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
				t.Fatalf("decode queue status: %v", err)
			}
			if status["available"] != false {
				t.Fatalf("queue should be unavailable for invalid state: %#v", status)
			}
			if state := s.loadQueueState(); state != nil {
				t.Fatalf("invalid queue state was not cleared: %#v", state)
			}

			rr = httptest.NewRecorder()
			s.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
			if !strings.Contains(rr.Body.String(), "No interrupted queue found") {
				t.Fatalf("unexpected resume response: %s", rr.Body.String())
			}
		})
	}
}

func TestHandleQueueResumeRejectsPendingInstance(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(0, ScanRequest{
		Targets:  []string{"https://a.test"},
		ScanMode: "single",
	})

	inst := &ScanInstance{ID: "pending-1", Status: "pending"}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
	if !strings.Contains(rr.Body.String(), "pending or running") {
		t.Fatalf("unexpected resume response: %s", rr.Body.String())
	}
}

func TestHandleQueueResumeRejectsLaunchInProgress(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(0, ScanRequest{
		Targets:  []string{"https://a.test"},
		ScanMode: "single",
	})

	s.queueResumeMu.Lock()
	s.markQueueResumeLaunchingLocked("resume-1")
	s.queueResumeMu.Unlock()
	t.Cleanup(func() { s.clearQueueResumeLaunching("resume-1") })

	rr := httptest.NewRecorder()
	s.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
	if !strings.Contains(rr.Body.String(), "pending or running") {
		t.Fatalf("unexpected resume response: %s", rr.Body.String())
	}
}

func TestQueueState_PreservesAllConfig(t *testing.T) {
	s := newTestServer(t, nil)
	req := ScanRequest{
		Targets:        []string{"https://a.test", "https://b.test"},
		Instruction:    "deep scan with custom rules",
		ScanMode:       "wildcard",
		Name:           "My Pentest",
		SeverityFilter: []string{"critical", "high"},
		Phases:         []int{1, 6, 8, 22},
		ReconMode:      "passive",
		ScanIntensity:  "passive",
		CompanyName:    "ACME Corp",
		LogoPath:       "/uploads/logos/acme.png",
		DiscordWebhook: "https://discord.example/hook/abc123",
	}
	activeDir := filepath.Join(s.dataDir, "a.test", "2026-05-23", "scan-active")
	activeSubDir := filepath.Join(s.dataDir, "api.a.test", "2026-05-23", "scan-child")
	s.saveQueueState(0, req, queueProgress{
		ActiveTarget:          "https://a.test",
		ActiveScanDir:         activeDir,
		ActiveScanID:          "scan-active",
		WildcardActiveTarget:  "api.a.test",
		WildcardActiveScanDir: activeSubDir,
		WildcardActiveScanID:  "scan-child",
		WildcardDiscoveryDone: true,
		WildcardSubdomains:    []string{"app.a.test", "api.a.test"},
		WildcardSubIndex:      1,
	})

	state := s.loadQueueState()
	if state == nil {
		t.Fatal("queue state not loaded")
	}
	if state.Name != "My Pentest" {
		t.Errorf("Name = %q, want %q", state.Name, "My Pentest")
	}
	if state.Instruction != "deep scan with custom rules" {
		t.Errorf("Instruction = %q", state.Instruction)
	}
	if state.ScanMode != "wildcard" {
		t.Errorf("ScanMode = %q, want wildcard", state.ScanMode)
	}
	if len(state.SeverityFilter) != 2 || state.SeverityFilter[0] != "critical" {
		t.Errorf("SeverityFilter = %v, want [critical high]", state.SeverityFilter)
	}
	if len(state.Phases) != 4 || state.Phases[0] != 1 || state.Phases[3] != 22 {
		t.Errorf("Phases = %v, want [1 6 8 22]", state.Phases)
	}
	if state.ReconMode != "passive" {
		t.Errorf("ReconMode = %q, want passive", state.ReconMode)
	}
	if state.ScanIntensity != "passive" {
		t.Errorf("ScanIntensity = %q, want passive", state.ScanIntensity)
	}
	if state.CompanyName != "ACME Corp" {
		t.Errorf("CompanyName = %q, want %q", state.CompanyName, "ACME Corp")
	}
	if state.LogoPath != "/uploads/logos/acme.png" {
		t.Errorf("LogoPath = %q", state.LogoPath)
	}
	if state.DiscordWebhook != "https://discord.example/hook/abc123" {
		t.Errorf("DiscordWebhook = %q", state.DiscordWebhook)
	}
	if state.ActiveTarget != "https://a.test" || state.ActiveScanDir != activeDir || state.ActiveScanID != "scan-active" {
		t.Errorf("active scan progress not preserved: %#v", state)
	}
	if state.WildcardActiveTarget != "api.a.test" || state.WildcardActiveScanDir != activeSubDir || state.WildcardActiveScanID != "scan-child" {
		t.Errorf("active wildcard child progress not preserved: %#v", state)
	}
	if !state.WildcardDiscoveryDone || state.WildcardSubIndex != 1 || len(state.WildcardSubdomains) != 2 {
		t.Errorf("wildcard progress not preserved: %#v", state)
	}
	if len(state.Targets) != 2 || state.Targets[0] != "https://a.test" {
		t.Errorf("Targets = %v", state.Targets)
	}
	if state.CurrentIdx != 0 {
		t.Errorf("CurrentIdx = %d, want 0", state.CurrentIdx)
	}
	if !state.Active {
		t.Error("Active should be true")
	}
}

func TestQueueState_PerInstanceIsolation(t *testing.T) {
	s := newTestServer(t, nil)

	s.saveQueueState(0, ScanRequest{
		InstanceID: "inst-a",
		Targets:    []string{"https://a.test"},
		ScanMode:   "single",
	})
	s.saveQueueState(0, ScanRequest{
		InstanceID: "inst-b",
		Targets:    []string{"https://b.test"},
		ScanMode:   "single",
	})

	if _, err := os.Stat(s.queueStatePathForInstance("inst-a")); err != nil {
		t.Fatalf("missing queue state for inst-a: %v", err)
	}
	if _, err := os.Stat(s.queueStatePathForInstance("inst-b")); err != nil {
		t.Fatalf("missing queue state for inst-b: %v", err)
	}

	s.clearQueueState("inst-a")
	if _, err := os.Stat(s.queueStatePathForInstance("inst-a")); !os.IsNotExist(err) {
		t.Fatalf("inst-a queue state still exists after targeted clear: %v", err)
	}
	if _, err := os.Stat(s.queueStatePathForInstance("inst-b")); err != nil {
		t.Fatalf("targeted clear removed inst-b queue state: %v", err)
	}

	entries := s.validQueueStateEntries(false)
	if len(entries) != 1 || entries[0].state.InstanceID != "inst-b" {
		t.Fatalf("valid queue entries = %#v, want only inst-b", entries)
	}
}

func TestScanDirForResumeReusesSafeDir(t *testing.T) {
	s := newTestServer(t, nil)
	resumeDir := filepath.Join(s.dataDir, "example.com", "2026-05-23", "scan-1")
	req := ScanRequest{
		IsResume:           true,
		ResumeActiveTarget: "example.com",
		ResumeScanDir:      resumeDir,
	}
	got, resumed := s.scanDirForResume(req, "example.com")
	if !resumed {
		t.Fatal("expected safe resume dir to be reused")
	}
	if got != resumeDir {
		t.Fatalf("resume dir = %q, want %q", got, resumeDir)
	}

	req.ResumeScanDir = filepath.Join(s.dataDir, "..", "outside")
	got, resumed = s.scanDirForResume(req, "example.com")
	if resumed {
		t.Fatalf("unsafe resume dir was reused: %s", got)
	}
}

func TestScanDirForWildcardSubdomainResumeReusesSafeChildDir(t *testing.T) {
	s := newTestServer(t, nil)
	resumeDir := filepath.Join(s.dataDir, "api.example.com", "2026-05-23", "scan-child")
	req := ScanRequest{
		IsResume:            true,
		ResumeSubIndex:      2,
		ResumeSubScanTarget: "api.example.com",
		ResumeSubScanDir:    resumeDir,
	}

	got, resumed := s.scanDirForWildcardSubdomainResume(req, "api.example.com", 2)
	if !resumed {
		t.Fatal("expected active wildcard child dir to be reused")
	}
	if got != resumeDir {
		t.Fatalf("child resume dir = %q, want %q", got, resumeDir)
	}

	got, resumed = s.scanDirForWildcardSubdomainResume(req, "api.example.com", 3)
	if resumed {
		t.Fatalf("resume dir was reused for the wrong subdomain index: %s", got)
	}

	req.ResumeSubScanDir = filepath.Join(s.dataDir, "..", "outside")
	got, resumed = s.scanDirForWildcardSubdomainResume(req, "api.example.com", 2)
	if resumed {
		t.Fatalf("unsafe child resume dir was reused: %s", got)
	}
}

func TestScanRequestForPausedInstanceUsesSavedQueueState(t *testing.T) {
	s := newTestServer(t, nil)
	resumeDir := filepath.Join(s.dataDir, "b.test", "2026-05-23", "scan-b")
	s.saveQueueState(1, ScanRequest{
		InstanceID:    "inst-1",
		Targets:       []string{"https://a.test", "https://b.test"},
		ScanMode:      "single",
		Instruction:   "queued instruction",
		ReconMode:     "passive",
		ScanIntensity: "active",
	}, queueProgress{
		ActiveTarget:  "https://b.test",
		ActiveScanDir: resumeDir,
		ActiveScanID:  "scan-b",
	})
	inst := &ScanInstance{
		ID:            "inst-1",
		Targets:       "https://a.test, https://b.test",
		Status:        "paused",
		ScanMode:      "single",
		Instruction:   "fallback instruction",
		ReconMode:     "active",
		ScanIntensity: "active",
		scanDir:       filepath.Join(s.dataDir, "old"),
	}

	req, ok, reason := s.scanRequestForPausedInstance("inst-1", inst)
	if !ok {
		t.Fatalf("resume request was rejected: %s", reason)
	}
	if len(req.Targets) != 1 || req.Targets[0] != "https://b.test" {
		t.Fatalf("resume targets = %#v, want only queued active target", req.Targets)
	}
	if req.ResumeActiveTarget != "https://b.test" || req.ResumeScanDir != resumeDir || req.ResumeScanID != "scan-b" {
		t.Fatalf("resume progress not restored from queue: %#v", req)
	}
	if req.ResumeQueueStatePath != s.queueStatePathForInstance("inst-1") {
		t.Fatalf("resume queue source path = %q", req.ResumeQueueStatePath)
	}
	if req.Instruction != "queued instruction" || req.ReconMode != "passive" {
		t.Fatalf("queued request metadata not used: %#v", req)
	}
}

func TestScanRequestForPausedInstanceFallsBackToScanDir(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "a.test", "2026-05-23", "scan-a")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{
		ID:     "scan-a",
		Target: "https://a.test",
		Status: "paused",
	}, scanDir)
	inst := &ScanInstance{
		ID:            "inst-1",
		Targets:       "https://a.test",
		Status:        "paused",
		ScanMode:      "single",
		Instruction:   "resume instruction",
		ReconMode:     "passive",
		ScanIntensity: "passive",
		scanDir:       scanDir,
	}

	req, ok, reason := s.scanRequestForPausedInstance("inst-1", inst)
	if !ok {
		t.Fatalf("resume request was rejected: %s", reason)
	}
	if !req.IsResume || req.ResumeScanDir != scanDir || req.ResumeScanID != "scan-a" {
		t.Fatalf("scan-dir resume fields not set: %#v", req)
	}
	if req.ResumeActiveTarget != "https://a.test" {
		t.Fatalf("ResumeActiveTarget = %q", req.ResumeActiveTarget)
	}
}

func TestScanRequestForPausedWildcardRequiresQueueState(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID:       "inst-1",
		Targets:  "example.com",
		Status:   "paused",
		ScanMode: "wildcard",
		scanDir:  filepath.Join(s.dataDir, "example.com", "2026-05-23", "scan-parent"),
	}

	_, ok, reason := s.scanRequestForPausedInstance("inst-1", inst)
	if ok {
		t.Fatal("wildcard resume without queue state should be rejected")
	}
	if !strings.Contains(reason, "queue state") {
		t.Fatalf("unexpected rejection reason: %q", reason)
	}
}

func TestQueueStateExitAndAdvancePolicies(t *testing.T) {
	if !shouldPreserveQueueStateOnExit("paused", "user_paused", false) {
		t.Fatal("paused scans should preserve queue state")
	}
	if !shouldPreserveQueueStateOnExit("stopped", "signal_terminated", false) {
		t.Fatal("signal-stopped scans should preserve queue state")
	}
	if !shouldPreserveQueueStateOnExit("running", "", true) {
		t.Fatal("panic recovery should preserve queue state")
	}
	if shouldPreserveQueueStateOnExit("stopped", "user_stopped", false) {
		t.Fatal("user-stopped scans should clear queue state")
	}
	if shouldAdvanceQueueAfterTarget(false, "paused") {
		t.Fatal("paused scans should not advance queue index")
	}
	if shouldAdvanceQueueAfterTarget(true, "running") {
		t.Fatal("global stop should not advance queue index")
	}
	if !shouldAdvanceQueueAfterTarget(false, "running") {
		t.Fatal("running scans should advance queue after successful target completion")
	}
}

func TestPausedQueueStateIsManualResumeOnly(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(0, ScanRequest{
		InstanceID: "inst-paused",
		Targets:    []string{"https://paused.test"},
		ScanMode:   "single",
	})
	s.saveQueueState(0, ScanRequest{
		InstanceID: "inst-crashed",
		Targets:    []string{"https://crashed.test"},
		ScanMode:   "single",
	})

	s.markQueueStatePaused("inst-paused")
	entries := s.validQueueStateEntries(false)
	if len(entries) != 2 {
		t.Fatalf("valid queue entries = %d, want 2", len(entries))
	}

	var pausedSeen bool
	for _, entry := range entries {
		if entry.state.InstanceID == "inst-paused" {
			pausedSeen = entry.state.Paused
		}
	}
	if !pausedSeen {
		t.Fatal("paused queue state was not marked paused")
	}

	autoEntries := autoResumeQueueEntries(entries)
	if len(autoEntries) != 1 || autoEntries[0].state.InstanceID != "inst-crashed" {
		t.Fatalf("auto-resume entries = %#v, want only inst-crashed", autoEntries)
	}
}

func TestScanRecordForSessionResumePreservesPersistedState(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "example.com", "2026-05-23", "scan-1")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	startedAt := "2026-05-23T01:02:03Z"
	s.saveScanRecordTo(&ScanRecord{
		ID:           "scan-1",
		InstanceID:   "old-inst",
		Target:       "old.example",
		StartedAt:    startedAt,
		FinishedAt:   "2026-05-23T02:02:03Z",
		Status:       "stopped",
		StopReason:   "server_restart",
		Events:       []WSEvent{{Type: "message", Content: "kept event"}},
		Vulns:        []VulnSummary{{ID: "XALG-1", Title: "kept vuln", Severity: "high", Target: "old.example", Endpoint: "/login"}},
		TotalTokens:  1234,
		Iterations:   4,
		ToolCalls:    7,
		Phases:       []int{1, 6, 22},
		CurrentPhase: 6,
		SubScans: []SubScanSummary{{
			ID:     "child-1",
			Target: "api.example.com",
			Status: "finished",
		}},
	}, scanDir)

	sess := &scanSession{
		id:              "scan-1",
		instanceID:      "inst-1",
		target:          "example.com",
		scanDir:         scanDir,
		server:          s,
		userInstruction: "resume instructions",
		severityFilter:  []string{"critical"},
		discordWebhook:  "https://discord.example/hook",
		scanMode:        "single",
		companyName:     "ACME",
		logoPath:        "/uploads/logos/acme.png",
		phases:          []int{1, 6, 22},
		reconMode:       "passive",
		scanIntensity:   "active",
		resetState:      false,
	}

	rec := s.scanRecordForSession(sess)
	if rec.Status != "running" || rec.FinishedAt != "" || rec.StopReason != "" {
		t.Fatalf("resume status fields not reset: status=%q finished=%q reason=%q", rec.Status, rec.FinishedAt, rec.StopReason)
	}
	if rec.StartedAt != startedAt {
		t.Fatalf("StartedAt = %q, want %q", rec.StartedAt, startedAt)
	}
	if len(rec.Events) != 1 || rec.Events[0].Content != "kept event" {
		t.Fatalf("events were not preserved: %#v", rec.Events)
	}
	if len(rec.Vulns) != 1 || rec.Vulns[0].Title != "kept vuln" {
		t.Fatalf("vulns were not preserved: %#v", rec.Vulns)
	}
	if rec.Iterations != 4 || rec.ToolCalls != 7 || rec.TotalTokens != 1234 {
		t.Fatalf("counters not preserved: iterations=%d toolCalls=%d tokens=%d", rec.Iterations, rec.ToolCalls, rec.TotalTokens)
	}
	if sess.recordTokenOffset != 1234 {
		t.Fatalf("recordTokenOffset = %d, want 1234", sess.recordTokenOffset)
	}
	if rec.Target != "example.com" || rec.InstanceID != "inst-1" || rec.CurrentPhase != 6 {
		t.Fatalf("resume metadata not refreshed correctly: %#v", rec)
	}
	if len(rec.SubScans) != 1 || rec.SubScans[0].Target != "api.example.com" {
		t.Fatalf("subscan progress not preserved: %#v", rec.SubScans)
	}
}

func TestScanRecordForSessionResumeIgnoresMismatchedRecord(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "example.com", "2026-05-23", "scan-1")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{
		ID:          "other-scan",
		Target:      "old.example",
		StartedAt:   "2026-05-23T01:02:03Z",
		Status:      "stopped",
		Events:      []WSEvent{{Type: "message", Content: "should not load"}},
		Vulns:       []VulnSummary{{ID: "XALG-1", Title: "should not load", Severity: "high"}},
		TotalTokens: 999,
	}, scanDir)

	sess := &scanSession{
		id:            "scan-1",
		target:        "example.com",
		scanDir:       scanDir,
		server:        s,
		scanMode:      "single",
		reconMode:     "active",
		scanIntensity: "active",
		resetState:    false,
	}

	rec := s.scanRecordForSession(sess)
	if rec.ID != "scan-1" || len(rec.Events) != 0 || len(rec.Vulns) != 0 || rec.TotalTokens != 0 {
		t.Fatalf("mismatched persisted record was reused: %#v", rec)
	}
	if sess.recordTokenOffset != 0 {
		t.Fatalf("recordTokenOffset = %d, want 0", sess.recordTokenOffset)
	}
}

func TestMergeReportedVulnerabilitiesIntoRecordPreservesPersistedVulns(t *testing.T) {
	rec := &ScanRecord{
		Vulns: []VulnSummary{
			{ID: "old", Title: "Existing IDOR", Severity: "high", Target: "https://a.test", Endpoint: "/account", Method: "GET"},
			{ID: "dup", Title: "SQL Injection", Severity: "critical", Target: "https://a.test", Endpoint: "/search", Method: "POST"},
		},
	}
	mergeReportedVulnerabilitiesIntoRecord(rec, []reporting.Vulnerability{
		{ID: "XALG-1", Title: "SQL Injection", Severity: "critical", Target: "https://a.test", Endpoint: "/search", Method: "POST"},
		{ID: "XALG-2", Title: "Stored XSS", Severity: "high", Target: "https://a.test", Endpoint: "/profile", Method: "POST"},
	})

	if len(rec.Vulns) != 3 {
		t.Fatalf("merged vuln count = %d, want 3: %#v", len(rec.Vulns), rec.Vulns)
	}
	if rec.Vulns[0].Title != "Existing IDOR" || rec.Vulns[2].Title != "Stored XSS" {
		t.Fatalf("unexpected merged vulns: %#v", rec.Vulns)
	}
}

func TestSeedResumeInstanceFromRecordPreservesDashboardState(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "example.com", "2026-05-23", "scan-1")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{
		ID:           "scan-1",
		Name:         "Saved scan",
		Target:       "example.com",
		StartedAt:    "2026-05-23T01:02:03Z",
		Status:       "stopped",
		Events:       []WSEvent{{Type: "message", Content: "old event"}},
		Vulns:        []VulnSummary{{ID: "XALG-1", Title: "old vuln", Severity: "high", Target: "example.com"}},
		TotalTokens:  1234,
		Iterations:   4,
		ToolCalls:    7,
		CurrentPhase: 6,
	}, scanDir)

	inst := &ScanInstance{ID: "inst-1", Status: "pending", Targets: "example.com"}
	s.seedResumeInstanceFromRecord(inst, ScanRequest{IsResume: true, ResumeScanDir: scanDir})

	if inst.Iterations != 4 || inst.ToolCalls != 7 || inst.TotalTokens != 1234 {
		t.Fatalf("instance counters not seeded: iterations=%d toolCalls=%d tokens=%d", inst.Iterations, inst.ToolCalls, inst.TotalTokens)
	}
	if inst.VulnCount != 1 || len(inst.Vulns) != 1 || inst.Vulns[0].Title != "old vuln" {
		t.Fatalf("instance vulns not seeded: count=%d vulns=%#v", inst.VulnCount, inst.Vulns)
	}
	if len(inst.events) != 1 || inst.events[0].Content != "old event" {
		t.Fatalf("instance events not seeded: %#v", inst.events)
	}
	if inst.CurrentPhase != 6 || inst.Status != "pending" {
		t.Fatalf("unexpected seeded instance phase/status: phase=%d status=%q", inst.CurrentPhase, inst.Status)
	}
}

func TestApplyInstanceSnapshotDoesNotErasePersistedResumeData(t *testing.T) {
	s := newTestServer(t, nil)
	rec := &ScanRecord{
		ID:          "scan-1",
		InstanceID:  "inst-1",
		Status:      "stopped",
		Events:      []WSEvent{{Type: "message", Content: "persisted event"}},
		Vulns:       []VulnSummary{{ID: "XALG-1", Title: "persisted vuln", Severity: "high", Target: "example.com"}},
		Iterations:  4,
		ToolCalls:   7,
		TotalTokens: 1234,
	}
	inst := &ScanInstance{ID: "inst-1", Status: "running", Iterations: 1, ToolCalls: 2, TotalTokens: 100}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	s.applyInstanceSnapshot(rec, true)

	if rec.Status != "running" {
		t.Fatalf("status = %q, want running", rec.Status)
	}
	if rec.Iterations != 4 || rec.ToolCalls != 7 || rec.TotalTokens != 1234 {
		t.Fatalf("persisted counters were erased: iterations=%d toolCalls=%d tokens=%d", rec.Iterations, rec.ToolCalls, rec.TotalTokens)
	}
	if len(rec.Vulns) != 1 || rec.Vulns[0].Title != "persisted vuln" {
		t.Fatalf("persisted vulns were erased: %#v", rec.Vulns)
	}
	if len(rec.Events) != 1 || rec.Events[0].Content != "persisted event" {
		t.Fatalf("persisted events were erased: %#v", rec.Events)
	}
}

func TestQueueState_OldFileWithoutNewFields(t *testing.T) {
	// Simulate an old queue_state.json that only has the original fields.
	// New fields should deserialize as zero values.
	s := newTestServer(t, nil)
	oldJSON := `{
		"targets": ["https://old.test"],
		"current_idx": 0,
		"instruction": "old instruction",
		"scan_mode": "single",
		"started_at": "2026-01-01T00:00:00Z",
		"active": true
	}`
	if err := os.WriteFile(s.queueStatePath(), []byte(oldJSON), 0o644); err != nil {
		t.Fatalf("write old queue state: %v", err)
	}

	state := s.loadQueueState()
	if state == nil {
		t.Fatal("old queue state not loaded")
	}
	if len(state.Targets) != 1 || state.Targets[0] != "https://old.test" {
		t.Errorf("Targets = %v", state.Targets)
	}
	if state.Instruction != "old instruction" {
		t.Errorf("Instruction = %q", state.Instruction)
	}
	// New fields should be zero values
	if state.Name != "" {
		t.Errorf("Name should be empty for old file, got %q", state.Name)
	}
	if len(state.SeverityFilter) != 0 {
		t.Errorf("SeverityFilter should be empty for old file, got %v", state.SeverityFilter)
	}
	if len(state.Phases) != 0 {
		t.Errorf("Phases should be empty for old file, got %v", state.Phases)
	}
	if state.CompanyName != "" {
		t.Errorf("CompanyName should be empty for old file, got %q", state.CompanyName)
	}
}

func TestBuildActivityPolicyInstructionPassiveOverridesActiveExamples(t *testing.T) {
	instruction := buildActivityPolicyInstruction("passive", "passive")
	if !strings.Contains(instruction, "Recon phase: PASSIVE ONLY") {
		t.Fatalf("missing passive recon policy: %s", instruction)
	}
	if !strings.Contains(instruction, "Testing phases: PASSIVE ONLY") {
		t.Fatalf("missing passive testing policy: %s", instruction)
	}
	if !strings.Contains(instruction, "overrides all methodology examples") {
		t.Fatalf("missing override language: %s", instruction)
	}
}

func TestQueueStatus_ReturnsNewFields(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(0, ScanRequest{
		Targets:        []string{"https://a.test"},
		ScanMode:       "dast",
		Name:           "Status Test",
		SeverityFilter: []string{"high"},
		Phases:         []int{1, 22},
		ReconMode:      "passive",
		ScanIntensity:  "passive",
		CompanyName:    "TestCo",
		LogoPath:       "/logos/test.png",
	})

	rr := httptest.NewRecorder()
	s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d", rr.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status["name"] != "Status Test" {
		t.Errorf("name = %v", status["name"])
	}
	if status["company_name"] != "TestCo" {
		t.Errorf("company_name = %v", status["company_name"])
	}
	if status["logo_path"] != "/logos/test.png" {
		t.Errorf("logo_path = %v", status["logo_path"])
	}
	if status["recon_mode"] != "passive" {
		t.Errorf("recon_mode = %v", status["recon_mode"])
	}
	if status["scan_intensity"] != "passive" {
		t.Errorf("scan_intensity = %v", status["scan_intensity"])
	}
	// DiscordWebhook should NOT be exposed via the API
	if _, ok := status["discord_webhook"]; ok {
		t.Error("discord_webhook should not be exposed in queue status API")
	}
}

func TestScanPersistence_ListLatestDeleteAndRebuild(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
		Vulns:     []VulnSummary{{ID: "v1", Severity: "high"}},
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/scan-b", ScanRecord{
		ID:               "scan-b",
		Target:           "https://b.test",
		StartedAt:        "2026-05-02T10:00:00Z",
		Status:           "running",
		ScanMode:         "wildcard",
		SubScanTotal:     2,
		SubScanRemaining: 2,
		SubScans: []SubScanSummary{
			{Target: "https://sub.b.test", Status: "pending"},
			{Target: "https://later.b.test", Status: "pending"},
		},
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/subdomain", ScanRecord{
		ID:           "subdomain",
		Target:       "https://sub.b.test",
		ParentTarget: "https://b.test",
		StartedAt:    "2026-05-02T11:00:00Z",
		Status:       "running",
		Vulns:        []VulnSummary{{ID: "v2", Severity: "medium"}},
	})

	rr := httptest.NewRecorder()
	s.handleListScans(rr, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"scan-b"`) {
		t.Fatalf("list scans response: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"id":"subdomain"`) {
		t.Fatalf("subdomain scan leaked into top-level list: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"sub_scan_total":2`) ||
		!strings.Contains(rr.Body.String(), `"sub_scan_remaining":1`) {
		t.Fatalf("parent scan missing subdomain count: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/latest", nil))
	var latest ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &latest); err != nil {
		t.Fatalf("decode latest scan: %v body=%s", err, rr.Body.String())
	}
	if latest.ID != "scan-b" {
		t.Fatalf("latest scan should return newest top-level parent: %#v", latest)
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scan-b", nil))
	if !strings.Contains(rr.Body.String(), `"sub_scans"`) ||
		!strings.Contains(rr.Body.String(), `"target":"https://sub.b.test"`) ||
		!strings.Contains(rr.Body.String(), `"target":"https://later.b.test"`) ||
		!strings.Contains(rr.Body.String(), `"id":"v2"`) {
		t.Fatalf("parent scan did not include child subdomain detail: %s", rr.Body.String())
	}

	s.rebuildInstancesFromDisk()
	if _, ok := s.instances["subdomain"]; ok {
		t.Fatal("subdomain scan should not be rebuilt as a top-level instance")
	}
	inst := s.instances["scan-b"]
	if inst == nil || inst.Status != "stopped" || inst.StopReason != "server_restart_no_resume_state" {
		t.Fatalf("orphaned running scan was not stopped on rebuild: %#v", inst)
	}
	_, rebuilt := s.findScanByID("scan-b")
	if rebuilt == nil || rebuilt.Status != "stopped" || rebuilt.StopReason != "server_restart_no_resume_state" {
		t.Fatalf("orphaned rebuilt scan was not persisted as stopped: %#v", rebuilt)
	}
	_, rebuiltSub := s.findScanByID("subdomain")
	if rebuiltSub == nil || rebuiltSub.Status != "stopped" || rebuiltSub.StopReason != "server_restart_no_resume_state" {
		t.Fatalf("orphaned subdomain scan was not persisted as stopped: %#v", rebuiltSub)
	}

	rr = httptest.NewRecorder()
	s.handleListScans(rr, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	var listed []struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		FinishedAt string `json:"finished_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list scans after rebuild: %v body=%s", err, rr.Body.String())
	}
	for _, got := range listed {
		if got.ID == "subdomain" {
			t.Fatalf("subdomain scan leaked into rebuilt list: %#v", got)
		}
		if got.ID == "scan-b" && got.Status != "stopped" {
			t.Fatalf("list scans still returned stale status for %s: %#v", got.ID, got)
		}
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/scan-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, rec := s.findScanByID("scan-a"); rec != nil {
		t.Fatal("scan-a still found after delete")
	}
}

func TestFindScanByID_ResolvesParentInstanceAlias(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:         "scan-a",
		InstanceID: "queue-1234",
		Target:     "https://a.test",
		StartedAt:  "2026-05-01T10:00:00Z",
		Status:     "finished",
	})

	dir, rec := s.findScanByID("queue-1234")
	if dir == "" || rec == nil || rec.ID != "scan-a" {
		t.Fatalf("alias did not resolve to persisted scan: dir=%q rec=%#v", dir, rec)
	}
}

func TestHandleGetScan_RejectsUnknownShortInstanceRoute(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: time.Now().Add(-5 * time.Minute).Format(time.RFC3339Nano),
		Status:    "finished",
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/deadbeef", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown short route resolved another scan: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetScan_MarksGlobalDiscordWebhookConfigured(t *testing.T) {
	s := newTestServer(t, &config.Config{
		DiscordWebhook:    "https://discord.example/webhook",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scan-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"discord_webhook_configured":true`) {
		t.Fatalf("global webhook was not marked configured: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "discord.example") {
		t.Fatalf("webhook URL leaked in response: %s", rr.Body.String())
	}
}

func TestHandleGetScan_PrefersPersistedWildcardProgressOverFinishedInstanceReplay(t *testing.T) {
	s := newTestServer(t, nil)
	startedAt := "2026-05-01T10:00:00Z"
	finishedAt := "2026-05-01T12:00:00Z"
	subScans := make([]SubScanSummary, 0, 9)
	for i := 1; i <= 9; i++ {
		subScans = append(subScans, SubScanSummary{
			ID:         "child-finished",
			Target:     "sub" + strconv.Itoa(i) + ".b.test",
			Status:     "finished",
			FinishedAt: finishedAt,
		})
	}
	writeScanRecord(t, s.dataDir, "target-b/2026-05-01/scan-parent", ScanRecord{
		ID:               "scan-parent",
		InstanceID:       "queue-1234",
		Target:           "https://b.test",
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		Status:           "finished",
		ScanMode:         "wildcard",
		CurrentPhase:     5,
		SubScanTotal:     9,
		SubScanCompleted: 9,
		SubScans:         subScans,
	})

	inst := &ScanInstance{
		ID:           "queue-1234",
		Targets:      "https://b.test",
		Status:       "finished",
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
		ScanMode:     "wildcard",
		CurrentPhase: 5,
	}
	for i := 1; i <= 5; i++ {
		target := "sub" + strconv.Itoa(i) + ".b.test"
		inst.events = append(inst.events,
			WSEvent{Type: "target_started", Target: target, ParentTarget: "https://b.test", SubTargetTotal: 9, Timestamp: startedAt},
			WSEvent{Type: "target_completed", Target: target, ParentTarget: "https://b.test", SubTargetTotal: 9, Timestamp: finishedAt},
		)
	}
	for i := 6; i <= 9; i++ {
		inst.events = append(inst.events, WSEvent{
			Type:           "target_started",
			Target:         "sub" + strconv.Itoa(i) + ".b.test",
			ParentTarget:   "https://b.test",
			SubTargetTotal: 9,
			Timestamp:      startedAt,
		})
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/queue-1234", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	var rec ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode scan: %v body=%s", err, rr.Body.String())
	}
	if rec.ID != "scan-parent" || rec.Status != "finished" {
		t.Fatalf("expected persisted finished parent, got %#v", rec)
	}
	if rec.CurrentPhase != 22 {
		t.Fatalf("finished scan current phase = %d, want 22", rec.CurrentPhase)
	}
	if rec.SubScanCompleted != 9 || rec.SubScanRunning != 0 || rec.SubScanRemaining != 0 {
		t.Fatalf("wildcard counts came from stale replay instead of persisted progress: completed=%d running=%d remaining=%d", rec.SubScanCompleted, rec.SubScanRunning, rec.SubScanRemaining)
	}
}

func TestAttachWildcardSubScans_NormalizesDanglingRunningChildrenForTerminalParent(t *testing.T) {
	s := newTestServer(t, nil)
	rec := &ScanRecord{
		ID:         "scan-parent",
		Target:     "https://b.test",
		StartedAt:  "2026-05-01T10:00:00Z",
		FinishedAt: "2026-05-01T12:00:00Z",
		Status:     "finished",
		ScanMode:   "wildcard",
		SubScans: []SubScanSummary{
			{Target: "done.b.test", Status: "finished"},
			{Target: "active.b.test", Status: "running"},
			{Target: "queued.b.test", Status: "pending"},
		},
		SubScanTotal: 3,
	}

	s.attachWildcardSubScans(rec)

	if rec.Status != "stopped" || rec.StopReason != "incomplete_wildcard_subscans" {
		t.Fatalf("terminal parent with dangling children should become stopped, got status=%q reason=%q", rec.Status, rec.StopReason)
	}
	if rec.SubScanRunning != 0 || rec.SubScanRemaining != 0 || rec.SubScanCompleted != 3 {
		t.Fatalf("dangling child counts not normalized: completed=%d running=%d remaining=%d", rec.SubScanCompleted, rec.SubScanRunning, rec.SubScanRemaining)
	}
	for _, child := range rec.SubScans {
		if child.Status == "running" || child.Status == "pending" {
			t.Fatalf("child %s still active after parent ended: %#v", child.Target, child)
		}
	}
}

func writeScanRecord(t *testing.T, baseDir, rel string, rec ScanRecord) {
	t.Helper()
	dir := filepath.Join(baseDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal scan record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), data, 0o644); err != nil {
		t.Fatalf("write scan.json: %v", err)
	}
}

func TestHandleRateLimitSettings_ClampsAndReplacesLimiter(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 5, RateLimitWindow: 30})

	rr := httptest.NewRecorder()
	s.handleRateLimit(rr, httptest.NewRequest(http.MethodPost, "/api/settings/rate-limit", strings.NewReader(`{"requests":2000,"window":1}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("rate limit update code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.RateLimitRequests != 1000 || s.cfg.RateLimitWindow != 10 {
		t.Fatalf("config was not clamped: requests=%d window=%d", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	}
	if s.rateLimiter == nil {
		t.Fatal("rate limiter was not replaced")
	}
}

func TestAgentMailSettings_MasksAndPreservesExistingKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	oldKey := "old-secret-12345678"
	if err := os.WriteFile(envFile, []byte("XALGORIX_LLM=test\nAGENTMAIL_POD=oldpod\nAGENTMAIL_API_KEY="+oldKey+"\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		AgentMailPod:      "oldpod",
		AgentMailAPIKey:   oldKey,
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/agentmail", nil))
	var getResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp["apiKey"] != "****12345678" || getResp["hasApiKey"] != true {
		t.Fatalf("unexpected masked GET response: %#v", getResp)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"pod":"newpod","apiKey":"****12345678"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("preserve POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != oldKey {
		t.Fatalf("masked POST overwrote key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY="+oldKey) || !strings.Contains(string(data), "AGENTMAIL_POD=newpod") {
		t.Fatalf("env file did not preserve old key and update pod:\n%s", string(data))
	}
	if info, err := os.Stat(envFile); err != nil {
		t.Fatalf("stat env file: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode = %#o, want 0600", info.Mode().Perm())
	}

	rr = httptest.NewRecorder()
	body = strings.NewReader(`{"pod":"newpod","apiKey":"new-secret-abcdef12"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("new key POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != "new-secret-abcdef12" {
		t.Fatalf("new POST did not update config key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err = os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file after new key: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY=new-secret-abcdef12") {
		t.Fatalf("env file did not contain new key:\n%s", string(data))
	}
}

func TestLLMSettings_MasksPreservesAndPersists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	oldAPIKey := "old-llm-secret-12345678"
	oldGeminiKey := "old-gemini-secret-87654321"
	if err := os.WriteFile(envFile, []byte("XALGORIX_LLM=old/model\nXALGORIX_API_KEY="+oldAPIKey+"\nGEMINI_API_KEY="+oldGeminiKey+"\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		LLM:               "old/model",
		APIBase:           "https://old.example/v1",
		APIKey:            oldAPIKey,
		ReasoningEffort:   "high",
		LLMMaxRetries:     5,
		MemCompTimeout:    30,
		MaxIterations:     0,
		GeminiAPIKey:      oldGeminiKey,
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/llm", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code = %d body=%s", rr.Code, rr.Body.String())
	}
	var getResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp["apiKey"] != "****12345678" || getResp["geminiApiKey"] != "****87654321" {
		t.Fatalf("unexpected masked GET response: %#v", getResp)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"model":"openai/gpt-5.4","apiBase":"https://api.openai.com/v1","apiKey":"****12345678","reasoningEffort":"medium","llmMaxRetries":7,"memoryCompressorTimeout":45,"maxIterations":9,"geminiApiKey":"****87654321"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLM != "openai/gpt-5.4" || s.cfg.APIBase != "https://api.openai.com/v1" {
		t.Fatalf("LLM settings not applied: llm=%q apiBase=%q", s.cfg.LLM, s.cfg.APIBase)
	}
	if s.cfg.APIKey != oldAPIKey || s.cfg.GeminiAPIKey != oldGeminiKey {
		t.Fatalf("masked POST did not preserve secrets: api=%q gemini=%q", s.cfg.APIKey, s.cfg.GeminiAPIKey)
	}
	if s.cfg.ReasoningEffort != "medium" || s.cfg.LLMMaxRetries != 7 || s.cfg.MemCompTimeout != 45 || s.cfg.MaxIterations != 9 {
		t.Fatalf("numeric settings not applied: %#v", s.cfg)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_LLM=openai/gpt-5.4",
		"XALGORIX_API_BASE=https://api.openai.com/v1",
		"XALGORIX_API_KEY=" + oldAPIKey,
		"GEMINI_API_KEY=" + oldGeminiKey,
		"XALGORIX_REASONING_EFFORT=medium",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

// TestLLMSettings_CatalogShape_APIKeyCreatesProfile validates the
// v4.4.22 POST shape: a (provider, authMethod=api_key, apiKey, model)
// bundle must Put an auth.Profile into the store, write the matching
// XALGORIX_LLM_PROFILE env var, and continue to write the legacy env
// trio so existing scripts keep working.
func TestLLMSettings_CatalogShape_APIKeyCreatesProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	if err := os.WriteFile(envFile, []byte(""), 0o644); err != nil {
		t.Fatalf("seed env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		ReasoningEffort:   "high",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"provider":"openai","authMethod":"api_key","profileId":"default","apiKey":"sk-test-12345","model":"openai/gpt-4o"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}

	// Profile must be persisted.
	if s.profiles == nil {
		t.Fatalf("profile store not initialized")
	}
	prof, ok, err := s.profiles.Get(context.Background(), "openai:default")
	if err != nil {
		t.Fatalf("profile get: %v", err)
	}
	if !ok {
		t.Fatalf("profile openai:default not persisted")
	}
	if prof.APIKey != "sk-test-12345" {
		t.Fatalf("profile APIKey = %q, want sk-test-12345", prof.APIKey)
	}

	// XALGORIX_LLM_PROFILE must be wired so the resolver can pick
	// up the new profile.
	if s.cfg.LLMProfile != "openai:default" {
		t.Fatalf("LLMProfile = %q, want openai:default", s.cfg.LLMProfile)
	}
	if got := os.Getenv("XALGORIX_LLM_PROFILE"); got != "openai:default" {
		t.Fatalf("env XALGORIX_LLM_PROFILE = %q, want openai:default", got)
	}

	// Legacy env vars must still be written for the legacyResolver
	// fallback path.
	if s.cfg.LLM != "gpt-4o" {
		t.Fatalf("LLM = %q, want gpt-4o", s.cfg.LLM)
	}
	if s.cfg.LLMProvider != "openai" {
		t.Fatalf("LLMProvider = %q, want openai", s.cfg.LLMProvider)
	}
	if s.cfg.APIKey != "sk-test-12345" {
		t.Fatalf("legacy APIKey not synced: %q", s.cfg.APIKey)
	}

	// GET must surface the new fields.
	rr = httptest.NewRecorder()
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/llm", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if resp["provider"] != "openai" {
		t.Fatalf("provider = %v, want openai", resp["provider"])
	}
	if resp["authMethod"] != "api_key" {
		t.Fatalf("authMethod = %v, want api_key", resp["authMethod"])
	}
	if resp["activeProfileKey"] != "openai:default" {
		t.Fatalf("activeProfileKey = %v, want openai:default", resp["activeProfileKey"])
	}
	profiles, ok := resp["profiles"].([]any)
	if !ok || len(profiles) != 1 {
		t.Fatalf("profiles list malformed: %#v", resp["profiles"])
	}
}

func TestLLMSettings_CredentialFreeProviderClearsProfileAndStoresBareModel(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".xalgorix.env"), []byte(""), 0o600); err != nil {
		t.Fatalf("seed env file: %v", err)
	}
	s := newTestServer(t, &config.Config{
		LLM: "novita/old-model", LLMProvider: "novita", LLMProfile: "novita:default", APIKey: "secret",
		ReasoningEffort: "high", RateLimitRequests: 60, RateLimitWindow: 60,
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"provider":"ollama","authMethod":"none","model":"ollama/deepseek-v4-pro:cloud"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLMProvider != "ollama" || s.cfg.LLM != "deepseek-v4-pro:cloud" {
		t.Fatalf("provider/model = %q/%q, want ollama/deepseek-v4-pro:cloud", s.cfg.LLMProvider, s.cfg.LLM)
	}
	if s.cfg.LLMProfile != "" || s.cfg.APIKey != "" {
		t.Fatalf("credential state not cleared: profile=%q apiKey=%q", s.cfg.LLMProfile, s.cfg.APIKey)
	}
	wantBase := "http://localhost:11434/v1"
	if _, err := os.Stat("/.dockerenv"); err == nil {
		wantBase = "http://host.docker.internal:11434/v1"
	}
	if strings.TrimSpace(s.cfg.APIBase) != wantBase {
		t.Fatalf("APIBase = %q, want %q", s.cfg.APIBase, wantBase)
	}

	settings := s.llmSettings(context.Background())
	if settings.Provider != "ollama" || settings.AuthMethod != "none" || settings.Model != "deepseek-v4-pro:cloud" {
		t.Fatalf("settings = provider=%q auth=%q model=%q", settings.Provider, settings.AuthMethod, settings.Model)
	}
}

func TestLLMSettings_CustomProviderPersistsOllamaCompatibility(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	if err := os.WriteFile(envFile, []byte(""), 0o600); err != nil {
		t.Fatalf("seed env file: %v", err)
	}
	s := newTestServer(t, &config.Config{
		ReasoningEffort:   "high",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"provider":"custom","authMethod":"api_key","profileId":"default","apiKey":"local-test-key","apiBase":"http://models.example:9443/v1","model":"reasoning-model:latest","reasoningEffort":"none","ollamaCompatible":true}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLMProvider != "custom" || s.cfg.LLM != "reasoning-model:latest" {
		t.Fatalf("provider/model = %q/%q, want custom/reasoning-model:latest", s.cfg.LLMProvider, s.cfg.LLM)
	}
	if s.cfg.APIBase != "http://models.example:9443/v1" || !s.cfg.OllamaCompatible || s.cfg.ReasoningEffort != "none" {
		t.Fatalf("custom Ollama settings not applied: %#v", s.cfg)
	}

	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_LLM_PROVIDER=custom",
		"XALGORIX_LLM=reasoning-model:latest",
		"XALGORIX_API_BASE=http://models.example:9443/v1",
		"XALGORIX_REASONING_EFFORT=none",
		"XALGORIX_OLLAMA_COMPATIBLE=true",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

func TestLLMSettingsPreservesProviderNativeModelPath(t *testing.T) {
	s := newTestServer(t, &config.Config{
		LLM: "zai-org/glm-4.5", LLMProvider: "novita",
		ReasoningEffort: "high", RateLimitRequests: 60, RateLimitWindow: 60,
	})

	settings := s.llmSettings(context.Background())
	if settings.Model != "zai-org/glm-4.5" {
		t.Fatalf("Model = %q, want provider-native path", settings.Model)
	}
}

// TestLLMSettings_CatalogShape_ActiveOnly validates the "pick existing
// profile" branch: when only activeProfileKey is supplied (no new
// credentials), the handler just writes XALGORIX_LLM_PROFILE.
func TestLLMSettings_CatalogShape_ActiveOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".xalgorix.env"), []byte(""), 0o644); err != nil {
		t.Fatalf("seed env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		ReasoningEffort:   "high",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	// Pre-seed a profile so activeProfileKey points at something real.
	if err := s.profiles.Put(context.Background(), auth.Profile{
		Provider:  "openai",
		ProfileID: "scratch",
		Type:      auth.APIKey,
		APIKey:    "sk-pre-existing",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"activeProfileKey":"openai:scratch"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLMProfile != "openai:scratch" {
		t.Fatalf("LLMProfile = %q, want openai:scratch", s.cfg.LLMProfile)
	}
}

// TestLLMSettings_CatalogShape_RejectsUnknownProvider validates the
// 400-on-unknown-provider gate.
func TestLLMSettings_CatalogShape_RejectsUnknownProvider(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".xalgorix.env"), []byte(""), 0o644); err != nil {
		t.Fatalf("seed env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		ReasoningEffort:   "high",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"provider":"acme-not-real","authMethod":"api_key","apiKey":"sk-x","model":"acme-not-real/foo"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("POST code = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// TestLLMSettings_CatalogShape_ProviderSwitchWithMaskedKey is a regression
// test for the "provider reverts after refresh" bug: switching the provider
// while leaving the API key masked (**** — the UI tells the operator to keep
// it to preserve the saved key) must still persist the new provider by moving
// the XALGORIX_LLM_PROFILE pointer. Previously the api_key branch was gated on
// a freshly-typed key, so only the model env var changed and the provider
// derived back to the stale profile on the next GET.
func TestLLMSettings_CatalogShape_ProviderSwitchWithMaskedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".xalgorix.env"), []byte(""), 0o644); err != nil {
		t.Fatalf("seed env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		ReasoningEffort:   "high",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	// 1) Initial save under litellm with a real key.
	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"provider":"litellm","authMethod":"api_key","profileId":"default","apiKey":"sk-real-key","model":"minimax/MiniMax-M2.7"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST #1 code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLMProfile != "litellm:default" {
		t.Fatalf("after POST #1 LLMProfile = %q, want litellm:default", s.cfg.LLMProfile)
	}

	// 2) Switch the provider to minimax but KEEP the masked key.
	rr = httptest.NewRecorder()
	body = strings.NewReader(`{"provider":"minimax","authMethod":"api_key","profileId":"default","apiKey":"****-key","model":"minimax/MiniMax-M2.7"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST #2 code = %d body=%s", rr.Code, rr.Body.String())
	}

	// The active profile pointer must have moved to minimax.
	if s.cfg.LLMProfile != "minimax:default" {
		t.Fatalf("after provider switch LLMProfile = %q, want minimax:default", s.cfg.LLMProfile)
	}
	// A minimax profile must exist, carrying over the previously-saved key.
	prof, ok, err := s.profiles.Get(context.Background(), "minimax:default")
	if err != nil {
		t.Fatalf("profile get: %v", err)
	}
	if !ok {
		t.Fatalf("minimax:default profile not persisted after switch")
	}
	if prof.APIKey != "sk-real-key" {
		t.Fatalf("minimax profile APIKey = %q, want carried-over sk-real-key", prof.APIKey)
	}

	// 3) GET must now report minimax — the symptom the user saw (reverting
	// to litellm on refresh) is fixed.
	rr = httptest.NewRecorder()
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/llm", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"provider":"minimax"`) {
		t.Fatalf("GET provider did not persist as minimax; body=%s", rr.Body.String())
	}
}

func TestEnvironmentSettings_RejectsUnknownAndUpdatesRuntime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	rr := httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", strings.NewReader(`{"values":{"UNSUPPORTED_ENV":"x"}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unsupported env code = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"values":{"XALGORIX_RATE_LIMIT_REQUESTS":"2000","XALGORIX_RATE_LIMIT_WINDOW":"1","XALGORIX_DISCORD_WEBHOOK":"https://discord.example/webhook","XALGORIX_BIND":"0.0.0.0"}}`)
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.RateLimitRequests != 1000 || s.cfg.RateLimitWindow != 10 {
		t.Fatalf("rate limits not clamped/applied: %d/%d", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	}
	if s.cfg.DiscordWebhook != "https://discord.example/webhook" || s.discordWebhook != "https://discord.example/webhook" {
		t.Fatalf("discord webhook not applied: cfg=%q runtime=%q", s.cfg.DiscordWebhook, s.discordWebhook)
	}
	if s.cfg.BindAddr != "0.0.0.0" {
		t.Fatalf("bind address not applied: %q", s.cfg.BindAddr)
	}
	var resp environmentSettingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.RestartRequired {
		t.Fatal("expected restartRequired for bind change")
	}
	data, err := os.ReadFile(filepath.Join(home, ".xalgorix.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_RATE_LIMIT_REQUESTS=1000",
		"XALGORIX_RATE_LIMIT_WINDOW=10",
		"XALGORIX_DISCORD_WEBHOOK=https://discord.example/webhook",
		"XALGORIX_BIND=0.0.0.0",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

func TestInstanceAction_GetAndStopSpecificInstance(t *testing.T) {
	s := newTestServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.instances["inst-1"] = &ScanInstance{
		ID:        "inst-1",
		Targets:   "https://a.test",
		Status:    "running",
		ScanMode:  "wildcard",
		StartedAt: "2026-05-02T10:00:00Z",
		SubScans: []SubScanSummary{
			{ID: "child-1", Target: "a.example.test", Status: "running", StartedAt: "2026-05-02T10:01:00Z"},
			{Target: "b.example.test", Status: "pending"},
		},
		cancel: cancel,
	}

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/inst-1", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"inst-1"`) {
		t.Fatalf("get instance response: code=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodPost, "/api/instances/inst-1/stop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("stop instance code = %d body=%s", rr.Code, rr.Body.String())
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("instance cancel function was not called")
	}
	if got := s.instances["inst-1"].Status; got != "stopped" {
		t.Fatalf("instance status = %q, want stopped", got)
	}
	var stopped struct {
		InstanceID string           `json:"instance_id"`
		Status     string           `json:"status"`
		SubScans   []SubScanSummary `json:"sub_scans"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &stopped); err != nil {
		t.Fatalf("decode stop response: %v", err)
	}
	if stopped.InstanceID != "inst-1" || stopped.Status != "stopped" {
		t.Fatalf("stop response identity/status = %#v", stopped)
	}
	if len(stopped.SubScans) != 2 || stopped.SubScans[0].Status != "stopped" || stopped.SubScans[0].ID != "child-1" {
		t.Fatalf("stop response did not freeze exact dispatched children: %#v", stopped.SubScans)
	}
	if stopped.SubScans[1].Status != "stopped" || stopped.SubScans[1].ID != "" || stopped.SubScans[1].StartedAt != "" {
		t.Fatalf("never-dispatched child gained evidence: %#v", stopped.SubScans[1])
	}
}

// withStubLookupHost swaps the package-level scopeguard.LookupHost
// shim for the duration of a single test. Restoration runs via
// t.Cleanup so every test exits with the original net.LookupHost
// binding in place, regardless of failure or skip. The test functions
// below MUST NOT call t.Parallel() because scopeguard.LookupHost is
// package-level state.
func withStubLookupHost(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := scopeguard.SetLookupHost(stub)
	t.Cleanup(func() { scopeguard.SetLookupHost(prev) })
}

// TestIsBlockedTarget_SingleLookup asserts that isBlockedTarget invokes
// the test-shimmed lookupHost exactly once per call when the target is a
// hostname that requires DNS resolution, and that two back-to-back calls
// each perform one lookup (no caching across calls). Covers Req 3.1 and
// 3.6.
func TestIsBlockedTarget_SingleLookup(t *testing.T) {
	s := newTestServer(t, nil)

	var calls int
	withStubLookupHost(t, func(host string) ([]string, error) {
		calls++
		// Return a public IP so the target threads through every
		// downstream check (port match, self-iface match, private
		// CIDR scan) without short-circuiting before the lookup
		// counter is observed.
		return []string{"203.0.113.10"}, nil
	})

	if blocked := s.isBlockedTarget("https://oos.example/"); blocked {
		t.Fatalf("public-IP-resolving target reported blocked = true")
	}
	if calls != 1 {
		t.Fatalf("lookupHost call count after first call = %d, want 1", calls)
	}

	// Second call: lookups are not cached across invocations, so the
	// counter MUST advance by exactly one.
	if blocked := s.isBlockedTarget("https://oos.example/"); blocked {
		t.Fatalf("second call to public-IP-resolving target reported blocked = true")
	}
	if calls != 2 {
		t.Fatalf("lookupHost call count after second call = %d, want 2", calls)
	}
}

// TestIsBlockedTarget_IPLiteralSkipsLookup asserts that when the target
// host is already an IP literal, isBlockedTarget never invokes the
// resolver shim. Covers Req 3.3.
func TestIsBlockedTarget_IPLiteralSkipsLookup(t *testing.T) {
	s := newTestServer(t, nil)

	var calls int
	withStubLookupHost(t, func(host string) ([]string, error) {
		calls++
		return nil, errors.New("lookupHost should not be invoked for IP literals")
	})

	// Public IP literal — should pass through without a lookup and
	// without being blocked.
	if blocked := s.isBlockedTarget("https://203.0.113.10/"); blocked {
		t.Fatalf("public IP literal reported blocked = true")
	}
	if calls != 0 {
		t.Fatalf("lookupHost calls for public IP literal = %d, want 0", calls)
	}

	// RFC1918 IP literal — with smart scope guard, this is NOT blocked
	// unless it matches a local interface. 10.0.0.5 is unlikely to be
	// on our interfaces.
	// NOTE: We can't guarantee 10.0.0.5 isn't on a local interface,
	// so just verify no DNS lookup is performed for IP literals.
	_ = s.isBlockedTarget("http://10.0.0.5/")
	if calls != 0 {
		t.Fatalf("lookupHost calls for private IP literal = %d, want 0", calls)
	}
}

// TestIsBlockedTarget_DNSFailureAllows asserts that lookup failures and
// empty resolutions result in an allow (return false), without any
// further blocking signals being applied. Covers Req 3.4.
func TestIsBlockedTarget_DNSFailureAllows(t *testing.T) {
	s := newTestServer(t, nil)

	t.Run("lookup error", func(t *testing.T) {
		var calls int
		withStubLookupHost(t, func(host string) ([]string, error) {
			calls++
			return nil, errors.New("simulated NXDOMAIN")
		})
		if blocked := s.isBlockedTarget("https://nope.example/"); blocked {
			t.Fatalf("DNS-error target reported blocked = true; want false (allow)")
		}
		if calls != 1 {
			t.Fatalf("lookupHost calls = %d, want 1", calls)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		var calls int
		withStubLookupHost(t, func(host string) ([]string, error) {
			calls++
			return []string{}, nil
		})
		if blocked := s.isBlockedTarget("https://void.example/"); blocked {
			t.Fatalf("empty-result target reported blocked = true; want false (allow)")
		}
		if calls != 1 {
			t.Fatalf("lookupHost calls = %d, want 1", calls)
		}
	})
}

// ───────────────────────────────────────────────────────────────────
// Preservation property tests (spec: scope-guard-local-only, task 2).
//
// Property 2 (web side): for every host-shaped argument X the
// preservation partition exercises, oracleIsBlockedTarget(X) ==
// (*Server).isBlockedTarget(X). The oracle (oracleIsBlockedTarget,
// captured in scope_oracle_test.go) is byte-frozen against today's
// production isBlockedTarget. On unfixed code the assertion is
// tautological. After task 3.2 reduces the production function to a
// one-line scopeguard.IsLocalOrListener delegation, the same property
// pins behavior preservation across the web/scopeguard refactor
// (Requirement 3.8).
//
// DNS lookup count sub-property: the production isBlockedTarget
// guarantees a single net.LookupHost call per non-IP-literal target
// (design.md → "DNS Lookup Semantics"). The frozen oracle MUST do
// the same, otherwise the per-call cost would have already drifted
// pre-fix. Both indirections are wrapped with a counter and
// asserted equal at one apiece.

// withOracleLookupHostWeb swaps oracleLookupHost (the web oracle's
// frozen resolver indirection) for the duration of a single test.
// Restoration runs via t.Cleanup so the original binding is
// preserved on every exit path.
func withOracleLookupHostWeb(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := oracleLookupHost
	oracleLookupHost = stub
	t.Cleanup(func() { oracleLookupHost = prev })
}

// webPreservationRow is one ¬C(X) input the web preservation
// property exercises. cell tags which partition cell the row
// belongs to so the test output names which preservation
// requirement is being hit when a row fails post-fix.
type webPreservationRow struct {
	cell    string // partition cell name from task 2
	name    string
	target  string
	wantDNS bool // true if the target must trigger a DNS lookup
	// stubResolution is the value the injected resolver returns for
	// the target hostname. Empty means "no resolver swap needed"
	// (the row uses an IP literal or short-circuits before DNS).
	stubResolution []string
}

// webPreservationRows lists the ¬C(X) inputs for the web-side
// preservation property. The cells map to task 2's partition
// (Local_Or_Listener_Host literals, hostnames resolving to a
// private IP, hostnames resolving to a public IP, IP literals,
// and the empty-host edge case isBlockedTarget already handles).
func webPreservationRows() []webPreservationRow {
	return []webPreservationRow{
		// ── Cell 1 (a): Always-self literals ────────────────────
		{cell: "always-self", name: "loopback ipv4", target: "http://127.0.0.1/admin"},
		{cell: "always-self", name: "loopback ipv4 with port", target: "http://127.0.0.1:9000/x"},
		{cell: "always-self", name: "localhost name", target: "http://localhost/x"},
		{cell: "always-self", name: "ipv6 loopback bracket", target: "http://[::1]:8080/"},
		{cell: "always-self", name: "unspecified 0.0.0.0", target: "http://0.0.0.0/"},

		// ── Cell 1 (b): hostname → private IP ─────────────────────
		{
			cell:           "hostname-resolves-private",
			name:           "hostname resolves to 10.0.0.5",
			target:         "https://internal.example/",
			wantDNS:        true,
			stubResolution: []string{"10.0.0.5"},
		},
		{
			cell:           "hostname-resolves-private",
			name:           "hostname resolves to 169.254.169.254",
			target:         "https://metadata.example/",
			wantDNS:        true,
			stubResolution: []string{"169.254.169.254"},
		},
		{
			cell:           "hostname-resolves-private",
			name:           "hostname resolves to ::1",
			target:         "https://lb6.example/",
			wantDNS:        true,
			stubResolution: []string{"::1"},
		},

		// ── Cell 3: In-scope (public hostname / public IP) ────────
		// Both implementations allow.
		{
			cell:           "public-host",
			name:           "hostname resolves to public IP",
			target:         "https://example.com/",
			wantDNS:        true,
			stubResolution: []string{"93.184.216.34"},
		},
		{
			cell:    "public-host",
			name:    "public IP literal",
			target:  "http://203.0.113.10/",
			wantDNS: false,
		},

		// ── DNS edge: failing lookup falls back to allow ──────────
		{
			cell:           "dns-failure",
			name:           "lookup error",
			target:         "https://nope.example/",
			wantDNS:        true,
			stubResolution: nil, // signals stub should error
		},
	}
}

// TestPreservation_WebGuardMatchesOracle pins Property 2 on the web
// side. Asserts oracleIsBlockedTarget(target) ==
// (*Server).isBlockedTarget(target) for every preservation row.
//
// On unfixed code the oracle is byte-identical to production so the
// equality is tautological. After task 3.2 reduces production to a
// one-line scopeguard.IsLocalOrListener delegation, this property
// catches any drift introduced by the refactor (Requirement 3.8).
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.8.
func TestPreservation_WebGuardMatchesOracle(t *testing.T) {
	for _, row := range webPreservationRows() {
		row := row
		t.Run(row.cell+"/"+row.name, func(t *testing.T) {
			s := newTestServer(t, nil)

			// Stub both the oracle's resolver and the production
			// resolver with the same response so the two
			// implementations see identical inputs.
			stub := func(host string) ([]string, error) {
				if row.stubResolution == nil && row.wantDNS {
					return nil, errors.New("simulated NXDOMAIN")
				}
				return row.stubResolution, nil
			}
			withOracleLookupHostWeb(t, stub)
			withStubLookupHost(t, stub)

			oracleVerdict := oracleIsBlockedTarget(s, row.target)
			prodVerdict := s.isBlockedTarget(row.target)

			if oracleVerdict != prodVerdict {
				t.Fatalf("verdict mismatch for %q: oracle=%v production=%v",
					row.target, oracleVerdict, prodVerdict)
			}
		})
	}
}

// TestPreservation_WebGuardSingleLookupCount pins the DNS lookup
// count sub-property: every host-shaped argument that requires DNS
// triggers exactly one lookup per call against the production
// resolver. The oracle preserves the same property — its frozen body
// keeps the single-lookup semantics identical to production today
// and across the spec.
//
// Validates: Requirements 3.3, 3.8 (and design.md → "DNS Lookup
// Semantics").
func TestPreservation_WebGuardSingleLookupCount(t *testing.T) {
	for _, row := range webPreservationRows() {
		row := row
		if !row.wantDNS {
			continue
		}
		t.Run(row.cell+"/"+row.name, func(t *testing.T) {
			s := newTestServer(t, nil)

			oracleR := newPreservationCounterResolverWeb(func(host string) ([]string, error) {
				if row.stubResolution == nil {
					return nil, errors.New("simulated NXDOMAIN")
				}
				return row.stubResolution, nil
			})
			prodR := newPreservationCounterResolverWeb(func(host string) ([]string, error) {
				if row.stubResolution == nil {
					return nil, errors.New("simulated NXDOMAIN")
				}
				return row.stubResolution, nil
			})
			withOracleLookupHostWeb(t, oracleR.lookup)
			withStubLookupHost(t, prodR.lookup)

			_ = oracleIsBlockedTarget(s, row.target)
			_ = s.isBlockedTarget(row.target)

			if oracleR.calls != 1 {
				t.Errorf("oracle DNS calls = %d, want exactly 1 per host-shaped arg", oracleR.calls)
			}
			if prodR.calls != 1 {
				t.Errorf("production DNS calls = %d, want exactly 1 per host-shaped arg", prodR.calls)
			}
		})
	}
}

// preservationCounterResolverWeb wraps a stub resolver with a
// per-host call counter so the DNS-lookup-count sub-property can
// assert exactly one resolution per host-shaped argument. A
// dedicated type lives in the web package to avoid pulling in the
// agent package's identically-named helper across the package
// boundary.
type preservationCounterResolverWeb struct {
	calls   int
	perHost map[string]int
	stub    func(string) ([]string, error)
}

func newPreservationCounterResolverWeb(stub func(string) ([]string, error)) *preservationCounterResolverWeb {
	return &preservationCounterResolverWeb{
		perHost: make(map[string]int),
		stub:    stub,
	}
}

func (r *preservationCounterResolverWeb) lookup(host string) ([]string, error) {
	r.calls++
	r.perHost[host]++
	return r.stub(host)
}

// ───────────────────────────────────────────────────────────────────
// Integration cross-check (spec: scope-guard-local-only, task 3.9).
//
// Test 5 — Web-fetcher cross-check
// ───────────────────────────────────────────────────────────────────

// TestIntegration_WebFetcherCrossCheckMatchesAgentGuardOracle pins
// Requirement 3.8 end-to-end: for the same set of targets the agent
// guard saw (one Local_Or_Listener_Host, one Public_OOS_Host, one
// in-scope, one self-listener), the web fetcher's
// (*Server).isBlockedTarget verdict matches the captured oracle's
// verdict on byte-identical inputs. The shared classifier
// (scopeguard.IsLocalOrListener) is the structural reason the two
// can never drift; this test is the runtime cross-check.
//
// "End-to-end web-fetcher run" here means: invoke
// (*Server).isBlockedTarget on each target the way the production
// fetcher does (server.go:4020 in runMultiScan filters with the same
// call), and assert the verdict matches oracleIsBlockedTarget on the
// same input. The oracle is byte-frozen against the pre-fix
// production isBlockedTarget body (internal/web/scope_oracle_test.go),
// so this test catches any drift introduced by the
// scopeguard.IsLocalOrListener delegation in 3.2.
//
// Validates: Requirement 3.8.
func TestIntegration_WebFetcherCrossCheckMatchesAgentGuardOracle(t *testing.T) {
	const listenerPort = 9000

	// Server is constructed via NewServer with port = listenerPort
	// so the self-listener row exercises the bind:port pairing rule
	// (BindAddr defaults to "127.0.0.1" via the per-test config).
	s := newTestServer(t, &config.Config{
		BindAddr:          "127.0.0.1",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})
	s.port = listenerPort

	// Inject the same deterministic resolution into both indirections
	// so the oracle and the production guard see identical DNS state.
	// `pentest-ground.com` resolves to a public IP, `oos.example` to
	// another public IP — both must allow under either implementation.
	stub := func(host string) ([]string, error) {
		switch host {
		case "pentest-ground.com":
			return []string{"203.0.113.42"}, nil
		case "oos.example":
			return []string{"198.51.100.7"}, nil
		}
		return nil, errors.New("unexpected host: " + host)
	}
	withStubLookupHost(t, stub)
	withOracleLookupHostWeb(t, stub)

	cases := []struct {
		name        string
		category    string // task 3.9 partition cell label
		target      string
		wantBlocked bool
	}{
		{
			name:        "Local_Or_Listener_Host: loopback literal",
			category:    "Local_Or_Listener_Host",
			target:      "http://127.0.0.1/admin",
			wantBlocked: true,
		},
		{
			name:        "Public_OOS_Host: oos.example resolves to public IP",
			category:    "Public_OOS_Host",
			target:      "https://oos.example/dump",
			wantBlocked: false,
		},
		{
			name:        "in-scope: pentest-ground.com resolves to public IP",
			category:    "in-scope",
			target:      "https://pentest-ground.com/",
			wantBlocked: false,
		},
		{
			name:        "self-listener: 127.0.0.1:listenerPort",
			category:    "self-listener",
			target:      "http://127.0.0.1:9000/dashboard",
			wantBlocked: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.category+"/"+tc.name, func(t *testing.T) {
			oracleVerdict := oracleIsBlockedTarget(s, tc.target)
			prodVerdict := s.isBlockedTarget(tc.target)

			if oracleVerdict != prodVerdict {
				t.Fatalf("Requirement 3.8: web-guard drift detected for %q\n  oracle    = %v\n  production = %v",
					tc.target, oracleVerdict, prodVerdict)
			}
			if prodVerdict != tc.wantBlocked {
				t.Fatalf("expected blocked=%v for %q (category=%s), got %v",
					tc.wantBlocked, tc.target, tc.category, prodVerdict)
			}
		})
	}
}

// TestScannerIdle covers the restart-when-idle gate: a restart may only fire
// when no scan instance is active and the server is not mid-scan.
func TestScannerIdle(t *testing.T) {
	s := newTestServer(t, nil)

	// Fresh server, no instances → idle.
	if !s.scannerIdle() {
		t.Fatalf("fresh server should be idle")
	}

	// Active instance statuses block a restart.
	for _, st := range []string{"running", "pending", "paused", "queued", "starting"} {
		s.instancesMu.Lock()
		s.instances = map[string]*ScanInstance{"i": {ID: "i", Status: st}}
		s.instancesMu.Unlock()
		if s.scannerIdle() {
			t.Fatalf("status %q should NOT be idle", st)
		}
	}

	// Terminal statuses are historical and do not block a restart.
	for _, st := range []string{"finished", "stopped", "failed"} {
		s.instancesMu.Lock()
		s.instances = map[string]*ScanInstance{"i": {ID: "i", Status: st}}
		s.instancesMu.Unlock()
		if !s.scannerIdle() {
			t.Fatalf("status %q should be idle", st)
		}
	}

	// The global running flag also blocks a restart.
	s.instancesMu.Lock()
	s.instances = map[string]*ScanInstance{}
	s.instancesMu.Unlock()
	s.running.Store(true)
	if s.scannerIdle() {
		t.Fatalf("server with running=true should NOT be idle")
	}
	s.running.Store(false)
	if !s.scannerIdle() {
		t.Fatalf("server should be idle after running cleared")
	}
}

// ── Telegram notification tests (issue #157) ──────────────────────────────────

// TestTelegramConfigured_TrueWhenTokenAndChatSet verifies the
// telegramConfigured helper returns true only when BOTH a bot token
// and a chat ID are present. An unconfigured server must report false
// so the trigger sites short-circuit before any outbound request.
func TestTelegramConfigured_TrueWhenTokenAndChatSet(t *testing.T) {
	s := newTestServer(t, nil)
	if s.telegramConfigured() {
		t.Fatal("fresh server with no token/chat should not be configured")
	}

	s.telegramBotToken = "123456789:ABC-DEF"
	if s.telegramConfigured() {
		t.Fatal("token set but no chat ID should not be configured")
	}

	s.telegramBotToken = ""
	s.telegramChatID = "-1001234567890"
	if s.telegramConfigured() {
		t.Fatal("chat ID set but no token should not be configured")
	}

	s.telegramBotToken = "123456789:ABC-DEF"
	if !s.telegramConfigured() {
		t.Fatal("token + chat ID set should be configured")
	}
}

// TestHandleGetScan_MarksTelegramConfigured mirrors the Discord test:
// when global Telegram is configured, GET /api/scans/:id surfaces
// telegram_configured:true and NEVER leaks the bot token in the
// response body (token is not stored on the record — only the boolean).
func TestHandleGetScan_MarksTelegramConfigured(t *testing.T) {
	s := newTestServer(t, &config.Config{
		TelegramBotToken:  "123456789:ABC-TOPSECRET",
		TelegramChatID:    "-1001234567890",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})
	writeScanRecord(t, s.dataDir, "target-tg/2026-05-01/scan-tg", ScanRecord{
		ID:        "scan-tg",
		Target:    "https://tg.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scan-tg", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"telegram_configured":true`) {
		t.Fatalf("global telegram was not marked configured: %s", rr.Body.String())
	}
	// The bot token must never appear in any API response.
	if strings.Contains(rr.Body.String(), "ABC-TOPSECRET") {
		t.Fatalf("telegram bot token leaked in response: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "123456789:ABC-TOPSECRET") {
		t.Fatalf("telegram bot token leaked in response: %s", rr.Body.String())
	}
}

// TestEnvironmentSettings_AppliesTelegramAndRedactsToken mirrors the
// Discord env-settings test: POSTing the three Telegram vars updates
// both cfg.* and the server runtime fields, persists to ~/.xalgorix.env,
// and the GET response masks the bot token (Sensitive: true) while the
// chat ID (non-secret) round-trips in cleartext.
func TestEnvironmentSettings_AppliesTelegramAndRedactsToken(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	body := strings.NewReader(`{"values":{"XALGORIX_TELEGRAM_BOT_TOKEN":"987654321:ZZ-TOPSECRET-99","XALGORIX_TELEGRAM_CHAT_ID":"-1001234567890","XALGORIX_TELEGRAM_MIN_SEVERITY":"critical"}}`)
	rr := httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.TelegramBotToken != "987654321:ZZ-TOPSECRET-99" || s.telegramBotToken != "987654321:ZZ-TOPSECRET-99" {
		t.Fatalf("telegram bot token not applied: cfg=%q runtime=%q", s.cfg.TelegramBotToken, s.telegramBotToken)
	}
	if s.cfg.TelegramChatID != "-1001234567890" || s.telegramChatID != "-1001234567890" {
		t.Fatalf("telegram chat id not applied: cfg=%q runtime=%q", s.cfg.TelegramChatID, s.telegramChatID)
	}
	if s.cfg.TelegramMinSeverity != "critical" || s.telegramMinSeverity != "critical" {
		t.Fatalf("telegram min severity not applied: cfg=%q runtime=%q", s.cfg.TelegramMinSeverity, s.telegramMinSeverity)
	}

	// GET must redact the secret token (Sensitive flag → maskSecretValue).
	// The masked form keeps a suffix (e.g. ****:ABC-DEF) so we assert the
	// FULL cleartext token is absent — partial suffix masking is expected,
	// but the full bot secret must never round-trip.
	rr = httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment GET code = %d body=%s", rr.Code, rr.Body.String())
	}
	gotBody := rr.Body.String()
	if strings.Contains(gotBody, "987654321:ZZ-TOPSECRET-99") {
		t.Fatalf("full telegram bot token NOT redacted in GET response: %s", gotBody)
	}
	if !strings.Contains(gotBody, "XALGORIX_TELEGRAM_BOT_TOKEN") {
		t.Fatalf("telegram bot token setting missing from GET response: %s", gotBody)
	}

	// The env file on disk must contain the cleartext values so the next
	// process restart picks them up (matching Discord behavior).
	data, err := os.ReadFile(filepath.Join(home, ".xalgorix.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_TELEGRAM_BOT_TOKEN=987654321:ZZ-TOPSECRET-99",
		"XALGORIX_TELEGRAM_CHAT_ID=-1001234567890",
		"XALGORIX_TELEGRAM_MIN_SEVERITY=critical",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

// telegramStubServer is a minimal Telegram Bot API stub: it records
// the inbound request path + body and responds with the Telegram
// envelope {"ok": true}. Used by the sendTelegram* early-return and
// HTTP-hit tests below.
type telegramStubServer struct {
	mu       sync.Mutex
	hits     int
	lastPath string
	lastBody []byte
	srv      *httptest.Server
}

func newTelegramStubServer(t *testing.T) *telegramStubServer {
	t.Helper()
	stub := &telegramStubServer{}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.hits++
		stub.lastPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		stub.lastBody = body
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(stub.srv.Close)
	return stub
}

// TestSendTelegram_EarlyReturnWhenUnconfigured verifies that with no
// bot token / chat ID set, sendTelegram makes ZERO outbound requests
// (the stub records no hits), matching the Discord early-return contract.
func TestSendTelegram_EarlyReturnWhenUnconfigured(t *testing.T) {
	stub := newTelegramStubServer(t)
	s := newTestServer(t, nil)
	// Deliberately leave token/chat empty.

	s.sendTelegram(0x3b82f6, "✅ Scan Finished", "no telegram configured")
	// Give the fire-and-forget goroutine a beat to (not) run.
	time.Sleep(50 * time.Millisecond)

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.hits != 0 {
		t.Fatalf("expected 0 requests when unconfigured, got %d", stub.hits)
	}
}

// TestSendTelegram_SendsMessageWhenConfigured verifies that a
// configured server posts a sendMessage request with the chat_id, text,
// HTML parse_mode, and disable_web_page_preview fields to the Telegram
// endpoint. It uses a stub server pointed at via an injectable base URL
// (telegramAPIBase is the fixed host, so the test temporarily swaps the
// package-level const via a test-only override helper).
func TestSendTelegram_SendsMessageWhenConfigured(t *testing.T) {
	stub := newTelegramStubServer(t)
	s := newTestServer(t, nil)
	s.telegramBotToken = "123456789:ABC-DEF"
	s.telegramChatID = "-1001234567890"

	// Override the package-level telegramAPIBase to point at the stub.
	prev := swapTelegramAPIBaseForTest(stub.srv.URL)
	defer swapTelegramAPIBaseForTest(prev)

	s.sendTelegram(0x3b82f6, "🚀 Scan Started", "target https://example.com")
	// Fire-and-forget goroutine; wait for the hit.
	deadline := time.Now().Add(2 * time.Second)
	for {
		stub.mu.Lock()
		done := stub.hits >= 1
		stub.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.hits != 1 {
		t.Fatalf("expected 1 sendMessage request, got %d", stub.hits)
	}
	if !strings.Contains(stub.lastPath, "/sendMessage") {
		t.Fatalf("expected /sendMessage in path, got %q", stub.lastPath)
	}
	if !strings.Contains(stub.lastPath, "123456789:ABC-DEF") {
		t.Fatalf("expected bot token in path, got %q", stub.lastPath)
	}
	body := string(stub.lastBody)
	for _, want := range []string{
		"chat_id=-1001234567890",
		"parse_mode=HTML",
		"disable_web_page_preview=true",
		"Scan+Started",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sendMessage body missing %q:\n%s", want, body)
		}
	}
}

// TestSendTelegramWithFile_SendsDocumentWhenConfigured verifies that
// with a file path set, sendTelegramWithFile posts a multipart
// sendDocument request including the chat_id, caption, and document
// (the PDF bytes). Falls back to a plain sendMessage if the file is
// missing.
func TestSendTelegramWithFile_SendsDocumentWhenConfigured(t *testing.T) {
	stub := newTelegramStubServer(t)
	s := newTestServer(t, nil)
	s.telegramBotToken = "123456789:ABC-DEF"
	s.telegramChatID = "-1001234567890"

	prev := swapTelegramAPIBaseForTest(stub.srv.URL)
	defer swapTelegramAPIBaseForTest(prev)

	// Write a fake "report" file.
	pdfPath := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(pdfPath, []byte("%PDF-1.4 fake report bytes"), 0o600); err != nil {
		t.Fatalf("write fake report: %v", err)
	}

	s.sendTelegramWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", "target https://example.com", pdfPath)
	deadline := time.Now().Add(2 * time.Second)
	for {
		stub.mu.Lock()
		done := stub.hits >= 1
		stub.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.hits != 1 {
		t.Fatalf("expected 1 sendDocument request, got %d", stub.hits)
	}
	if !strings.Contains(stub.lastPath, "/sendDocument") {
		t.Fatalf("expected /sendDocument in path, got %q", stub.lastPath)
	}
	body := string(stub.lastBody)
	for _, want := range []string{
		"name=\"chat_id\"",
		"name=\"caption\"",
		"name=\"document\"",
		"filename=\"report.pdf\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sendDocument body missing %q:\n%s", want, body)
		}
	}
}

// TestSendTelegramWithFile_FallsBackWhenFileMissing verifies that when
// the report file cannot be read, sendTelegramWithFile degrades to a
// plain sendMessage noting the failure rather than crashing the scan.
func TestSendTelegramWithFile_FallsBackWhenFileMissing(t *testing.T) {
	stub := newTelegramStubServer(t)
	s := newTestServer(t, nil)
	s.telegramBotToken = "123456789:ABC-DEF"
	s.telegramChatID = "-1001234567890"

	prev := swapTelegramAPIBaseForTest(stub.srv.URL)
	defer swapTelegramAPIBaseForTest(prev)

	s.sendTelegramWithFile(0x3b82f6, "✅ Scan Finished", "target https://example.com", "/nonexistent/report.pdf")
	deadline := time.Now().Add(2 * time.Second)
	for {
		stub.mu.Lock()
		done := stub.hits >= 1
		stub.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.hits != 1 {
		t.Fatalf("expected 1 fallback sendMessage request, got %d", stub.hits)
	}
	if !strings.Contains(stub.lastPath, "/sendMessage") {
		t.Fatalf("expected fallback /sendMessage path, got %q", stub.lastPath)
	}
	if !strings.Contains(string(stub.lastBody), "report+delivery+failed") {
		t.Fatalf("expected fallback message noting delivery failure: %s", string(stub.lastBody))
	}
}

// TestSeverityMeetsThreshold_TelegramReuseIsIdenticalToDiscord verifies
// the shared severity gate behaves identically for Telegram and Discord
// (the helper is reused, not duplicated). Table-driven over the same
// severity scale the issue specifies.
func TestSeverityMeetsThreshold_TelegramReuseIsIdenticalToDiscord(t *testing.T) {
	cases := []struct {
		name         string
		severity     string
		minSeverity  string
		wantDiscord  bool
		wantTelegram bool
	}{
		{"empty threshold sends all", "info", "", true, true},
		{"info below low", "info", "low", false, false},
		{"low meets low", "low", "low", true, true},
		{"medium below high", "medium", "high", false, false},
		{"high meets high", "high", "high", true, true},
		{"critical above medium", "critical", "medium", true, true},
		{"unknown severity sends", "weird", "high", true, true},
		{"case-insensitive", "HIGH", "Medium", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDiscord := severityMeetsThreshold(tc.severity, tc.minSeverity)
			// Telegram reuses the SAME helper with its own threshold string;
			// simulate the gate the agent applies.
			gotTelegram := severityMeetsThreshold(tc.severity, tc.minSeverity)
			if gotDiscord != tc.wantDiscord || gotTelegram != tc.wantTelegram {
				t.Fatalf("severity=%q min=%q: discord=%v telegram=%v, want discord=%v telegram=%v",
					tc.severity, tc.minSeverity, gotDiscord, gotTelegram, tc.wantDiscord, tc.wantTelegram)
			}
			if gotDiscord != gotTelegram {
				t.Fatalf("discord and telegram gates diverged for severity=%q min=%q", tc.severity, tc.minSeverity)
			}
		})
	}
}

// ── Report accuracy vs severity filter (customer feedback) ─────────────────────

// TestReportPersistsBelowFilterVulns is the regression test for the
// customer-reported bug: "the report shows no findings, but when I
// checked the log there were findings, even critical findings."
//
// Root cause: the severity-filter gate at the report_vulnerability
// event handler used to wrap BOTH persistence and broadcast in a single
// `if allowed` block, so a vuln below the configured severity filter was
// dropped from sess.record.Vulns entirely — never persisted to scan.json,
// never included in the PDF report. The fix separates the two concerns:
// ALWAYS persist to the record (the report's source of truth), gate only
// the live broadcast/notify. This test asserts the persistence side by
// simulating the merge that the cleanup path performs.
func TestReportPersistsBelowFilterVulns(t *testing.T) {
	// Simulate a scan where the operator set severity_filter=["critical"]
	// (i.e. only critical should be surfaced live), but the agent found
	// a medium and a critical. Both must land in the record so the report
	// reflects reality — the medium is "filtered" only from live broadcast,
	// not from the persisted scan.json / PDF.
	rec := &ScanRecord{
		Vulns: []VulnSummary{},
	}

	reported := []reporting.Vulnerability{
		{ID: "XALG-LOW", Title: "Verbose error message", Severity: "medium", Target: "https://a.test", Endpoint: "/api/x", Method: "GET"},
		{ID: "XALG-CRIT", Title: "Auth bypass", Severity: "critical", Target: "https://a.test", Endpoint: "/api/auth", Method: "POST"},
	}

	// mergeReportedVulnerabilitiesIntoRecord is the persistence path used
	// by the cleanup handler (server.go ~L3451) and MUST be unconditional —
	// it does not consult any severity filter.
	mergeReportedVulnerabilitiesIntoRecord(rec, reported)

	if len(rec.Vulns) != 2 {
		t.Fatalf("record should contain BOTH vulns regardless of severity filter, got %d: %#v", len(rec.Vulns), rec.Vulns)
	}

	// The below-filter vuln must be present (this is the regression).
	titles := map[string]bool{}
	for _, v := range rec.Vulns {
		titles[v.Title] = true
	}
	if !titles["Verbose error message"] {
		t.Fatalf("below-filter (medium) vuln was NOT persisted to record — this is the report-accuracy bug: %#v", rec.Vulns)
	}
	if !titles["Auth bypass"] {
		t.Fatalf("critical vuln missing from record: %#v", rec.Vulns)
	}
}

// TestAppendVulnSummaryUniqueIsFilterAgnostic pins the helper's contract:
// it dedups by identity only, never by severity. A below-filter vuln and
// an allowed vuln with the same identity dedup; distinct identities both
// persist. This guarantees the report slice the PDF is built from cannot
// lose vulns to the severity filter through this helper.
func TestAppendVulnSummaryUniqueIsFilterAgnostic(t *testing.T) {
	vulns := []VulnSummary{}
	// medium (would be filtered by a ["critical"] display filter)
	added := appendVulnSummaryUnique(&vulns, VulnSummary{ID: "1", Title: "Medium thing", Severity: "medium", Target: "t", Endpoint: "/m", Method: "GET"})
	if !added {
		t.Fatal("first append must report added=true")
	}
	// critical (allowed by the same display filter)
	added = appendVulnSummaryUnique(&vulns, VulnSummary{ID: "2", Title: "Critical thing", Severity: "critical", Target: "t", Endpoint: "/c", Method: "POST"})
	if !added {
		t.Fatal("second distinct append must report added=true")
	}
	// duplicate of the medium — must NOT be re-added (identity dedup, not severity)
	added = appendVulnSummaryUnique(&vulns, VulnSummary{ID: "1", Title: "Medium thing", Severity: "medium", Target: "t", Endpoint: "/m", Method: "GET"})
	if added {
		t.Fatal("duplicate identity append must report added=false")
	}
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns (medium + critical), got %d: %#v", len(vulns), vulns)
	}
}

// TestRestartForceRequested covers parsing of the force flag from either the
// query string or a JSON body.
func TestRestartForceRequested(t *testing.T) {
	tests := []struct {
		name string
		url  string
		body string
		want bool
	}{
		{name: "no force", url: "/api/restart", want: false},
		{name: "query true", url: "/api/restart?force=true", want: true},
		{name: "query 1", url: "/api/restart?force=1", want: true},
		{name: "query yes", url: "/api/restart?force=yes", want: true},
		{name: "query false", url: "/api/restart?force=false", want: false},
		{name: "body true", url: "/api/restart", body: `{"force":true}`, want: true},
		{name: "body false", url: "/api/restart", body: `{"force":false}`, want: false},
		{name: "empty body", url: "/api/restart", body: "", want: false},
		{name: "garbage body", url: "/api/restart", body: "not json", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *http.Request
			if tt.body != "" {
				r = httptest.NewRequest(http.MethodPost, tt.url, strings.NewReader(tt.body))
			} else {
				r = httptest.NewRequest(http.MethodPost, tt.url, nil)
			}
			if got := restartForceRequested(r); got != tt.want {
				t.Fatalf("restartForceRequested = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandleRestart_ForceRestartsImmediately verifies that ?force=true triggers
// the immediate-restart path (recorded via the injectable seam) rather than the
// wait-for-idle scheduler — even when a scan is active.
func TestHandleRestart_ForceRestartsImmediately(t *testing.T) {
	s := newTestServer(t, nil)
	// An active instance would normally block a graceful restart.
	s.instancesMu.Lock()
	s.instances = map[string]*ScanInstance{"inst-busy": {ID: "inst-busy", Status: "running"}}
	s.instancesMu.Unlock()

	done := make(chan struct{})
	s.forceRestartFn = func() { close(done) }

	rr := httptest.NewRecorder()
	s.handleRestart(rr, httptest.NewRequest(http.MethodPost, "/api/restart?force=true", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"forced":true`) {
		t.Fatalf("response missing forced marker: %s", rr.Body.String())
	}
	select {
	case <-done:
		// force restart fired
	case <-time.After(2 * time.Second):
		t.Fatal("force restart was not triggered")
	}
}

// TestHandleRestart_DefaultSchedulesWhenBusy verifies the default (non-force)
// path still only schedules a restart and does not fire immediately while a
// scan is active.
func TestHandleRestart_DefaultSchedulesWhenBusy(t *testing.T) {
	s := newTestServer(t, nil)
	s.instancesMu.Lock()
	s.instances = map[string]*ScanInstance{"inst-busy": {ID: "inst-busy", Status: "running"}}
	s.instancesMu.Unlock()
	s.forceRestartFn = func() { t.Fatal("force restart must not fire on the default path") }

	rr := httptest.NewRecorder()
	s.handleRestart(rr, httptest.NewRequest(http.MethodPost, "/api/restart", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"scheduled"`) {
		t.Fatalf("expected scheduled status, got: %s", rr.Body.String())
	}
	if got := rr.Body.String(); strings.Contains(got, `"idle":true`) {
		t.Fatalf("scanner should report busy (idle=false), got: %s", got)
	}
}

func TestDispatchIDValidationAndReservation(t *testing.T) {
	s := newTestServer(t, nil)
	if validDispatchID("short") || validDispatchID(strings.Repeat("a", 129)) {
		t.Fatal("invalid dispatch id length was accepted")
	}
	if validDispatchID("123456789012345!") || !validDispatchID("550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("dispatch id URL-safe validation mismatch")
	}

	id := "550e8400-e29b-41d4-a716-446655440000"
	if status, ok := s.reserveDispatchID(id); !ok || status != "" {
		t.Fatalf("first reservation = (%q, %v), want reserved", status, ok)
	}
	if status, ok := s.reserveDispatchID(id); ok || status != "pending" {
		t.Fatalf("duplicate reservation = (%q, %v), want pending acknowledgement", status, ok)
	}
	s.releaseDispatchID(id)

	s.instances[id] = &ScanInstance{ID: id, Status: "running"}
	if status, ok := s.reserveDispatchID(id); ok || status != "running" {
		t.Fatalf("live collision = (%q, %v), want running acknowledgement", status, ok)
	}
	delete(s.instances, id)

	writeScanRecord(t, s.dataDir, "example/2026-08-12/persisted", ScanRecord{
		ID: "persisted", InstanceID: id, Target: "https://example.test", Status: "finished",
	})
	if status, ok := s.reserveDispatchID(id); ok || status != "finished" {
		t.Fatalf("persisted collision = (%q, %v), want finished acknowledgement", status, ok)
	}
}

func TestRandomSlugHas128BitsAndNoImmediateCollisions(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 256; i++ {
		id := randomSlug()
		if len(id) != 32 || !validDispatchID(id) {
			t.Fatalf("random slug %q is not a 128-bit URL-safe id", id)
		}
		if seen[id] {
			t.Fatalf("random slug collision: %q", id)
		}
		seen[id] = true
	}
}

func TestBeginWildcardSubScanSerializesWithStop(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID: "wildcard-instance", Status: "running", SubScanTotal: 2,
		SubScans: []SubScanSummary{{Target: "a.example"}, {Target: "b.example"}},
	}
	s.instances[inst.ID] = inst
	if !s.beginWildcardSubScan(inst.ID, 0, "a.example", "child-a") {
		t.Fatal("running child dispatch was rejected")
	}
	if child := inst.SubScans[0]; child.ID != "child-a" || child.StartedAt == "" || child.Status != "running" {
		t.Fatalf("positive dispatch evidence missing: %#v", child)
	}
	inst.mu.Lock()
	inst.Status = "stopped"
	normalizeTerminalWildcardInstanceLocked(inst)
	inst.mu.Unlock()
	if s.beginWildcardSubScan(inst.ID, 1, "b.example", "child-b") {
		t.Fatal("child dispatch started after terminal stop")
	}
	if child := inst.SubScans[1]; child.ID != "" || child.StartedAt != "" {
		t.Fatalf("stopped child gained dispatch evidence: %#v", child)
	}
}
