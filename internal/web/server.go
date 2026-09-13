// Package web provides the Xalgorix web UI server.
package web

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// Version is set by main.go at startup — single source of truth.
var Version = "dev"

//go:embed static/*
var staticFiles embed.FS

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	// Cleanup old entries every minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stopCh:
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

// cleanup walks the request map and discards entries whose timestamps have
// all aged out of the active window. Done in two passes (collect → delete)
// to minimize lock contention with Allow() under high churn.
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-rl.window)

	// Pass 1: collect IPs whose buckets are fully expired. RLock would be
	// ideal, but the underlying mutex is sync.Mutex; the read cost is small.
	rl.mu.Lock()
	var toDelete []string
	for ip, times := range rl.requests {
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			toDelete = append(toDelete, ip)
		}
	}
	rl.mu.Unlock()

	if len(toDelete) == 0 {
		return
	}

	// Pass 2: re-check each IP under lock — a request could have arrived
	// between passes and re-validated the bucket.
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, ip := range toDelete {
		times, ok := rl.requests[ip]
		if !ok {
			continue
		}
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			delete(rl.requests, ip)
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Get or create the slice
	times := rl.requests[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for WebSocket, static files, and dashboard
			// polling reads. Auth still wraps this middleware, so protected
			// reads require a valid session before they reach this point.
			if r.URL.Path == "/ws" || isStaticWebAssetPath(r.URL.Path) ||
				isDashboardReadPath(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Use RemoteAddr only — do not trust X-Forwarded-For as it can be
			// spoofed when running without a trusted reverse proxy. Strip the
			// port so each TCP connection from the same client shares a bucket.
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isStaticWebAssetPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/api/") || path == "/ws" {
		return false
	}
	if strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/assets/") ||
		strings.HasPrefix(path, "/chunks/") {
		return true
	}
	switch filepath.Ext(path) {
	case ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func isDashboardReadPath(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/instances",
		"/api/queue/status",
		"/api/findings/summary",
		"/api/legacy-import/status":
		return true
	default:
		return strings.HasPrefix(path, "/api/scans/") ||
			strings.HasPrefix(path, "/api/instances/")
	}
}

func setWebUICacheHeaders(w http.ResponseWriter) {
	// HTML and compatibility asset routes must always revalidate so a binary
	// upgrade discovers the newly content-hashed dashboard bundle immediately.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func validDispatchID(id string) bool {
	if len(id) < 16 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// reserveDispatchID serializes duplicate HTTP submissions before runMultiScan
// registers the instance. Existing/reserved IDs are idempotent acknowledgments,
// never permission to overwrite another live run.
func (s *Server) reserveDispatchID(id string) (string, bool) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if s.dispatchReservations == nil {
		s.dispatchReservations = make(map[string]bool)
	}
	if s.dispatchReservations[id] {
		return "pending", false
	}
	s.instancesMu.RLock()
	inst := s.instances[id]
	s.instancesMu.RUnlock()
	if inst != nil {
		inst.mu.RLock()
		status := inst.Status
		if isTerminalScanStatus(status) && inst.snapshotFinalizing {
			status = "pending"
		}
		inst.mu.RUnlock()
		return status, false
	}
	if rec, err := s.loadExactDispatchSnapshot(id); err == nil {
		return rec.Status, false
	} else if !errors.Is(err, errDispatchSnapshotNotFound) {
		log.Printf("[scan] refusing dispatch id %q because its durable snapshot is unreadable: %v", id, err)
		return "conflict", false
	}
	if status, claimed := s.persistedInstanceIDClaim(id); claimed {
		return status, false
	}
	s.dispatchReservations[id] = true
	return "", true
}

func (s *Server) releaseDispatchID(id string) {
	s.dispatchMu.Lock()
	delete(s.dispatchReservations, id)
	s.dispatchMu.Unlock()
}

func canStartInstanceStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "saved", "stopped", "failed", "finished":
		return true
	default:
		return false
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

// logRecover is a deferred recovery helper used by best-effort cleanup
// blocks. The previous pattern was `defer func() { recover() }()` which
// silently swallowed panics — making cleanup bugs invisible in
// production. logRecover preserves the original behavior (don't crash
// the server during shutdown) while emitting a stack trace so the bug
// can be diagnosed.
//
// Usage: defer logRecover("scanSession.cleanup.scanctx")
func logRecover(label string) {
	if r := recover(); r != nil {
		log.Printf("[recover] %s: %v\n%s", label, r, debug.Stack())
	}
}

// ScanRequest is the JSON body for starting a scan.
type ScanRequest struct {
	Targets        []string `json:"targets"`
	Instruction    string   `json:"instruction"`
	ScanMode       string   `json:"scan_mode"`       // "single" or "wildcard"
	Model          string   `json:"model"`           // e.g. "openai/gpt-5.6"
	APIKey         string   `json:"api_key"`         // provider API key
	APIBase        string   `json:"api_base"`        // provider API base URL
	DiscordWebhook string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter []string `json:"severity_filter"` // e.g. ["critical", "high"]
	Name           string   `json:"name"`            // user-defined scan name
	SaveOnly       bool     `json:"save_only"`       // if true, save scan config without starting
	Phases         []int    `json:"phases"`          // selected methodology phases (empty = all)
	ReconMode      string   `json:"recon_mode"`      // active or passive reconnaissance
	ScanIntensity  string   `json:"scan_intensity"`  // active or passive testing/scanning
	CompanyName    string   `json:"company_name"`    // report branding: company name
	LogoPath       string   `json:"logo_path"`       // report branding: logo file path
	// TargetAuth carries per-scan authenticated-scanning material so the
	// agent can exercise post-login attack surface. Format mirrors
	// XALGORIX_TARGET_AUTH (see httpclient/sessionauth.go): a header/cookie
	// spec applied automatically to http_request. Empty = unauthenticated.
	TargetAuth string `json:"target_auth"`
	// TargetAuthSecondary is a SECOND account's auth (same format as TargetAuth),
	// surfaced to the agent to prove horizontal access-control flaws (IDOR/BOLA).
	// Not auto-applied. Empty = single-account testing.
	TargetAuthSecondary string `json:"target_auth_b"`
	// SourceRepo enables whitebox/source-assisted scanning. It is either a
	// git clone URL or a local path; the agent clones/opens it at scan
	// start and exposes it via the code_search tool. Empty = blackbox.
	SourceRepo string `json:"source_repo"`
	// CodeScan selects a code-first scan (SourceRepo becomes the subject, no
	// live target URL is required):
	//   "review"    — source review / SAST, no running target (Option 1).
	//   "provision" — build & run the source locally, then DAST it (Option 2).
	// Empty = normal target-driven scan (SourceRepo, if set, augments it).
	CodeScan string `json:"code_scan"`
	// ScanContext is a path to operator-supplied context artifact(s) — an
	// OpenAPI/Swagger spec, HAR capture, or Postman collection (file or dir).
	// The engine parses them into a seeded attack surface (real endpoints +
	// params) and harvests any captured auth. Empty = crawl-only discovery.
	ScanContext string `json:"scan_context"`
	// ProviderProfile is the optional "<provider>:<profileId>" key
	// (e.g. "openai:default") that selects an Auth_Profile from
	// Profile_Store for this scan. When set on a request from an
	// Authenticated_Operator, resolveScanCredentials maps it to a
	// (baseURL, auth_method, credentials) tuple at scan start. When
	// empty, the existing legacy / catalog-default resolver path is
	// used. Ad-hoc Model/APIKey/APIBase fields still take precedence
	// per Requirement 11.4.
	// Validates: Requirements 11.1, 11.2, 11.5.
	ProviderProfile string `json:"provider_profile,omitempty"`
	// DispatchID is an optional caller-owned idempotency key for control-plane
	// dispatch. It is validated and reserved before the goroutine starts; the
	// internal InstanceID remains wire-inaccessible for resume safety.
	DispatchID string `json:"dispatch_id,omitempty"`
	// Internal fields — `json:"-"` makes them un-settable from the wire.
	// Critical: a client must not be able to set InstanceID to spoof
	// broadcasts to another scan, or set IsResume to bypass the resume
	// codepath's safety checks.
	InstanceID           string   `json:"-"` // parent instance ID, threaded server-side
	IsResume             bool     `json:"-"` // true when auto-resuming after restart
	ResumeQueueStatePath string   `json:"-"`
	ResumeActiveTarget   string   `json:"-"`
	ResumeScanDir        string   `json:"-"`
	ResumeScanID         string   `json:"-"`
	ResumeSubScanTarget  string   `json:"-"`
	ResumeSubScanDir     string   `json:"-"`
	ResumeSubScanID      string   `json:"-"`
	ResumeSubdomains     []string `json:"-"`
	ResumeSubIndex       int      `json:"-"`
	ResumeDiscoveryDone  bool     `json:"-"`
	ResumeOriginalTarget int      `json:"-"`
	queueOwnership       *queueOwnership

	// Code-scan internals, resolved server-side from CodeScan in handleScan.
	// codeScanMode drives the agent's methodology; allowLoopbackPorts is the
	// per-scan loopback allowlist the scope guard honors for provision scans.
	codeScanMode       agent.CodeScanMode `json:"-"`
	allowLoopbackPorts []int              `json:"-"`
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type           string            `json:"type"`
	Content        string            `json:"content,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolArgs       map[string]string `json:"tool_args,omitempty"`
	Output         string            `json:"output,omitempty"`
	Error          string            `json:"error,omitempty"`
	AgentID        string            `json:"agent_id,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	Timestamp      string            `json:"timestamp,omitempty"`
	Vulns          []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex    int               `json:"target_index,omitempty"`
	TotalTargets   int               `json:"total_targets,omitempty"`
	Target         string            `json:"target,omitempty"`
	TotalTokens    int               `json:"total_tokens,omitempty"`
	SubTargetIndex int               `json:"sub_target_index,omitempty"` // subdomain index within a wildcard target
	SubTargetTotal int               `json:"sub_target_total,omitempty"` // total subdomains for current wildcard target
	ParentTarget   string            `json:"parent_target,omitempty"`    // parent domain for subdomain scans
	CurrentPhase   int               `json:"current_phase,omitempty"`    // inferred active methodology phase
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                 string   `json:"id"`
	SourceScanID       string   `json:"source_scan_id,omitempty"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	Target             string   `json:"target,omitempty"`
	Endpoint           string   `json:"endpoint"`
	CVSS               float64  `json:"cvss"`
	CVSSVector         string   `json:"cvss_vector,omitempty"`
	Description        string   `json:"description,omitempty"`
	Impact             string   `json:"impact,omitempty"`
	Method             string   `json:"method,omitempty"`
	CVE                string   `json:"cve,omitempty"`
	CWE                string   `json:"cwe_id,omitempty"`
	OWASP              string   `json:"owasp,omitempty"`
	TechnicalAnalysis  string   `json:"technical_analysis,omitempty"`
	PoCDescription     string   `json:"poc_description,omitempty"`
	PoCScript          string   `json:"poc_script,omitempty"`
	Remediation        string   `json:"remediation,omitempty"`
	Fix                string   `json:"fix,omitempty"`
	ExploitationProof  string   `json:"exploitation_proof,omitempty"`
	VerificationMethod string   `json:"verification_method,omitempty"`
	Verified           bool     `json:"verified"`
	Tags               []string `json:"tags,omitempty"`
}

// SubScanSummary is a child target scanned as part of a wildcard parent scan.
type SubScanSummary struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Status      string `json:"status"`
	VulnCount   int    `json:"vuln_count"`
	TotalTokens int    `json:"total_tokens"`
}

// ScanRecord is a persisted scan result.
type ScanRecord struct {
	ID                       string    `json:"id"`
	InstanceID               string    `json:"instance_id,omitempty"` // parent queue/instance id returned by /api/scan
	Name                     string    `json:"name,omitempty"`        // user-defined scan name
	Target                   string    `json:"target"`
	ParentTarget             string    `json:"parent_target,omitempty"` // parent domain for subdomain scans (wildcard mode)
	StartedAt                string    `json:"started_at"`
	FinishedAt               string    `json:"finished_at,omitempty"`
	Status                   string    `json:"status"`                               // saved, running, finished, stopped
	StopReason               string    `json:"stop_reason,omitempty"`                // why scan stopped (error, user, watchdog, etc.)
	ScanMode                 string    `json:"scan_mode,omitempty"`                  // single, wildcard, dast
	Instruction              string    `json:"instruction,omitempty"`                // custom scan instructions
	SeverityFilter           []string  `json:"severity_filter,omitempty"`            // severity filter for scan
	DiscordWebhook           string    `json:"discord_webhook,omitempty"`            // discord notification webhook
	DiscordWebhookConfigured bool      `json:"discord_webhook_configured,omitempty"` // true when a per-scan or global webhook is configured
	TelegramConfigured       bool      `json:"telegram_configured,omitempty"`        // true when global Telegram notifications are configured (token never exposed)
	ReconMode                string    `json:"recon_mode,omitempty"`                 // active or passive reconnaissance
	ScanIntensity            string    `json:"scan_intensity,omitempty"`             // active or passive testing/scanning
	Events                   []WSEvent `json:"events"`
	// EventsTotal / EventsTruncated are RESPONSE-ONLY hints for the scan-detail
	// view. GET /api/scans/{id} returns only a tail of the event log (the most
	// recent detailEventTail events) so a scan with a multi-hundred-MB event log
	// doesn't have to be fully parsed, marshaled, and shipped on every open.
	// When Truncated is set, the client lazily pages older events via
	// GET /api/scans/{id}/events?offset=&limit=. Both are omitempty so the
	// persisted scan.json is unaffected (they are zero on the saved record).
	EventsTotal      int              `json:"events_total,omitempty"`
	EventsTruncated  bool             `json:"events_truncated,omitempty"`
	Vulns            []VulnSummary    `json:"vulns"`
	TotalTokens      int              `json:"total_tokens"`
	Iterations       int              `json:"iterations"`
	ToolCalls        int              `json:"tool_calls"`
	CompanyName      string           `json:"company_name,omitempty"` // report branding: company name
	LogoPath         string           `json:"logo_path,omitempty"`    // report branding: logo path
	Phases           []int            `json:"phases,omitempty"`       // selected methodology phases
	CurrentPhase     int              `json:"current_phase,omitempty"`
	SubScans         []SubScanSummary `json:"sub_scans,omitempty"`
	SubScanTotal     int              `json:"sub_scan_total,omitempty"`
	SubScanCompleted int              `json:"sub_scan_completed,omitempty"`
	SubScanRunning   int              `json:"sub_scan_running,omitempty"`
	SubScanRemaining int              `json:"sub_scan_remaining,omitempty"`
	WorkStarted      bool             `json:"work_started,omitempty"` // positive proof that an agent session was admitted
}

// QueueState persists scan queue state for recovery after restart
type QueueState struct {
	InstanceID            string   `json:"instance_id,omitempty"`
	Targets               []string `json:"targets"`
	CurrentIdx            int      `json:"current_idx"`
	Instruction           string   `json:"instruction"`
	ScanMode              string   `json:"scan_mode"`
	StartedAt             string   `json:"started_at"`
	Active                bool     `json:"active"`
	Name                  string   `json:"name,omitempty"`
	SeverityFilter        []string `json:"severity_filter,omitempty"`
	Phases                []int    `json:"phases,omitempty"`
	ReconMode             string   `json:"recon_mode,omitempty"`
	ScanIntensity         string   `json:"scan_intensity,omitempty"`
	CompanyName           string   `json:"company_name,omitempty"`
	LogoPath              string   `json:"logo_path,omitempty"`
	DiscordWebhook        string   `json:"discord_webhook,omitempty"`
	Paused                bool     `json:"paused,omitempty"`
	ActiveTarget          string   `json:"active_target,omitempty"`
	ActiveScanDir         string   `json:"active_scan_dir,omitempty"`
	ActiveScanID          string   `json:"active_scan_id,omitempty"`
	WildcardActiveTarget  string   `json:"wildcard_active_target,omitempty"`
	WildcardActiveScanDir string   `json:"wildcard_active_scan_dir,omitempty"`
	WildcardActiveScanID  string   `json:"wildcard_active_scan_id,omitempty"`
	WildcardDiscoveryDone bool     `json:"wildcard_discovery_done,omitempty"`
	WildcardSubdomains    []string `json:"wildcard_subdomains,omitempty"`
	WildcardSubIndex      int      `json:"wildcard_sub_index,omitempty"`
}

// ScanInstance represents a running or completed scan instance.
type ScanInstance struct {
	ID             string   `json:"id"`
	Name           string   `json:"name,omitempty"` // user-defined scan name
	Targets        string   `json:"targets"`
	ParentTarget   string   `json:"parent_target,omitempty"` // parent domain for subdomain scans
	Status         string   `json:"status"`                  // saved, running, paused, finished, stopped
	StartedAt      string   `json:"started_at"`
	FinishedAt     string   `json:"finished_at,omitempty"`
	StopReason     string   `json:"stop_reason,omitempty"` // why stopped (user, error, watchdog)
	Iterations     int      `json:"iterations"`
	ToolCalls      int      `json:"tool_calls"`
	VulnCount      int      `json:"vuln_count"`
	TotalTokens    int      `json:"total_tokens"`
	ScanMode       string   `json:"scan_mode"`
	Instruction    string   `json:"instruction,omitempty"`     // custom scan instructions for restart
	SeverityFilter []string `json:"severity_filter,omitempty"` // severity filter for restart
	Phases         []int    `json:"phases,omitempty"`          // selected methodology phases (empty = all)
	ReconMode      string   `json:"recon_mode,omitempty"`      // active or passive reconnaissance
	ScanIntensity  string   `json:"scan_intensity,omitempty"`  // active or passive testing/scanning
	CompanyName    string   `json:"company_name,omitempty"`    // report branding: company name
	LogoPath       string   `json:"logo_path,omitempty"`       // report branding: logo path
	DiscordWebhook string   `json:"-"`                         // discord webhook (not exposed to API)
	// Per-scan auth/whitebox/context, restored when a saved scan is started.
	// Kept in-memory only (json:"-", like DiscordWebhook) so third-party
	// credentials and token-bearing source URLs are never written to the
	// on-disk instance record or exposed via the API. Survives save→start
	// within the running process; a process restart drops them (the operator
	// re-enters auth), which is the safe default for secrets.
	TargetAuth          string        `json:"-"`
	TargetAuthSecondary string        `json:"-"`
	SourceRepo          string        `json:"-"`
	ScanContext         string        `json:"-"`
	Vulns               []VulnSummary `json:"vulns,omitempty"`
	CurrentPhase        int           `json:"current_phase,omitempty"`
	// Wildcard progress is mirrored from the persisted parent record so the
	// exact instance endpoint can serve a complete snapshot without a data-dir
	// walk. SubScans intentionally omits `omitempty`: an empty array is the
	// capability marker SaaS uses to distinguish upgraded scanners from older
	// versions that cannot safely finalize wildcard scans from this endpoint.
	SubScans           []SubScanSummary `json:"sub_scans"`
	SubScanTotal       int              `json:"sub_scan_total"`
	SubScanCompleted   int              `json:"sub_scan_completed"`
	SubScanRunning     int              `json:"sub_scan_running"`
	SubScanRemaining   int              `json:"sub_scan_remaining"`
	WorkStarted        bool             `json:"work_started"` // true once any agent session is admitted
	agent              *agent.Agent
	cancel             context.CancelFunc
	scanDir            string
	sctx               *scanctx.ScanContext // per-instance session state (vulns, notes, terminal, browser)
	events             []WSEvent            // buffered events for replay
	chatCfg            *config.Config       // provider settings for post-scan chat (not exposed)
	chatMessages       []llm.Message        // lightweight post-scan chat history (not exposed)
	mu                 sync.RWMutex
	lastSessionTokens  int  // tracks token count from current session for delta calculation
	snapshotReady      bool // final queue event and session cleanup are complete; persistence may be retried safely
	snapshotFinalizing bool // terminal status is not externally coherent until the final queue event is durably snapshotted
}

// maxConcurrentInstances removed — replaced by dynamic resource-aware
// admission via resources.CanAdmitScan(). See internal/resources/.

// A newly admitted scan can take a short time to allocate its agent, browser,
// and tool memory. Until then MemAvailable still looks unchanged, so treat its
// RAM budget as reserved rather than allowing every pending waiter to spend the
// same live headroom snapshot. After this window the OS reading is authoritative.
const admissionMemoryReflectionWindow = 30 * time.Second

func admissionMemoryUnreflected(startedAt string, now time.Time) bool {
	started, err := time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return false
	}
	age := now.Sub(started)
	return age >= 0 && age < admissionMemoryReflectionWindow
}

type queueProgress struct {
	ActiveTarget          string
	ActiveScanDir         string
	ActiveScanID          string
	WildcardActiveTarget  string
	WildcardActiveScanDir string
	WildcardActiveScanID  string
	WildcardDiscoveryDone bool
	WildcardSubdomains    []string
	WildcardSubIndex      int
}

// dashboardRoutes lists every URL pattern the dashboard mux
// registers in NewServer.Start. It exists primarily as a test
// surface so that the test in internal/web asserting
// `/oauth/callback` is NOT mounted on the dashboard mux (R13.3)
// has a single source of truth to consult — without it, that
// invariant would have to be re-derived from the call sites in
// Start every time the route surface changes.
//
// The slice is updated in lockstep with the mux.HandleFunc /
// mux.Handle calls inside Server.Start; if a route is added or
// removed there, the slice should be updated to match.
//
// Validates: Requirement 13.3 ("never registers `/oauth/callback`
// on the dashboard mux"), Requirement 15.2 (existing routes
// preserved unchanged).
var dashboardRoutes = []string{
	// Static + WebSocket roots (registered as catch-all and "/ws").
	"/",
	"/ws",

	// Existing scan / status / report / settings surface.
	"/api/scan",
	"/api/stop",
	"/api/restart",
	"/api/status",
	"/api/findings/summary",
	"/api/findings",
	"/api/legacy-import/status",
	"/api/scans",
	"/api/scans/",
	"/api/data-dirs/",
	"/api/schedules",
	"/api/schedules/",
	"/api/upload-targets",
	"/api/upload-instructions",
	"/api/upload-logo",
	"/api/upload-context",
	"/api/upload-source",
	"/uploads/logos/",
	"/api/report/",
	"/api/settings/rate-limit",
	"/api/settings/agentmail",
	"/api/settings/llm",
	"/api/settings/llm/keys",
	"/api/settings/llm/test-route",
	"/api/settings/environment",
	"/api/queue/status",
	"/api/queue/resume",
	"/api/queue/clear",
	"/api/version",
	"/api/stop-notify",
	"/api/instances",
	"/api/instances/",
	"/api/chat",

	// Dashboard auth (login/logout/status). Distinct from the new
	// /api/auth/profiles namespace below.
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/status",

	// Provider catalog (read-only) + auth profile routes.
	"/api/providers",
	"/api/auth/profiles",
	"/api/auth/profiles/api-key",
	"/api/auth/profiles/oauth/start",
	"/api/auth/profiles/oauth/complete",
	"/api/auth/profiles/",
}

// Server is the web UI server.
type Server struct {
	cfg             *config.Config
	port            int
	clients         map[*wsClient]bool
	mu              sync.RWMutex
	currentAgents   map[string]*agent.Agent // scanID → agent (replaces singleton currentAgent)
	cancelScan      context.CancelFunc      // cancels the current scan session context
	running         atomic.Bool
	stopReq         atomic.Bool
	restartWhenIdle atomic.Bool  // SIGUSR1 sets this; a watcher restarts once scans drain
	httpServer      *http.Server // set in Start; used to trigger graceful restart from the API
	// forceRestartFn performs an immediate restart for POST /api/restart?force=true.
	// nil in production (the handler re-execs via restartNow); tests set it to a
	// stub so the force path can be exercised without exec'ing the process.
	forceRestartFn         func()
	dataDir                string
	currentScanDir         string
	currentScanID          string
	discordWebhook         string
	discordMinSeverity     string      // minimum severity to send to Discord ("info", "low", "medium", "high", "critical")
	telegramBotToken       string      // XALGORIX_TELEGRAM_BOT_TOKEN (secret, never exposed via API)
	telegramChatID         string      // XALGORIX_TELEGRAM_CHAT_ID (numeric ID or @channelusername)
	telegramMinSeverity    string      // minimum severity to send to Telegram ("info", "low", "medium", "high", "critical")
	notifyScanComplete     atomic.Bool // XALGORIX_NOTIFY_SCAN_COMPLETE - send the "Scan Finished" summary after every scan (default false)
	rateLimiter            *RateLimiter
	settingsMu             sync.Mutex
	instances              map[string]*ScanInstance // concurrent scan instances
	instancesMu            sync.RWMutex
	dispatchMu             sync.Mutex
	dispatchReservations   map[string]bool
	exactStopNotifications map[string]bool
	queueResumeMu          sync.Mutex
	queueResumeLaunching   map[string]bool
	postScanChatFn         func(*config.Config, []llm.Message) (string, error)
	schedulesMu            sync.RWMutex
	schedules              map[string]*ScanSchedule
	shutdownChan           chan struct{}
	// scanListCache memoizes the built GET /api/scans list for a few seconds
	// so paging/filtering/polling don't each re-walk the whole data dir.
	scanListCacheMu sync.Mutex
	scanListCache   []scanListItem
	scanListCacheAt time.Time
	// scanSummaryCache memoizes the per-file parsed (events-free) scan record
	// keyed by file path. Finished scans' scan.json files are immutable, so
	// after the first parse they are reused across walks without re-reading or
	// re-parsing. Entries are validated by (modtime, size) so a running scan
	// whose file changes is re-parsed. See findAllScanSummaries.
	scanSummaryCacheMu sync.Mutex
	scanSummaryCache   map[string]scanSummaryCacheEntry
	// admissionWake is a buffered (len=1) channel used by runMultiScan's
	// admission loop to wait fairly for a freed slot. A scan instance ending
	// signals this channel non-blockingly in its defer cleanup, waking
	// exactly one waiter per terminate. The 2-second ticker in the loop is
	// retained as a safety-net so we still re-check periodically if a wake
	// signal is missed for any reason. (R3.2, R3.6 / Property 5.)
	admissionWake chan struct{}

	// legacyImportCount is the number of scan records imported from the
	// pre-migration directory (~/xalgorix-data/) into the active dataDir
	// on the current server start. It is set once by importLegacyDataDir
	// and surfaced via /api/legacy-import/status so the WebUI can render
	// a one-time banner. Not persisted; resets to 0 each restart.
	// legacyImportDismissed flips to true when the WebUI dismisses the
	// banner; only valid for the current process lifetime.
	// Guarded by legacyImportMu so the short banner-status reads/writes
	// don't contend with the WebSocket-clients lock (s.mu).
	// (See findings-consistency-and-pagination spec, Property 6.)
	legacyImportMu        sync.RWMutex
	legacyImportCount     int
	legacyImportDismissed bool

	// catalog is the read-only LLM provider catalog backing the
	// GET /api/providers handler and the per-scan endpoint
	// resolver. v4.4.22 collapsed the runtime-editable JSON-backed
	// catalog into a compiled-in providers.Builtin() set;
	// providers.NewService() is unconditional and never fails. The
	// field is kept (rather than being read from a singleton) so
	// tests can swap a fixture catalog in without touching package
	// state.
	catalog *providers.Service

	// profiles is the runtime-editable credential profile store
	// backing /api/auth/profiles (Wave E task 5.2). Like catalog,
	// it is initialized in NewServer and may be nil if startup
	// failed. The catalog handlers in this task do not consult
	// profiles directly, but the field is declared here so task 5.2
	// can wire profile handlers without re-touching the Server
	// shape. Validates: Requirement 4.1.
	profiles *auth.Store

	// oauthRegistry is the OAuth driver registry consulted by
	// handleOAuthStart / handleOAuthComplete / handleProfileRefresh
	// (Wave E task 5.2). It is wired in NewServer immediately
	// after profiles via auth.RegisterDefaultDrivers so the four
	// built-in flow handlers (pkce, device_code, setup_token,
	// claude_cli_reuse) are available without further setup. A
	// nil value mirrors the catalog/profiles fields: the OAuth
	// handlers surface 503 so the rest of the dashboard keeps
	// serving traffic. Validates: Requirements 6.x, 7.x, 8.x, 9.x.
	oauthRegistry *auth.Registry

	// llmKeyStore is the multi-provider API key store backing the
	// /api/settings/llm/keys handlers. nil if construction failed at
	// startup, in which case handleProviderKeys returns 503.
	llmKeyStore *llm.KeyStore

	// llmRouter resolves a model name to a provider endpoint using the
	// catalog + llmKeyStore. Backs /api/settings/llm/test-route. nil
	// when llmKeyStore is nil.
	llmRouter *llm.Router
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	// The active Data_Dir is owned by config.resolveDataDir (R6.1, R6.3) and
	// already canonicalized + created with mode 0o700 before we get here.
	// The Web_Server is a downstream consumer; it must NOT re-derive a data
	// root from $HOME or $CWD (Task 3.6 / R6.4 / R6.6) — doing so would
	// silently bypass XALGORIX_DATA_DIR and resurrect the legacy
	// ~/xalgorix-data location.
	dataDir := cfg.DataDir
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)

	srv := &Server{
		cfg:                    cfg,
		port:                   port,
		clients:                make(map[*wsClient]bool),
		currentAgents:          make(map[string]*agent.Agent),
		dataDir:                dataDir,
		discordWebhook:         cfg.DiscordWebhook,
		discordMinSeverity:     strings.ToLower(strings.TrimSpace(cfg.DiscordMinSeverity)),
		telegramBotToken:       cfg.TelegramBotToken,
		telegramChatID:         cfg.TelegramChatID,
		telegramMinSeverity:    strings.ToLower(strings.TrimSpace(cfg.TelegramMinSeverity)),
		rateLimiter:            rl,
		instances:              make(map[string]*ScanInstance),
		dispatchReservations:   make(map[string]bool),
		exactStopNotifications: make(map[string]bool),
		queueResumeLaunching:   make(map[string]bool),
		// postScanChatFn is set BELOW, after srv has been
		// allocated, so the closure can capture *srv and read
		// srv.catalog / srv.profiles at call time. Those fields
		// are populated later in NewServer when the catalog and
		// profile stores load successfully; capturing the
		// pointer keeps the closure valid even when those
		// fields flip from nil to non-nil during construction.
		schedules:    make(map[string]*ScanSchedule),
		shutdownChan: make(chan struct{}),
		// Buffered to length 1 so a non-blocking send from a terminating
		// scan never blocks; the buffered slot guarantees a wake signal
		// is delivered to whichever waiter is currently parked in the
		// admission select.
		admissionWake: make(chan struct{}, 1),
	}
	srv.notifyScanComplete.Store(cfg.NotifyScanComplete)

	// Wire postScanChatFn now that srv exists. The closure reads
	// srv.catalog / srv.profiles at call time so the catalog
	// branch engages once both stores load below — the values
	// captured here are pointers, not snapshots, so a successful
	// catalog load later in NewServer is observable on every
	// subsequent invocation of postScanChatFn.
	//
	// Decision order matches llm.compositeResolver.Resolve
	// exactly (catalog non-empty → catalogResolver; otherwise
	// legacy when XALGORIX_LLM matches Legacy_Provider_Shape;
	// otherwise *ConfigError surfaced to the caller). That is
	// the contract Requirement 11.2 / Requirement 2.x require
	// for /api/scan, and putting the same resolver behind every
	// LLM call site keeps the chat-summary path consistent with
	// the per-scan path. (Wave E task 5.4.)
	srv.postScanChatFn = func(cfg *config.Config, messages []llm.Message) (string, error) {
		opts := []llm.ResolverOption{}
		if srv.catalog != nil && srv.profiles != nil {
			opts = append(opts, llm.WithCatalog(srv.catalog, srv.profiles))
		}
		opts = append(opts, llm.WithLegacy(cfg))
		resolver := llm.NewCompositeResolver(opts...)
		client := llm.NewClient(cfg, llm.WithResolver(resolver))
		client.SetContext(context.Background())
		return client.Chat(messages)
	}

	// Import legacy data dir (pre-migration ~/xalgorix-data/) into the
	// active dataDir on first start. Idempotent (sentinel-gated) and
	// non-fatal — failures are logged and the server still starts. Must
	// run BEFORE rebuildInstancesFromDisk so imported scans appear in
	// the dashboard immediately.
	imported, ierr := srv.importLegacyDataDir()
	if ierr != nil {
		log.Printf("[legacy-import] error: %v (continuing)", ierr)
	}
	srv.legacyImportCount = imported
	srv.legacyImportDismissed = false

	// Provider catalog + auth profile store.
	//
	// As of v4.4.22 the catalog is compiled-in (providers.Builtin)
	// rather than file-backed. providers.NewService is constructed
	// unconditionally and never fails. The auth profile store is
	// still file-backed under ~/.xalgorix/data/auth-profiles.json;
	// a failure there is non-fatal — the dashboard still serves
	// traffic, and the profile handlers surface the missing
	// dependency as HTTP 503 so the operator can repair the file
	// without losing access to the rest of the UI.
	//
	// auth.NewStore defers file creation until the first write, so
	// the constructor is safe to invoke unconditionally on every
	// start.
	srv.catalog = providers.NewService()
	profilePath := filepath.Join(dataDir, "auth-profiles.json")
	if store, err := auth.NewStore(profilePath, srv.catalog); err != nil {
		log.Printf("[auth] failed to load profile store at %s: %v (profile handlers will return 503)", profilePath, err)
	} else {
		srv.profiles = store
		// Wire the OAuth driver registry now that both
		// catalog + profile store are live. Driver
		// constructors in internal/auth are unexported,
		// so RegisterDefaultDrivers is the single
		// exported seam through which production code
		// stands up the canonical four-driver registry.
		// nil clock → registry uses realClock for the
		// device-code poller.
		srv.oauthRegistry = auth.NewRegistry(store, http.DefaultClient, nil)
		auth.RegisterDefaultDrivers(srv.oauthRegistry, nil)
	}

	// Multi-provider key store + model router (LiteLLM-style). The key
	// store is file-backed under <dataDir>/llm_keys.json; a load failure
	// is non-fatal — the provider-key handlers surface 503 and the rest
	// of the dashboard keeps serving. The router shares the compiled-in
	// catalog and is only built when the key store is live.
	if ks, err := llm.NewKeyStore(dataDir); err != nil {
		log.Printf("[llm] failed to load key store: %v (provider-key handlers will return 503)", err)
	} else {
		srv.llmKeyStore = ks
		srv.llmRouter = llm.NewRouter(srv.catalog, ks)
	}

	// Rebuild instances map from disk so dashboard shows historical scans on startup
	srv.rebuildInstancesFromDisk()

	// Load schedules from disk
	srv.loadSchedulesFromDisk()

	return srv
}

func (s *Server) hasPendingOrRunningInstance() bool {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		active := inst.Status == "pending" || inst.Status == "running"
		inst.mu.RUnlock()
		if active {
			return true
		}
	}
	return false
}

func (s *Server) hasQueueResumeLaunchingLocked() bool {
	return len(s.queueResumeLaunching) > 0
}

func (s *Server) markQueueResumeLaunchingLocked(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	if s.queueResumeLaunching == nil {
		s.queueResumeLaunching = make(map[string]bool)
	}
	s.queueResumeLaunching[key] = true
}

func (s *Server) clearQueueResumeLaunching(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	s.queueResumeMu.Lock()
	delete(s.queueResumeLaunching, key)
	s.queueResumeMu.Unlock()
}

func queueResumeEntryKey(entry queueStateEntry) string {
	if entry.state != nil && strings.TrimSpace(entry.state.InstanceID) != "" {
		return strings.TrimSpace(entry.state.InstanceID)
	}
	if entry.path != "" {
		return filepath.Clean(entry.path)
	}
	return "legacy"
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Start the background scheduler
	go s.startScheduler()

	// Start the scan-retention sweeper. It self-disables (returns
	// immediately) when XALGORIX_SCAN_RETENTION_DAYS is 0, so this is a
	// no-op for installs that want to keep scans forever.
	go s.startRetentionSweeper()

	// Reap expired session cookies in the background so the auth map cannot
	// grow unbounded from abandoned logins.
	if authConfigured(s.cfg) {
		startSessionReaper()
	}

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	// fs.Sub on embed.FS returns an fs.FS that does implement ReadFileFS today,
	// but assert with comma-ok so a future runtime change can't crash the server.
	rfs, hasRfs := staticFS.(fs.ReadFileFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setWebUICacheHeaders(w)
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file. Production Vite assets use
		// content-hashed /assets/* paths; older builds may request stable root
		// names or /static/app.js. staticFS already points at that root.
		strippedPath := strings.TrimPrefix(path, "/")
		strippedPath = strings.TrimPrefix(strippedPath, "static/")
		if hasRfs {
			if f, err := rfs.ReadFile(strippedPath); err == nil && f != nil {
				// Rewrite URL to serve from staticFS root (which is already "static")
				r.URL.Path = "/" + strippedPath
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Known static asset paths that didn't resolve to a real file are
		// genuine 404s. App routes may contain dots in path params (for
		// example scan ids derived from hostnames), so don't treat every
		// dotted path as a file.
		if isStaticWebAssetPath(path) {
			http.NotFound(w, r)
			return
		}
		// Not a static file — serve index.html (SPA catch-all)
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/restart", s.handleRestart)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/findings/summary", s.handleFindingsSummary)
	mux.HandleFunc("/api/findings", s.handleFindingsList)
	mux.HandleFunc("/api/legacy-import/status", s.handleLegacyImportStatus)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scans/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/vulns/") && r.Method == http.MethodDelete {
			s.handleDeleteVuln(w, r)
			return
		}
		// GET /api/scans/{id}/events?offset=&limit= — lazy-page the event log
		// that the detail response only tails. Must be checked before the
		// generic detail handler.
		if strings.HasSuffix(r.URL.Path, "/events") && r.Method == http.MethodGet {
			s.handleScanEvents(w, r)
			return
		}
		s.handleGetScan(w, r)
	})
	// DELETE /api/data-dirs/{name} — delete one top-level Scan_Folder under
	// Data_Dir. Distinct prefix from /api/scans/ (no collision, R5.3); inherits
	// authMiddleware + CSRF and stays subject to rate limiting as a mutating
	// route (intentionally NOT added to isDashboardReadPath). R5.1, R5.2.
	mux.HandleFunc("/api/data-dirs/", s.handleDeleteDataDir)
	mux.HandleFunc("/api/schedules", s.handleSchedules)
	mux.HandleFunc("/api/schedules/", s.handleScheduleDetail)
	mux.HandleFunc("/api/upload-targets", s.handleUploadTargets)
	mux.HandleFunc("/api/upload-instructions", s.handleUploadInstructions)
	mux.HandleFunc("/api/upload-logo", s.handleUploadLogo)
	mux.HandleFunc("/api/upload-context", s.handleUploadContext)
	mux.HandleFunc("/api/upload-source", s.handleUploadSource)
	// Serve uploaded logos
	logosDir := filepath.Join(s.dataDir, "logos")
	_ = os.MkdirAll(logosDir, 0700)
	mux.Handle("/uploads/logos/", http.StripPrefix("/uploads/logos/", http.FileServer(http.Dir(logosDir))))
	mux.HandleFunc("/api/report/", s.handleDownloadReport)
	mux.HandleFunc("/api/settings/rate-limit", s.handleRateLimit)
	mux.HandleFunc("/api/settings/agentmail", s.handleAgentMailSettings)
	mux.HandleFunc("/api/settings/llm", s.handleLLMSettings)
	mux.HandleFunc("/api/settings/llm/keys", s.handleProviderKeys)
	mux.HandleFunc("/api/settings/llm/test-route", s.handleTestRoute)
	mux.HandleFunc("/api/settings/environment", s.handleEnvironmentSettings)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/stop-notify", s.handleStopNotify)
	mux.HandleFunc("/api/instances", s.handleInstances)
	mux.HandleFunc("/api/instances/", s.handleInstanceAction)

	mux.HandleFunc("/api/chat", s.handleChat)

	// Auth routes (these are public — authMiddleware skips them)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)

	// ── Provider catalog + auth profile routes (Wave E task 5.4) ──
	//
	// All these routes mount on the same mux as the rest of /api/*,
	// so they inherit:
	//   • authMw  — Authenticated_Operator gate (R12.4) plus the
	//               global isCSRFSafe check that wraps every
	//               state-changing /api/* request (R12.5).
	//   • rlMw    — the per-IP token-bucket rate limiter applied to
	//               every API route.
	//
	// We deliberately do NOT register `/oauth/callback` here — the
	// PKCE driver allocates its own ephemeral 127.0.0.1 listener
	// per flow start (R13.1, R13.3). Putting the callback on the
	// dashboard mux would expose it to CSRF and to any long-lived
	// network exposure the operator chooses; the per-flow listener
	// avoids both. The dashboardRoutes slice below is consulted in
	// tests to assert this invariant continues to hold.
	//
	// Multi-method routes are dispatched by HTTP method via small
	// adapters; each downstream handler still validates its own
	// method so an unexpected verb returns 405 even when called
	// through these adapters from a future entry point.
	mux.HandleFunc("/api/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListProviders(w, r)
	})
	mux.HandleFunc("/api/providers/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/models") {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDiscoverProviderModels(w, r)
	})
	mux.HandleFunc("/api/auth/profiles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListProfiles(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/api-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleCreateAPIKeyProfile(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/oauth/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOAuthStart(w, r)
	})
	mux.HandleFunc("/api/auth/profiles/oauth/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOAuthComplete(w, r)
	})
	// /api/auth/profiles/{key}/refresh (POST) and
	// /api/auth/profiles/{key} (DELETE) share the same trailing-slash
	// dispatcher because http.ServeMux funnels every sub-path of
	// "/api/auth/profiles/" through one handler. We branch on the
	// "/refresh" suffix first; everything else is treated as the
	// {key}-only DELETE path. Both /api/auth/profiles/api-key and
	// /api/auth/profiles/oauth/{start,complete} are registered as
	// exact-match patterns above so their longer-prefix dispatch
	// wins over this trailing-slash handler.
	mux.HandleFunc("/api/auth/profiles/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/refresh") {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.handleProfileRefresh(w, r)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleDeleteProfile(w, r)
	})

	// Wrap with auth middleware (outermost) then rate limiting
	authMw := authMiddleware(s.cfg)
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)

	// Bind to a specific interface. Default is 127.0.0.1 (loopback) so a
	// fresh install isn't exposed to the network. Operators who want
	// external access set XALGORIX_BIND=0.0.0.0 explicitly — and in that
	// case auth MUST be configured or we refuse to start. This is a
	// deliberate safety choice: the dashboard can launch arbitrary scans
	// and a chat tool with the LLM, so an open port is a control plane.
	bindAddr := s.cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	isLoopback := bindAddr == "127.0.0.1" || bindAddr == "::1" || bindAddr == "localhost"
	if !isLoopback && !authConfigured(s.cfg) {
		return fmt.Errorf(
			"refusing to bind to non-loopback address %q without auth: set XALGORIX_USERNAME and either XALGORIX_PASSWORD_HASH (bcrypt) or XALGORIX_PASSWORD in ~/.xalgorix.env, or set XALGORIX_BIND=127.0.0.1",
			bindAddr,
		)
	}
	addr := fmt.Sprintf("%s:%d", bindAddr, s.port)
	if isLoopback {
		log.Printf("Xalgorix Web UI → http://%s:%d (loopback only)", bindAddr, s.port)
	} else {
		log.Printf("Xalgorix Web UI → http://%s:%d (NETWORK-EXPOSED)", bindAddr, s.port)
	}
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	if authConfigured(s.cfg) {
		authMode := "plaintext"
		if s.cfg.PasswordHash != "" {
			authMode = "bcrypt"
		}
		log.Printf("Authentication enabled (user: %s, password: %s)", s.cfg.Username, authMode)
	} else {
		log.Printf("Authentication disabled — listening on loopback only. Set XALGORIX_USERNAME and XALGORIX_PASSWORD_HASH in ~/.xalgorix.env to enable.")
	}

	// ── Auto-resume interrupted scan queue after short startup delay ──
	// Gate the resume on no scan having started in the meantime — without
	// this, a user request arriving in the first 5 seconds would race with
	// the auto-resume goroutine and both runMultiScan calls would stomp
	// on the same cancelScan field.
	go func() {
		time.Sleep(3 * time.Second) // let HTTP server fully initialize
		s.queueResumeMu.Lock()
		defer s.queueResumeMu.Unlock()
		if s.running.Load() || s.hasQueueResumeLaunchingLocked() {
			log.Printf("[AUTO-RESUME] Skipping — a scan execution is already active.")
			return
		}
		entries := autoResumeQueueEntries(s.validQueueStateEntries(true))
		if len(entries) == 0 {
			return
		}
		log.Printf("[AUTO-RESUME] Resuming %d interrupted scan queue(s)", len(entries))
		for _, entry := range entries {
			if s.stopReq.Load() {
				break
			}
			req := scanRequestFromQueueState(entry.state, entry.path)
			if len(req.Targets) == 0 {
				continue
			}
			instanceID := entry.state.InstanceID
			log.Printf("[AUTO-RESUME] Resuming interrupted scan queue %s: %d targets from index %d", instanceID, len(req.Targets), entry.state.CurrentIdx)
			scanCfg := *s.cfg
			resumeKey := queueResumeEntryKey(entry)
			s.markQueueResumeLaunchingLocked(resumeKey)
			go func(e queueStateEntry, r ScanRequest, cfg config.Config, id string, key string) {
				defer s.clearQueueResumeLaunching(key)
				s.runMultiScan(r, &cfg, id)
			}(entry, req, scanCfg, instanceID, resumeKey)
		}
	}()

	// ── Graceful shutdown on SIGTERM/SIGINT ──
	httpServer := &http.Server{
		Addr: addr,
		// safe.HTTPMiddleware MUST be the outermost wrapper so it catches
		// panics from every layer below it (auth, rate-limit, gzip, mux,
		// individual handlers). On panic it increments PanicsRecovered,
		// emits a structured log line with stack trace, and returns 500.
		// gzip sits innermost (closest to the mux) so it compresses handler
		// output after auth + rate limiting have run; it skips /ws.
		Handler: safe.HTTPMiddleware(authMw(rlMiddleware(gzipMiddleware(mux)))),
		// Bound the time spent reading request headers so a slow client
		// cannot hold a connection open indefinitely (Slowloris). The
		// dashboard serves interactive traffic, so keep this generous.
		ReadHeaderTimeout: 30 * time.Second,
	}
	// Expose the server so the /api/restart handler can trigger a graceful
	// restart-when-idle through the same path as the SIGUSR1 watcher.
	s.httpServer = httpServer

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("[SHUTDOWN] Received signal %s — saving state and shutting down gracefully", sig)

		// Stop the background scheduler
		close(s.shutdownChan)

		// Stop all running scans so they save queue state
		s.stopReq.Store(true)
		s.mu.Lock()
		if s.cancelScan != nil {
			s.cancelScan()
		}
		for _, agnt := range s.currentAgents {
			if agnt != nil {
				agnt.Stop()
			}
		}
		s.mu.Unlock()

		// Stop all instances
		s.instancesMu.RLock()
		for _, inst := range s.instances {
			inst.mu.Lock()
			if inst.Status == "running" {
				inst.Status = "stopped"
				inst.StopReason = "signal_" + sig.String()
				inst.FinishedAt = time.Now().Format(time.RFC3339)
				normalizeTerminalWildcardInstanceLocked(inst)
				if inst.agent != nil {
					inst.agent.Stop()
				}
			}
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()

		terminal.KillAllProcesses()

		// Send Discord notification. Use sig.String() explicitly so we get
		// "terminated"/"interrupt" rather than a numeric fallback for any
		// os.Signal implementation that doesn't satisfy fmt.Stringer.
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}
		if s.telegramConfigured() {
			s.sendTelegram(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}

		// Give scans a moment to save their queue state
		time.Sleep(2 * time.Second)

		// Graceful HTTP shutdown (5s deadline for in-flight requests)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] HTTP shutdown error: %v", err)
		}

		_ = proxy.Close()
		s.rateLimiter.Stop()
		log.Printf("[SHUTDOWN] Graceful shutdown complete")
	}()

	// ── Graceful restart-when-idle on SIGUSR1 ──
	// `xalgorix --restart-when-idle` sends SIGUSR1 to this process. We do not
	// restart immediately: a watcher waits until no scan instance is active
	// and no tool process is leased, then restarts cleanly (so in-flight
	// engagements are never interrupted).
	go func() {
		usrCh := make(chan os.Signal, 1)
		signal.Notify(usrCh, syscall.SIGUSR1)
		for range usrCh {
			if !s.scheduleGracefulRestart() {
				log.Printf("[RESTART] Graceful restart already pending — ignoring duplicate SIGUSR1")
			}
		}
	}()

	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil // graceful shutdown
	}
	return err
}

// scheduleGracefulRestart marks the server for a restart-when-idle and starts
// the watcher that performs the restart once no scan/instance is active. It is
// the shared entry point for both the SIGUSR1 signal and the POST /api/restart
// endpoint. Returns false if a restart was already pending (idempotent), so
// duplicate requests don't spawn multiple watchers.
func (s *Server) scheduleGracefulRestart() bool {
	if s.restartWhenIdle.Swap(true) {
		return false
	}
	log.Printf("[RESTART] Graceful restart requested — will restart once all scans finish")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	go s.restartWhenIdleWatcher(s.httpServer)
	return true
}

// scannerIdle reports whether it is safe to restart: no scan instance is// active (running/pending/paused/queued/starting) and no terminal tool is
// currently leased. Completed/stopped/failed instances are historical and
// do not block a restart.
func (s *Server) scannerIdle() bool {
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		st := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		switch st {
		case "running", "pending", "paused", "queued", "starting":
			s.instancesMu.RUnlock()
			return false
		}
	}
	s.instancesMu.RUnlock()
	if s.running.Load() {
		return false
	}
	if resources.Capacity().ActiveToolLeases > 0 {
		return false
	}
	return true
}

// restartWhenIdleWatcher polls scanner state after a SIGUSR1 request and
// triggers a restart once the scanner has been idle for a few consecutive
// checks (debounced so a brief gap between queued targets does not trigger an
// early restart).
func (s *Server) restartWhenIdleWatcher(httpServer *http.Server) {
	const interval = 5 * time.Second
	const idleChecksNeeded = 3 // ~15s of sustained idle before restarting
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	idleStreak := 0
	for range ticker.C {
		if !s.restartWhenIdle.Load() {
			return // request was cleared elsewhere
		}
		if s.scannerIdle() {
			idleStreak++
			if idleStreak >= idleChecksNeeded {
				s.restartNow(httpServer)
				return
			}
		} else {
			idleStreak = 0
		}
	}
}

// restartNow performs the actual restart. Under systemd (Restart=always) a
// clean exit is enough — systemd re-runs ExecStart, reloading the env file.
// Outside systemd (background mode) we re-exec the binary in place so the
// service comes back without an external supervisor. Either path also picks
// up a newly-installed binary on disk.
func (s *Server) restartNow(httpServer *http.Server) {
	log.Printf("[RESTART] Scanner idle — restarting now")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}

	// Belt-and-suspenders: reap any stray tool processes before we go.
	terminal.KillAllProcesses()

	// Release the listening socket so the restarted process can rebind.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[RESTART] HTTP shutdown error: %v", err)
		}
	}
	_ = proxy.Close()

	// systemd-managed: INVOCATION_ID is set by systemd for service units.
	// A clean exit triggers Restart=always with a freshly-loaded env file.
	if os.Getenv("INVOCATION_ID") != "" {
		log.Printf("[RESTART] Exiting for systemd to restart (fresh environment)")
		os.Exit(0)
	}

	// Background mode: re-exec in place.
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		exe = os.Args[0]
	}
	log.Printf("[RESTART] Re-executing %s", exe)
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("[RESTART] re-exec failed: %v — exiting for supervisor restart", err)
		os.Exit(0)
	}
}

// initDataDir is a thin wrapper around cfg.DataDir (Task 3.6 / R6.4, R6.6):
// the directory is already canonicalized and created with mode 0o700 by
// config.resolveDataDir at startup, so the MkdirAll below is belt-and-
// suspenders — it covers the narrow window where a test or operator
// removes the directory between config load and Server.Start. The
// function's real job is the per-startup cleanup of stale scan dirs and
// the surfacing of any interrupted scan queues for auto-resume.
func (s *Server) initDataDir() {
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		log.Printf("Error: failed to create data directory %s: %v", s.dataDir, err)
	}

	// Cleanup scans older than 30 days
	entries, _ := os.ReadDir(s.dataDir)
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Explicitly skip folder names starting with '_' or named 'logos'
		if strings.HasPrefix(e.Name(), "_") || e.Name() == "logos" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(s.dataDir, e.Name()))
			log.Printf("Cleaned up old scan: %s", e.Name())
		}
	}

	// Check for interrupted queues — will auto-resume after server starts
	if entries := s.validQueueStateEntries(true); len(entries) > 0 {
		remaining := 0
		for _, entry := range entries {
			remaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		log.Printf("Found %d interrupted scan queue(s): %d targets remaining (will auto-resume in 5s)", len(entries), remaining)
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Code-first scans: the subject is source (SourceRepo), not a live URL.
	// "review" needs no target; "provision" synthesizes a loopback target the
	// agent stands the app up on. resolveCodeScan validates and, on success,
	// sets req.Targets / req.codeScanMode / req.allowLoopbackPorts.
	isCodeScan, codeErr := s.resolveCodeScan(&req)
	if codeErr != "" {
		http.Error(w, codeErr, http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets required (or provide source_repo with code_scan=review|provision)", http.StatusBadRequest)
		return
	}
	normalizeScanRequestActivity(&req)

	// Reject up front when every requested target is a local/internal IP or
	// the dashboard's own listener. runMultiScan filters these out anyway,
	// but without this check a fully-blocked request produces a "started"
	// instance with zero effective targets that the operator must then
	// clean up. Surface a 400 instead. Mixed requests (at least one allowed
	// target) proceed and the blocked entries are filtered downstream.
	// Code scans are exempt: a "provision" target is a deliberate loopback
	// address the scope guard allowlists for this scan only.
	if !req.SaveOnly && !isCodeScan {
		allBlocked := true
		for _, t := range req.Targets {
			if strings.TrimSpace(t) == "" {
				continue
			}
			if !s.isBlockedTarget(t) {
				allBlocked = false
				break
			}
		}
		if allBlocked {
			msg := "All targets are local/internal addresses or the dashboard's own listener, so the scan was refused (self-scan protection)."
			if s.cfg.AllowLocalTargets {
				// Local scanning is already on, so the only things still blocked
				// are the dashboard itself and the unspecified address.
				msg += " The dashboard's own listener and the unspecified address (0.0.0.0 / ::) are never scannable, even with local targets enabled — point the scan at the app's actual host:port instead."
			} else {
				// Self-hosted operators can opt in; tell them exactly how.
				msg += " To scan a locally-hosted app on a self-hosted install, enable local targets: Settings → Security → \"Allow local targets\", or set XALGORIX_ALLOW_LOCAL_TARGETS=true in ~/.xalgorix.env and restart. (The dashboard's own listener stays protected either way. Leave this OFF on shared/hosted deployments.)"
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
	}

	// R11.6 precondition check: if the request names a
	// provider_profile, fail fast with HTTP 400 BEFORE spawning a
	// scan goroutine. Other resolver errors are intentionally NOT
	// surfaced here — they're either transient (file lock contention
	// during a concurrent profile edit) or downstream concerns the
	// LLM client's own resolver will report when it actually runs
	// the request. This guard exists solely so a misspelled profile
	// id never produces a "started" instance the operator then has
	// to clean up.
	if _, err := s.resolveScanCredentials(r.Context(), req, s.cfg); err != nil {
		if errors.Is(err, errUnknownProviderProfile) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Non-sentinel resolver error (typically a transient
		// flock contention or a profile race-deleted between
		// the dashboard's profile-list fetch and the scan
		// submission). M8: log so the error is visible at
		// triage time rather than being silently swallowed; the
		// LLM client's own resolver will surface a follow-up
		// envelope at first chat call.
		log.Printf("scan: precondition resolveScanCredentials returned non-sentinel error: %v", err)
		// fall through — surface the error only when it is the
		// canonical R11.6 sentinel.
	}

	// Apply LLM provider settings from web UI securely using a copy
	scanCfg := *s.cfg // shallow copy
	if req.Model != "" {
		scanCfg.LLM = req.Model
	}
	if req.APIKey != "" {
		scanCfg.APIKey = req.APIKey
	}
	if req.APIBase != "" {
		scanCfg.APIBase = req.APIBase
	}

	// Save-only mode: create a persistent scan config without starting execution
	if req.SaveOnly {
		instanceID := randomSlug()
		now := time.Now().Format(time.RFC3339Nano)
		inst := &ScanInstance{
			ID:             instanceID,
			Name:           req.Name,
			Targets:        strings.Join(req.Targets, ", "),
			Status:         "saved",
			StartedAt:      now,
			ScanMode:       req.ScanMode,
			Instruction:    req.Instruction,
			SeverityFilter: req.SeverityFilter,
			Phases:         req.Phases,
			ReconMode:      req.ReconMode,
			ScanIntensity:  req.ScanIntensity,
			CurrentPhase:   firstSelectedPhase(req.Phases),
			CompanyName:    req.CompanyName,
			LogoPath:       req.LogoPath,
			DiscordWebhook: req.DiscordWebhook,
			// Retained in-memory so "Save for later" → start keeps the
			// operator's authenticated-scanning + whitebox + context config.
			TargetAuth:          req.TargetAuth,
			TargetAuthSecondary: req.TargetAuthSecondary,
			SourceRepo:          req.SourceRepo,
			ScanContext:         req.ScanContext,
		}
		chatCfg := scanCfg
		inst.chatCfg = &chatCfg
		s.instancesMu.Lock()
		s.instances[instanceID] = inst
		s.instancesMu.Unlock()

		// Persist to disk so saved targets survive server restarts
		targetStr := strings.Join(req.Targets, ", ")
		savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
		if err := os.MkdirAll(savedDir, 0700); err != nil {
			log.Printf("[ERROR] failed to create saved-target dir %s: %v", savedDir, err)
		} else {
			rec := &ScanRecord{
				ID:                       instanceID,
				Name:                     req.Name,
				Target:                   targetStr,
				Status:                   "saved",
				StartedAt:                now,
				ScanMode:                 req.ScanMode,
				Instruction:              req.Instruction,
				SeverityFilter:           req.SeverityFilter,
				Phases:                   req.Phases,
				ReconMode:                req.ReconMode,
				ScanIntensity:            req.ScanIntensity,
				CurrentPhase:             firstSelectedPhase(req.Phases),
				CompanyName:              req.CompanyName,
				LogoPath:                 req.LogoPath,
				DiscordWebhook:           req.DiscordWebhook,
				DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
				TelegramConfigured:       s.telegramConfigured(),
			}
			s.saveScanRecordTo(rec, savedDir)
		}

		s.broadcastDashboard(WSEvent{
			Type:    "instance_started",
			Content: instanceID,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "instance_id": instanceID})
		return
	}

	instanceID := strings.TrimSpace(req.DispatchID)
	callerDispatchID := instanceID != ""
	if callerDispatchID {
		if !validDispatchID(instanceID) {
			http.Error(w, "dispatch_id must be 16-128 URL-safe characters", http.StatusBadRequest)
			return
		}
	} else {
		for {
			instanceID = randomSlug()
			if _, reserved := s.reserveDispatchID(instanceID); reserved {
				break
			}
		}
	}
	if callerDispatchID {
		if status, reserved := s.reserveDispatchID(instanceID); !reserved {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "instance_id": instanceID})
			return
		}
	}
	ownership, owned, err := s.acquireQueueOwnership(instanceID)
	if err != nil {
		s.releaseDispatchID(instanceID)
		http.Error(w, "could not acquire dispatch queue ownership", http.StatusInternalServerError)
		return
	}
	if !owned {
		s.releaseDispatchID(instanceID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "instance_id": instanceID})
		return
	}
	req.queueOwnership = ownership
	status, accepted, err := s.persistPendingDispatchSnapshot(req, instanceID)
	if err != nil {
		ownership.release()
		s.releaseDispatchID(instanceID)
		http.Error(w, "could not durably reserve dispatch identity", http.StatusInternalServerError)
		return
	}
	if !accepted {
		ownership.release()
		s.releaseDispatchID(instanceID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "instance_id": instanceID})
		return
	}
	req.Name = strings.TrimSpace(req.Name) // propagate name to running scans too
	req.InstanceID = instanceID
	if err := s.saveQueueStateDurable(0, req); err != nil {
		if abortErr := s.abortPendingDispatchSnapshot(instanceID, "queue_state_persist_failed"); abortErr != nil {
			log.Printf("[scan] failed to terminalize dispatch %s after queue-state error: %v", instanceID, abortErr)
		}
		ownership.release()
		s.releaseDispatchID(instanceID)
		http.Error(w, "could not durably persist resumable dispatch", http.StatusInternalServerError)
		return
	}
	go func() {
		defer s.releaseDispatchID(instanceID)
		s.runMultiScan(req, &scanCfg, instanceID)
	}()

	// The ack reflects the scan's actual local state: it is QUEUED as
	// "pending" (orchestrator.go registers it pending, then the admission
	// gate flips it to "running" only once a concurrency slot is granted).
	// Previously this returned "started", which external callers (e.g. a SaaS
	// control plane) misread as "running" — producing a SaaS=running /
	// worker=pending desync whenever the worker was at its RAM-derived cap.
	// Callers wanting the authoritative status should poll GET /api/instances
	// (or /api/scans), whose "status" field is pending until admission.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "instance_id": instanceID})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts LLM calls, tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	// Stop all tracked agents (safe for multi-instance)
	var agents []*agent.Agent
	for _, a := range s.currentAgents {
		agents = append(agents, a)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, agnt := range agents {
		if agnt != nil {
			agnt.Stop()
		}
	}

	// Stop ALL running instances (use write lock since we're modifying instance state)
	s.instancesMu.Lock()
	for _, inst := range s.instances {
		inst.mu.Lock()
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			normalizeTerminalWildcardInstanceLocked(inst)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	// Kill all spawned processes as a safety net
	terminal.KillAllProcesses()

	// A global user stop is terminal for every queue — clear all persisted
	// resume files so the dashboard queue counter clears and nothing is
	// auto-resumed on the next start (issue #239).
	s.clearQueueState()

	s.broadcast(WSEvent{Type: "stopped", Content: "All instances stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// handleRestart restarts the backend. By default the restart is graceful: it
// waits until no scan instance is active and no tool process is leased, then
// restarts cleanly (in-flight scans auto-resume afterwards). This is the HTTP
// equivalent of `xalgorix --restart-when-idle` (SIGUSR1) and shares the watcher.
//
// With force=true (query param ?force=true or JSON body {"force":true}) the
// restart is IMMEDIATE: it interrupts any in-flight scans/tools and restarts
// right now. Instances with durable queue state are reconstructed and resumed
// when the process returns; only an orphan without resumable state becomes a
// terminal stopped record. Use force when the scanner is wedged and would
// never reach idle on its own.
//
// POST /api/restart            → { "status": "scheduled"|"already_pending", "idle": bool }
// POST /api/restart?force=true → { "status": "restarting", "idle": bool, "forced": true }
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	idle := s.scannerIdle()

	if restartForceRequested(r) {
		log.Printf("[RESTART] /api/restart FORCE requested (idle=%v) — restarting immediately, interrupting any in-flight work", idle)
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔁 Xalgorix Force Restart",
				"An immediate restart was requested. Xalgorix is restarting now; in-flight processes are interrupted and resumable queues will recover after startup.")
		}
		if s.telegramConfigured() {
			s.sendTelegram(0xff6b6b, "🔁 Xalgorix Force Restart",
				"An immediate restart was requested. Xalgorix is restarting now; in-flight processes are interrupted and resumable queues will recover after startup.")
		}
		// Prevent an already-scheduled idle watcher from also firing.
		s.restartWhenIdle.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "restarting",
			"idle":   idle,
			"forced": true,
		})
		// Flush the response so the caller sees 200 BEFORE the process re-execs
		// (restartNow replaces/exits the process), then restart out-of-band.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if s.forceRestartFn != nil {
			go s.forceRestartFn()
			return
		}
		go func() {
			time.Sleep(500 * time.Millisecond)
			s.restartNow(s.httpServer)
		}()
		return
	}

	scheduled := s.scheduleGracefulRestart()

	status := "scheduled"
	if !scheduled {
		status = "already_pending"
	}
	log.Printf("[RESTART] /api/restart requested (idle=%v, status=%s)", idle, status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"idle":   idle,
	})
}

// restartForceRequested reports whether the caller asked for an immediate
// restart, via either the ?force=true query param or a JSON body {"force":true}.
func restartForceRequested(r *http.Request) bool {
	if isTrueish(r.URL.Query().Get("force")) {
		return true
	}
	if r.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil || len(body) == 0 {
		return false
	}
	var payload struct {
		Force bool `json:"force"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Force
}

func isTrueish(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	scanID := s.currentScanID
	s.mu.RUnlock()

	// Count running instances
	s.instancesMu.RLock()
	runningCount := 0
	runningInstanceID := ""
	currentPhase := 0
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
			if runningInstanceID == "" {
				runningInstanceID = inst.ID
				currentPhase = inst.CurrentPhase
			}
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Aggregate vulns across all active instances via their per-session context
	totalVulns := 0
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.sctx != nil {
			totalVulns += len(reporting.GetVulnerabilitiesForContext(inst.sctx.ID))
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Take a single atomic snapshot of safe counters so the values are
	// internally consistent (Task 11.4 / R9.5).
	counters := safe.Snapshot()
	allowList := sandbox.Default().Roots()
	readDeny := sandbox.Default().ReadDenyRoots()

	// vulns_persisted: total count from on-disk corpus across every scan
	// record. Stable across teardown — survives reporting.CleanupContext.
	// Additive change; the existing `vulns` field keeps its in-memory
	// semantics for backward compatibility. See Task 3.3 in
	// .kiro/specs/findings-consistency-and-pagination/tasks.md.
	persistedVulns := s.totalPersistedVulnCount()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"running":            s.running.Load() || runningCount > 0,
		"scan_id":            scanID,
		"instance_id":        runningInstanceID,
		"current_phase":      currentPhase,
		"vulns":              totalVulns,
		"vulns_persisted":    persistedVulns,
		"running_instances":  runningCount,
		"panics_recovered":   counters.PanicsRecovered,
		"path_rejections":    counters.PathRejections,
		"watchdog_kills":     counters.WatchdogKills,
		"admission_refusals": counters.AdmissionRefusals,
		"llm_inflight_cap":   resources.LLMInFlightCap(),
		"data_dir":           s.cfg.DataDir,
		"allow_list":         allowList,
		// read_deny is the deny-list applied to Filesystem_Tool reads.
		// Reads outside allow_list succeed by default; only paths under
		// these roots are rejected. Set XALGORIX_READ_DENY_LIST
		// (colon-separated) to extend the defaults.
		"read_deny": readDeny,
	})
}

// handleFindingsSummary returns a stable on-disk severity tally across
// every scan record under cfg.DataDir. Used by the WebUI Findings and
// Overview totals widgets to surface a counter that does NOT collapse
// when reporting.CleanupContext wipes in-memory stores during teardown.
//
// Counts are deduplicated by (target, endpoint, title, severity) — the
// same key the WebUI's dedupFindings helper uses. Without this, a
// vulnerability that recurs across N rescans of the same target would
// inflate the totals strip relative to the deduped row count rendered
// below it on /findings.
//
// Response shape:
//
//	{
//	  "totals": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
//	  "as_of": "<RFC3339>",
//	  "etag": "<hex sha256>"
//	}
//
// Honors If-None-Match: returns 304 Not Modified when the etag matches.
// The etag is derived from the marshaled totals plus the seconds-truncated
// as_of timestamp, so it is stable for short polling windows but rotates
// at least once per second when totals change.
//
// See Task 3.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 2 (counter monotonicity) in design.md.
func (s *Server) handleFindingsSummary(w http.ResponseWriter, r *http.Request) {
	totals := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	// Wrap the iteration in safe.Recover so a corrupt scan record cannot
	// kill the handler. (defer + named recover keeps response writing in
	// scope even when the walk panics.)
	func() {
		defer safe.Recover("findings-summary", "")
		seen := make(map[string]struct{})
		for _, entry := range s.findAllScanSummaries() {
			for _, v := range entry.rec.Vulns {
				key := dedupFindingKey(entry.rec.Target, v)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				bucket := normalizeSeverityBucket(v.Severity)
				totals[bucket]++
			}
		}
	}()

	asOf := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	// etag: sha256 over (marshaled totals || as_of). Truncating as_of to
	// seconds keeps the etag stable for sub-second polling windows.
	totalsJSON, _ := json.Marshal(totals)
	hash := sha256.New()
	hash.Write(totalsJSON)
	hash.Write([]byte(asOf))
	etag := hex.EncodeToString(hash.Sum(nil))

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"totals": totals,
		"as_of":  asOf,
		"etag":   etag,
	})
}

// flatFinding is a single vulnerability flattened across scans and augmented
// with its owning scan's identity. The embedded VulnSummary inlines its JSON
// fields, so the wire shape matches the WebUI's FlatFinding type exactly.
type flatFinding struct {
	VulnSummary
	ScanID        string `json:"scan_id"`
	ScanTarget    string `json:"scan_target"`
	ScanStartedAt string `json:"scan_started_at"`
}

// severityRankValue mirrors the WebUI's severityRank so server-side ordering
// matches the client (critical > high > medium > low > info).
func severityRankValue(severity string) int {
	switch normalizeSeverityBucket(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// handleFindingsList returns every finding flattened across all scans, deduped
// by (target, endpoint, title, severity) and sorted by severity desc then
// scan_started_at desc. This replaces the previous WebUI behavior of fetching
// every scan record individually (an N+1 of full-record requests, each
// carrying the scan's entire event log) just to build the findings table.
// One server-side walk returns only the vuln fields the table needs.
func (s *Server) handleFindingsList(w http.ResponseWriter, r *http.Request) {
	deduped := make(map[string]flatFinding)

	func() {
		defer safe.Recover("findings-list", "")
		for _, entry := range s.findAllScanSummaries() {
			rec := entry.rec
			for _, v := range rec.Vulns {
				key := dedupFindingKey(rec.Target, v)
				candidate := flatFinding{
					VulnSummary:   v,
					ScanID:        rec.ID,
					ScanTarget:    rec.Target,
					ScanStartedAt: rec.StartedAt,
				}
				if existing, ok := deduped[key]; ok && existing.ScanStartedAt >= candidate.ScanStartedAt {
					continue
				}
				deduped[key] = candidate
			}
		}
	}()

	findings := make([]flatFinding, 0, len(deduped))
	for _, f := range deduped {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRankValue(findings[i].Severity), severityRankValue(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ScanStartedAt > findings[j].ScanStartedAt
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(findings)
}

// handleLegacyImportStatus exposes the in-memory legacy import counter
// surfaced once to the WebUI on the run that did the import. The count
// originates from importLegacyDataDir at startup; this endpoint just
// reads the cached value so the WebUI can render a one-time dismissible
// banner on first load.
//
// Response shape:
//
//	{"count": N, "dismissed": false}
//
// Methods:
//   - GET  → return the current state.
//   - POST → flip dismissed=true for the remainder of the process and
//     return the updated state. Restart re-shows the banner once.
//
// The dismissed flag is in-memory only; restart re-shows. When count==0
// the WebUI suppresses the banner outright (so dismissal of a zero
// state is a harmless no-op).
//
// See Task 5.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 6 (legacy-import idempotence) in design.md.
func (s *Server) handleLegacyImportStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.legacyImportMu.RLock()
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	case http.MethodPost:
		s.legacyImportMu.Lock()
		s.legacyImportDismissed = true
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstances returns all scan instances (running + recent)
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.instancesMu.RLock()
	instances := make([]*ScanInstance, 0, len(s.instances))
	for _, inst := range s.instances {
		inst.mu.RLock()
		instances = append(instances, &ScanInstance{
			ID:               inst.ID,
			Name:             inst.Name,
			Targets:          inst.Targets,
			Status:           inst.Status,
			StartedAt:        inst.StartedAt,
			FinishedAt:       inst.FinishedAt,
			Iterations:       inst.Iterations,
			ToolCalls:        inst.ToolCalls,
			VulnCount:        inst.VulnCount,
			TotalTokens:      inst.TotalTokens,
			ScanMode:         inst.ScanMode,
			Instruction:      inst.Instruction,
			SeverityFilter:   append([]string(nil), inst.SeverityFilter...),
			Phases:           inst.Phases,
			ReconMode:        inst.ReconMode,
			ScanIntensity:    inst.ScanIntensity,
			CompanyName:      inst.CompanyName,
			LogoPath:         inst.LogoPath,
			CurrentPhase:     inst.CurrentPhase,
			SubScans:         cloneSubScanSummaries(inst.SubScans),
			SubScanTotal:     inst.SubScanTotal,
			SubScanCompleted: inst.SubScanCompleted,
			SubScanRunning:   inst.SubScanRunning,
			SubScanRemaining: inst.SubScanRemaining,
		})
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()
	runningInstances := 0
	recentAdmissions := 0
	now := time.Now()
	for _, inst := range instances {
		if strings.EqualFold(strings.TrimSpace(inst.Status), "running") {
			runningInstances++
			if admissionMemoryUnreflected(inst.StartedAt, now) {
				recentAdmissions++
			}
		}
	}

	// Sort: running first, then by start time descending
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Status == "running" && instances[j].Status != "running" {
			return true
		}
		if instances[i].Status != "running" && instances[j].Status == "running" {
			return false
		}
		return instances[i].StartedAt > instances[j].StartedAt
	})

	// Distinct scan modes across ALL instances, computed before filtering so
	// the UI's mode dropdown always offers the full set of options.
	modeSet := make(map[string]struct{})
	for _, inst := range instances {
		if inst.ScanMode != "" {
			modeSet[inst.ScanMode] = struct{}{}
		}
	}
	modes := make([]string, 0, len(modeSet))
	for m := range modeSet {
		modes = append(modes, m)
	}
	sort.Strings(modes)

	// Optional server-side filtering (no-ops when the params are absent).
	if q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q"))); q != "" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.Contains(strings.ToLower(inst.Name), q) ||
				strings.Contains(strings.ToLower(inst.Targets), q) ||
				strings.Contains(strings.ToLower(inst.ID), q) {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if st := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); st != "" && st != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.ToLower(inst.Status) == st {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if mode := strings.TrimSpace(r.URL.Query().Get("mode")); mode != "" && mode != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if inst.ScanMode == mode {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}

	// Pagination is opt-in: only slice when a page/size param is present, so
	// the default GET /api/instances response still returns every instance.
	total := len(instances)
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	page, size := 1, 0
	if pageStr != "" || sizeStr != "" {
		page, size = parsePageParams(pageStr, sizeStr)
		start := (page - 1) * size
		if start < 0 {
			start = 0
		}
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		instances = instances[start:end]
	}
	if instances == nil {
		instances = []*ScanInstance{}
	}

	// Include resource stats so the UI can explain why scans are pending
	stats := resources.GetStats()
	level, _ := resources.CurrentLevel()
	effectiveMax, reason := resources.EffectiveMaxInstancesForAdmission(
		runningInstances,
		recentAdmissions,
	)
	availableInstanceSlots := effectiveMax - runningInstances
	if availableInstanceSlots < 0 {
		availableInstanceSlots = 0
	}
	capacity := resources.Capacity()
	response := map[string]any{
		"instances": instances,
		"total":     total,
		"page":      page,
		"size":      size,
		"modes":     modes,
		"resources": map[string]any{
			"cpu_cores":                stats.CPUCores,
			"cpu_load_1m":              stats.LoadAvg1m,
			"ram_total_mb":             stats.MemTotalMB,
			"ram_available_mb":         stats.MemAvailableMB,
			"disk_free_mb":             stats.DiskFreeMB,
			"process_rss_mb":           stats.ProcessRSSMB,
			"go_heap_alloc_mb":         stats.GoHeapAllocMB,
			"go_heap_sys_mb":           stats.GoHeapSysMB,
			"goroutines":               stats.Goroutines,
			"level":                    level.String(),
			"reason":                   reason,
			"max_instances":            effectiveMax,
			"manual_max_instances":     resources.MaxInstances(),
			"effective_max_instances":  effectiveMax,
			"running_instances":        runningInstances,
			"unreflected_admissions":   recentAdmissions,
			"available_instance_slots": availableInstanceSlots,
			"active_tool_leases":       capacity.ActiveToolLeases,
			"active_heavy_tool_leases": capacity.ActiveHeavyToolLeases,
			"heavy_tool_slots":         capacity.HeavyToolSlots,
			"light_tool_slots":         capacity.LightToolSlots,
			"tool_mem_limit_mb":        capacity.ToolMemLimitMB,
			"scan_memory_budget_mb":    capacity.ScanMemoryBudgetMB,
			"heavy_tool_cpu_load":      capacity.HeavyToolCPULoad,
			"go_memory_limit_mb":       capacity.GoMemoryLimitMB,
		},
	}
	_ = json.NewEncoder(w).Encode(response)
}

// handleInstanceAction handles per-instance operations (stop, etc)
// resolveInstanceForAction maps a URL id to a live ScanInstance for the
// per-instance action endpoints (stop/pause/resume/restart/start/events).
//
// The exact in-memory instance id always wins. But the scan-detail page routes
// by the scan RECORD id (and sometimes a short hex alias), which for wildcard
// scans differs from the instance id — so a plain map lookup 404'd and the
// Stop/Delete buttons silently did nothing there, while the Instances page
// (which passes the real instance id) worked. Fall back to resolving the id as
// a record id / short alias and mapping that record to its instance.
func (s *Server) resolveInstanceForAction(id string) (*ScanInstance, bool) {
	if id == "" {
		return nil, false
	}
	s.instancesMu.RLock()
	inst, ok := s.instances[id]
	s.instancesMu.RUnlock()
	if ok {
		return inst, true
	}
	// Not a live instance id — resolve only a provable persisted record
	// relationship and map that record back to its instance. Record IDs remain
	// supported for dashboard navigation, but recency/target/short-alias guesses
	// are forbidden for reads and mutations.
	_, rec := s.findScanByID(id)
	if rec != nil {
		if inst := s.instanceForRecord(rec); inst != nil {
			return inst, true
		}
	}
	return nil, false
}

func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Path: /api/instances/{id}/stop or /api/instances/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/instances/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "instance ID required", http.StatusBadRequest)
		return
	}
	instanceID := parts[0]

	// GET /api/instances/{id}/snapshot is the authoritative coordinator API.
	// It resolves only the exact external instance ID and returns status,
	// findings, wildcard counters, and events under one lock / one persisted
	// record read. This gives callers independent identity proof and prevents a
	// terminal summary from being paired with another run's bare event array.
	if r.Method == http.MethodGet && len(parts) >= 2 && parts[1] == "snapshot" {
		s.instancesMu.RLock()
		exact := s.instances[instanceID]
		s.instancesMu.RUnlock()
		if exact != nil {
			exact.mu.RLock()
			terminalFinalizing := isTerminalScanStatus(exact.Status) && exact.snapshotFinalizing
			ready := exact.snapshotReady
			exact.mu.RUnlock()
			if terminalFinalizing {
				if !ready {
					http.Error(w, "terminal instance snapshot is still finalizing", http.StatusConflict)
					return
				}
				if err := s.retryReadyExactSnapshot(exact); err != nil {
					log.Printf("[scan] GET exact snapshot retry failed for %s: %v", instanceID, err)
					http.Error(w, "terminal instance snapshot is still finalizing", http.StatusConflict)
					return
				}
			}
			exact.mu.RLock()
			events := append([]WSEvent(nil), exact.events...)
			response := struct {
				*ScanInstance
				InstanceID string    `json:"instance_id"`
				Events     []WSEvent `json:"events"`
			}{ScanInstance: exact, InstanceID: exact.ID, Events: events}
			_ = json.NewEncoder(w).Encode(response)
			exact.mu.RUnlock()
			return
		}

		// An evicted or post-restart terminal run remains readable only when its
		// persisted immutable InstanceID exactly equals the requested value.
		// Active persisted records without a live instance are uncertainty.
		_, rec := s.findScanByInstanceID(instanceID)
		if rec == nil || !isTerminalScanStatus(rec.Status) {
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}
		s.attachWildcardSubScans(rec)
		finalizeScanRecordForResponse(rec)
		_ = json.NewEncoder(w).Encode(rec)
		return
	}

	// Exact control-plane stop must resolve under the same dispatch lock used by
	// delayed POST registration and work admission. A map lookup performed
	// before that lock can go stale and tombstone an ID while its live instance
	// continues running.
	if r.Header.Get("X-Xalgorix-Exact-Instance") == "1" &&
		len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		rec, notifyListeners, err := s.cancelExactDispatch(instanceID)
		if err != nil {
			if errors.Is(err, errDispatchSnapshotNotFound) {
				http.Error(w, "instance not found", http.StatusNotFound)
			} else {
				http.Error(w, "could not durably stop exact instance", http.StatusInternalServerError)
			}
			return
		}
		if notifyListeners {
			for _, event := range rec.Events {
				if event.Type == "stopped" && event.Content == exactStopEventContent {
					s.notifyInstanceListeners(instanceID, event)
					break
				}
			}
		}
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		if strings.EqualFold(rec.Status, "stopping") {
			http.Error(w, "instance stop is still finalizing", http.StatusConflict)
			return
		}
		if err := s.clearQueueStateDurable(instanceID); err != nil {
			log.Printf("[queue] exact stop persisted for %s but queue deletion failed: %v", instanceID, err)
			http.Error(w, "instance stopped but queue cleanup was not durable", http.StatusInternalServerError)
			return
		}
		// A successful exact stop is the same coherent durable aggregate served
		// by the snapshot endpoint, including final events and findings.
		finalizeScanRecordForResponse(rec)
		_ = json.NewEncoder(w).Encode(rec)
		return
	}

	inst, ok := s.resolveInstanceForAction(instanceID)

	// GET /api/instances/{id} — return instance details.
	if r.Method == http.MethodGet && (len(parts) == 1 || parts[1] == "") {
		if ok {
			// A stop/failure path can mark the instance terminal before the
			// active session has drained and persisted its final
			// events/findings. Do not expose that partial terminal snapshot;
			// callers retry and receive the coherent snapshot after the
			// runMultiScan defer clears the live session pointers.
			inst.mu.RLock()
			if isTerminalScanStatus(inst.Status) && inst.snapshotFinalizing {
				inst.mu.RUnlock()
				http.Error(w, "terminal instance snapshot is still finalizing", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(inst)
			inst.mu.RUnlock()
			return
		}

		// No live in-memory instance — serve only an exact persisted terminal
		// record. The payload keeps its immutable IDs unchanged so callers can
		// verify either the canonical record ID or external instance ID; unknown
		// short aliases remain 404/no-news.
		_, rec := s.findScanByID(instanceID)
		if rec == nil {
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}
		// Only serve terminal records. If the persisted record is somehow
		// non-terminal, do not expose it — return 404 so the SaaS treats it
		// as uncertainty and waits for the live instance to appear.
		if !isTerminalScanStatus(rec.Status) {
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}
		s.applyInstanceSnapshot(rec, false)
		s.attachWildcardSubScans(rec)
		finalizeScanRecordForResponse(rec)
		_ = json.NewEncoder(w).Encode(rec)
		return
	}

	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// POST /api/instances/{id}/stop — stop specific instance
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		inst.mu.Lock()
		// Queued scans are stoppable too, even before they acquire resources.
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			normalizeTerminalWildcardInstanceLocked(inst)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()

		// Drop the persisted resume file now so the dashboard's queue counter
		// clears immediately and the startup auto-resume never replays it. A
		// user stop is terminal (non-resumable); the runMultiScan defer also
		// clears it on exit, so this is just the prompt path (issue #239).
		s.clearQueueState(instanceID)

		// Broadcast stop to clients watching this instance
		s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Instance stopped by user"})
		// Broadcast update to dashboard clients
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

		inst.mu.RLock()
		stopResponse := struct {
			InstanceID  string           `json:"instance_id"`
			Status      string           `json:"status"`
			SubScans    []SubScanSummary `json:"sub_scans"`
			WorkStarted bool             `json:"work_started"`
		}{
			InstanceID:  inst.ID,
			Status:      inst.Status,
			SubScans:    cloneSubScanSummaries(inst.SubScans),
			WorkStarted: inst.WorkStarted,
		}
		inst.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(stopResponse)
		return
	}

	// POST /api/instances/{id}/restart — restart scan with same config
	if len(parts) >= 2 && parts[1] == "restart" && r.Method == http.MethodPost {
		// Avoid creating a duplicate scan against the same targets while this
		// instance is still active.
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus == "running" || currentStatus == "pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot restart: instance is still " + currentStatus,
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		instruction := inst.Instruction
		scanMode := inst.ScanMode
		severityFilter := inst.SeverityFilter
		discordWebhook := inst.DiscordWebhook
		phases := inst.Phases
		reconMode := inst.ReconMode
		scanIntensity := inst.ScanIntensity
		companyName := inst.CompanyName
		logoPath := inst.LogoPath
		instName := inst.Name
		targetAuth := inst.TargetAuth
		targetAuthB := inst.TargetAuthSecondary
		sourceRepo := inst.SourceRepo
		scanContext := inst.ScanContext
		inst.mu.RUnlock()

		// Build a new ScanRequest from stored config
		req := ScanRequest{
			Targets:             targets,
			Instruction:         instruction,
			ScanMode:            scanMode,
			SeverityFilter:      severityFilter,
			DiscordWebhook:      discordWebhook,
			Name:                instName,
			Phases:              phases,
			ReconMode:           reconMode,
			ScanIntensity:       scanIntensity,
			CompanyName:         companyName,
			LogoPath:            logoPath,
			TargetAuth:          targetAuth,
			TargetAuthSecondary: targetAuthB,
			SourceRepo:          sourceRepo,
			ScanContext:         scanContext,
		}

		scanCfg := *s.cfg // shallow copy
		go s.runMultiScan(req, &scanCfg)

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
		return
	}

	// POST /api/instances/{id}/start — start a saved scan, or start a new
	// run from an existing finished/stopped/failed scan's saved config.
	if len(parts) >= 2 && parts[1] == "start" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		if !canStartInstanceStatus(currentStatus) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot start: instance is " + currentStatus,
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		req := ScanRequest{
			Targets:             targets,
			Instruction:         inst.Instruction,
			ScanMode:            inst.ScanMode,
			SeverityFilter:      inst.SeverityFilter,
			DiscordWebhook:      inst.DiscordWebhook,
			Name:                inst.Name,
			Phases:              inst.Phases,
			ReconMode:           inst.ReconMode,
			ScanIntensity:       inst.ScanIntensity,
			CompanyName:         inst.CompanyName,
			LogoPath:            inst.LogoPath,
			TargetAuth:          inst.TargetAuth,
			TargetAuthSecondary: inst.TargetAuthSecondary,
			SourceRepo:          inst.SourceRepo,
			ScanContext:         inst.ScanContext,
		}
		inst.mu.RUnlock()

		if currentStatus == "saved" {
			// Remove the saved placeholder — runMultiScan creates a new
			// pending/running instance. Finished scans are kept so their
			// reports remain available while the new run starts separately.
			s.instancesMu.Lock()
			delete(s.instances, instanceID)
			s.instancesMu.Unlock()

			savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
			_ = os.RemoveAll(savedDir)
		}

		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": newID})
		return
	}

	// POST /api/instances/{id}/pause — gracefully pause a running scan
	if len(parts) >= 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		inst.mu.Lock()
		if inst.Status != "running" {
			inst.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot pause: instance is " + inst.Status,
			})
			return
		}
		inst.Status = "paused"
		inst.StopReason = "user_paused"
		if inst.cancel != nil {
			inst.cancel()
		}
		if inst.agent != nil {
			inst.agent.Stop()
		}
		inst.mu.Unlock()

		s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan paused by user"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		s.notifyAdmissionWake()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "paused", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/resume — resume a paused scan
	if len(parts) >= 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus != "paused" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: instance is " + currentStatus + ", expected paused",
			})
			return
		}

		req, ok, reason := s.scanRequestForPausedInstance(instanceID, inst)
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: " + reason,
			})
			return
		}

		// Remove the paused instance — a new one will be created by runMultiScan
		s.instancesMu.Lock()
		delete(s.instances, instanceID)
		s.instancesMu.Unlock()

		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastToInstance(instanceID, WSEvent{Type: "resumed", Content: "Scan resumed"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "instance_id": newID})
		return
	}

	// GET /api/instances/{id}/events — return buffered event history
	if len(parts) >= 2 && parts[1] == "events" && r.Method == http.MethodGet {
		inst.mu.RLock()
		events := make([]WSEvent, len(inst.events))
		copy(events, inst.events)
		inst.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(events)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// ────────────────────────────────────────────────────────
// scanSession — self-contained unit for a single scan run
// ────────────────────────────────────────────────────────

// scanSession isolates all per-scan state. Crashes in one session
// cannot corrupt server-level state or leak into subsequent scans.
type scanSession struct {
	id                 string
	target             string
	parentTarget       string // parent domain for subdomain scans (wildcard mode)
	scanDir            string
	cfg                *config.Config
	agent              *agent.Agent
	events             chan agent.Event
	record             *ScanRecord
	recordTokenOffset  int
	server             *Server
	instruction        string
	name               string
	userInstruction    string
	severityFilter     []string
	discordWebhook     string
	discoveryMode      bool
	genReport          bool
	resetState         bool
	instanceID         string               // parent instance ID for multi-instance tracking
	parentCtx          context.Context      // parent target context; canceled by exact stop
	scanMode           string               // single, wildcard, dast — persisted so dashboard shows correct mode
	sctx               *scanctx.ScanContext // per-session isolated state
	companyName        string               // report branding: company name
	logoPath           string               // report branding: logo path
	phases             []int                // selected methodology phases
	reconMode          string               // active or passive reconnaissance
	scanIntensity      string               // active or passive testing/scanning
	targetAuth         string               // per-scan authenticated-scanning material (see ScanRequest.TargetAuth)
	targetAuthB        string               // per-scan second account for IDOR/BOLA (see ScanRequest.TargetAuthSecondary)
	sourceRepo         string               // per-scan whitebox source repo/path (see ScanRequest.SourceRepo)
	scanContext        string               // per-scan attack-surface context path (see ScanRequest.ScanContext)
	codeScanMode       agent.CodeScanMode   // code-first scan mode (see ScanRequest.CodeScan)
	allowLoopbackPorts []int                // per-scan loopback allowlist for provision scans (scope-guard exemption)

	// llmClient, when non-nil, is a pre-built llm.Client carrying
	// a per-scan endpoint resolver derived from the originating
	// ScanRequest.ProviderProfile (B1). executeScanSession threads
	// it into agent.NewAgent via agent.WithLLMClient so the scan's
	// outbound traffic actually uses the operator's chosen
	// credentials. nil falls back to the agent's default
	// llm.NewClient(cfg) construction, preserving the prior
	// behavior for tests and CLI paths that have not opted in.
	llmClient *llm.Client

	// Wildcard lifecycle flags
	skipNotesCleanup     bool   // when true, don't delete notes store on cleanup (discovery phase)
	parentReportingCtxID string // stable context ID for accumulating vulns across wildcard subdomain scans

	// abortReason is set (via processEvent) when the agent emits a "finished"
	// event flagged as an abnormal LLM-side abort — refused to call tools,
	// empty responses, repeated errors, provider rate-limit exhaustion. When
	// set, the session finalizes the record as "failed" (not "finished") so a
	// force-stopped scan is never reported as a clean completion.
	abortReason string
}

// cleanup tears down all per-session resources. Every sub-operation
// has its own panic guard so cleanup NEVER panics upward.
func (sess *scanSession) cleanup() {
	// Stop the root and its scan-scoped delegation graph before closing tool
	// stores or persisting findings. Otherwise a late child can report after
	// the final merge, or access a terminal/browser context that cleanup has
	// already destroyed. The wait is bounded so a broken external process can
	// never stall server cleanup indefinitely.
	if sess.agent != nil {
		func() {
			defer logRecover("cleanup.agent.stop")
			sess.agent.Stop()
			if !sess.agent.WaitForDelegatedAgents(5 * time.Second) {
				log.Printf("[cleanup] delegated agents for session %s did not unwind within 5s", sess.id)
			}
		}()
	}

	// Deactivate and close the per-session ScanContext (if set).
	// Close() calls Terminal.KillAll() and Browser.Close() internally,
	// so no redundant calls are needed below.
	if sess.sctx != nil {
		func() {
			defer logRecover("cleanup.scanctx.close")
			scanctx.Deactivate(sess.sctx.ID)
			sess.sctx.Close()
		}()
	}

	// Clean up tool-level context stores to prevent unbounded memory growth.
	// Each tool package maintains a map[contextID]→store that must be cleared.
	if sess.sctx != nil {
		// Panic-safe persistence (Property 4 / spec
		// findings-consistency-and-pagination Wave C 4.2): persist
		// any in-memory vulns reported via report_vulnerability into
		// the on-disk scan record, and merge this child session's
		// vulns into the parent reporting context, BEFORE we delete
		// the in-memory reporting store via CleanupContext below.
		//
		// Each merge runs in its own safe.Recover boundary so a
		// panic in one branch does not skip the other. Both merges
		// are idempotent (mergeReportedVulnerabilitiesIntoRecord
		// dedups via appendVulnSummaryUnique keyed on
		// title|target|endpoint|method|CVE; MergeVulnsToContext
		// skips ID duplicates and semantic duplicates), so even when
		// the success path has already saved a partial record this
		// deferred call is a no-op for vulns it has already
		// persisted.
		func() {
			defer safe.Recover("cleanup.scanrecord.merge", sess.sctx.ID)
			if sess.record == nil {
				return
			}
			before := len(sess.record.Vulns)
			mergeReportedVulnerabilitiesIntoRecord(sess.record, reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
			if added := len(sess.record.Vulns) - before; added > 0 {
				log.Printf("[cleanup] Persisted %d in-memory vulns into scan.json for session %s", added, sess.sctx.ID)
			}
			sess.server.saveScanRecordTo(sess.record, sess.scanDir)
			// The exact instance endpoint must carry every persisted finding,
			// including findings hidden from live broadcasts by severity filters.
			// This runs before runMultiScan publishes its terminal snapshot.
			sess.server.mirrorPersistedSessionVulnerabilities(sess.instanceID, sess.record.Vulns)
		}()

		// Wildcard vuln accumulation: merge this session's vulns into
		// the parent reporting context BEFORE we delete this session's
		// reporting store.
		if sess.parentReportingCtxID != "" {
			func() {
				defer safe.Recover("cleanup.reporting.merge", sess.sctx.ID)
				merged := reporting.MergeVulnsToContext(sess.sctx.ID, sess.parentReportingCtxID)
				if merged > 0 {
					log.Printf("[wildcard] Merged %d vulns from session %s into parent context %s", merged, sess.sctx.ID, sess.parentReportingCtxID)
				}
			}()
		}

		func() {
			defer logRecover("cleanup.reporting.cleanup")
			reporting.CleanupContext(sess.sctx.ID)
		}()
		if !sess.skipNotesCleanup {
			func() {
				defer logRecover("cleanup.notes.cleanup")
				notes.CleanupContext(sess.sctx.ID)
			}()
		} else {
			log.Printf("[wildcard] Skipping notes cleanup for discovery session %s (notes preserved for subdomain collection)", sess.sctx.ID)
		}
		func() {
			defer logRecover("cleanup.terminal.cleanup")
			terminal.CleanupContext(sess.sctx.ID)
		}()
		func() {
			defer logRecover("cleanup.browser.cleanup")
			browser.CleanupContext(sess.sctx.ID)
		}()
	}

	// Fallback process kill if sctx was never initialized
	if sess.sctx == nil {
		func() {
			defer logRecover("cleanup.terminal.killAll")
			terminal.KillAllProcesses()
		}()
	}

	// Clear terminal working directory to prevent stale workdir leaking to next session
	func() {
		defer logRecover("cleanup.terminal.setWorkDir")
		if sess.sctx != nil && sess.sctx.Terminal != nil {
			sess.sctx.Terminal.SetWorkDir("")
		} else {
			terminal.SetWorkDir("") // fallback if sctx not initialized
		}
	}()

	// Clear server references under lock
	sess.server.mu.Lock()
	delete(sess.server.currentAgents, sess.id)
	sess.server.mu.Unlock()
}

var fallbackSlugCounter atomic.Uint64

// randomSlug generates a 128-bit hex identifier. The fallback preserves the
// same width and process-local uniqueness if the kernel CSPRNG is unavailable.
func randomSlug() string {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		counter := fallbackSlugCounter.Add(1)
		log.Printf("Warning: crypto/rand failed, falling back to hashed process identity: %v", err)
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d", os.Getpid(), time.Now().UnixNano(), counter)))
		return hex.EncodeToString(sum[:16])
	}
	return hex.EncodeToString(b)
}

// sanitizeTarget creates a safe directory name from a target URL/domain.
func sanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	clean := re.ReplaceAllString(target, "_")
	clean = strings.TrimPrefix(clean, "https___")
	clean = strings.TrimPrefix(clean, "http___")
	clean = strings.Trim(clean, "_")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return clean
}

// saveScanRecordTo saves a scan record to a specific directory.
func (s *Server) saveScanRecordTo(rec *ScanRecord, scanDir string) {
	if scanDir == "" {
		return
	}

	// Check disk space before writing (50MB minimum)
	if avail := diskAvailable(scanDir); avail > 0 && avail < 50*1024*1024 {
		log.Printf("Warning: low disk space (%d MB available), scan record may fail to save", avail/1024/1024)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Low disk space: %d MB remaining. Scan data may not be saved.", avail/1024/1024)})
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal scan record: %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(scanDir, "scan.json"), data, 0600); err != nil {
		log.Printf("Error: failed to save scan record to %s: %v", scanDir, err)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Failed to save scan data: %v", err)})
		return
	}
	// Refresh the detail sidecar (metadata + event tail) so GET /api/scans/{id}
	// stays instant regardless of how large the event log grows. Best-effort and
	// written after scan.json so a reader never sees a sidecar newer than its
	// source (readScanDetailMeta treats a stale sidecar as absent).
	writeScanDetailMeta(scanDir, rec)
}

// diskAvailable returns available bytes on the filesystem containing path, or 0 on error.
func diskAvailable(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize) //nolint:gosec // G115: filesystem block size is small and non-negative
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	// Normalise: strip any path separators so a crafted /api/report/../etc/passwd
	// can never escape the scan-dir even if a future caller forgets.
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == "/" {
		http.Error(w, "scan ID required", http.StatusBadRequest)
		return
	}

	scanDir, rec := s.findScanByID(scanID)
	if scanDir == "" || rec == nil {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if inst != nil {
			rec = s.scanRecordFromInstance(inst)
			inst.mu.RLock()
			scanDir = inst.scanDir
			inst.mu.RUnlock()
		}
		if scanDir == "" || rec == nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
	}

	reportPath, err := s.generateReportAt(rec, scanDir)
	if err != nil {
		log.Printf("Report generation error: %v", err)
		fallbackPath := filepath.Join(scanDir, fmt.Sprintf("xalgorix_report_%s.pdf", scanID))
		if info, statErr := os.Stat(fallbackPath); statErr == nil && info.Mode().IsRegular() {
			reportPath = fallbackPath
		} else {
			http.Error(w, "failed to generate report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Defense-in-depth: confirm the resolved target is a regular file before
	// handing it to http.ServeFile. ServeFile will happily render a directory
	// index if asked for a directory.
	info, err := os.Stat(reportPath)
	if err != nil {
		log.Printf("Report stat failed for %s: %v", reportPath, err)
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("Report path is not a regular file: %s (mode=%s)", reportPath, info.Mode())
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.pdf\"", scanID))
	http.ServeFile(w, r, reportPath)
}

// handleRateLimit handles GET and POST for rate limit settings.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current rate limit settings
		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	case "POST":
		// Update rate limit settings
		var req struct {
			Requests int `json:"requests"`
			Window   int `json:"window"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Validate values
		if req.Requests < 1 {
			req.Requests = 1
		}
		if req.Requests > 1000 {
			req.Requests = 1000
		}
		if req.Window < 10 {
			req.Window = 10
		}
		if req.Window > 3600 {
			req.Window = 3600
		}

		if _, err := s.applyEnvironmentUpdates(map[string]string{
			"XALGORIX_RATE_LIMIT_REQUESTS": strconv.Itoa(req.Requests),
			"XALGORIX_RATE_LIMIT_WINDOW":   strconv.Itoa(req.Window),
		}); err != nil {
			log.Printf("Failed to save rate limit settings: %v", err)
			http.Error(w, "failed to save rate limit settings", http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func maskAgentMailKey(apiKey string) string {
	if len(apiKey) > 8 {
		return "****" + apiKey[len(apiKey)-8:]
	}
	if apiKey != "" {
		return "****"
	}
	return ""
}

func isMaskedAgentMailKey(apiKey string) bool {
	apiKey = strings.TrimSpace(apiKey)
	return strings.HasPrefix(apiKey, "****") || strings.Contains(apiKey, "••••")
}

// handleAgentMailSettings handles GET and POST for AgentMail settings.
func (s *Server) handleAgentMailSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current AgentMail settings (without exposing the full API key)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pod":       s.cfg.AgentMailPod,
			"apiKey":    maskAgentMailKey(s.cfg.AgentMailAPIKey),
			"hasApiKey": s.cfg.AgentMailAPIKey != "",
		})

	case "POST":
		// Update AgentMail settings
		var req struct {
			Pod    string `json:"pod"`
			APIKey string `json:"apiKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		preserveKey := strings.TrimSpace(req.APIKey) == "" || isMaskedAgentMailKey(req.APIKey)
		effectiveAPIKey := req.APIKey
		if preserveKey {
			effectiveAPIKey = s.cfg.AgentMailAPIKey
		}

		updates := map[string]string{"AGENTMAIL_POD": req.Pod}
		if !preserveKey {
			updates["AGENTMAIL_API_KEY"] = effectiveAPIKey
		}
		if _, err := s.applyEnvironmentUpdates(updates); err != nil {
			log.Printf("Failed to save AgentMail settings: %v", err)
			http.Error(w, "failed to save AgentMail settings", http.StatusInternalServerError)
			return
		}

		log.Printf("AgentMail settings updated: pod=%s", req.Pod)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"pod":       req.Pod,
			"apiKey":    maskAgentMailKey(effectiveAPIKey),
			"hasApiKey": effectiveAPIKey != "",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": Version,
		"ai": map[string]any{
			"configured": s.cfg.APIKey != "" && s.cfg.LLM != "",
			"provider":   llmProviderLabel(s.cfg.LLM, s.cfg.APIBase),
			"model":      s.cfg.LLM,
			"gateway":    llmGatewayName(s.cfg.LLM, s.cfg.APIBase),
		},
	})
}

// handleStopNotify sends a stop notification to Discord if a scan was running
func (s *Server) handleStopNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Send Discord notification if webhook is configured
	if s.discordWebhook != "" {
		s.sendDiscord(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "notified"})
}

// handleQueueStatus returns the current queue state for recovery
func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	entries := s.validQueueStateEntries(true)
	if len(entries) > 0 {
		state := entries[0].state
		totalRemaining := 0
		for _, entry := range entries {
			totalRemaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"available":                 true,
			"queue_count":               len(entries),
			"total_remaining":           totalRemaining,
			"instance_id":               state.InstanceID,
			"targets":                   state.Targets,
			"current_idx":               state.CurrentIdx,
			"remaining":                 len(state.Targets) - state.CurrentIdx,
			"instruction":               state.Instruction,
			"scan_mode":                 state.ScanMode,
			"started_at":                state.StartedAt,
			"paused":                    state.Paused,
			"name":                      state.Name,
			"severity_filter":           state.SeverityFilter,
			"phases":                    state.Phases,
			"recon_mode":                normalizeActivityMode(state.ReconMode),
			"scan_intensity":            normalizeActivityMode(state.ScanIntensity),
			"company_name":              state.CompanyName,
			"logo_path":                 state.LogoPath,
			"active_target":             state.ActiveTarget,
			"active_scan_id":            state.ActiveScanID,
			"wildcard_active_target":    state.WildcardActiveTarget,
			"wildcard_active_scan_id":   state.WildcardActiveScanID,
			"wildcard_sub_index":        state.WildcardSubIndex,
			"wildcard_subdomains_total": len(state.WildcardSubdomains),
		})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()

	if s.running.Load() || s.hasPendingOrRunningInstance() || s.hasQueueResumeLaunchingLocked() {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already pending or running"})
		return
	}

	entries := s.validQueueStateEntries(true)
	if len(entries) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "No interrupted queue found"})
		return
	}

	totalRemaining := 0
	firstIdx := entries[0].state.CurrentIdx
	for _, entry := range entries {
		req := scanRequestFromQueueState(entry.state, entry.path)
		if len(req.Targets) == 0 {
			continue
		}
		totalRemaining += len(req.Targets)
		scanCfg := *s.cfg
		instanceID := entry.state.InstanceID
		resumeKey := queueResumeEntryKey(entry)
		s.markQueueResumeLaunchingLocked(resumeKey)
		go func(req ScanRequest, scanCfg config.Config, instanceID, resumeKey string) {
			defer s.clearQueueResumeLaunching(resumeKey)
			s.runMultiScan(req, &scanCfg, instanceID)
		}(req, scanCfg, instanceID, resumeKey)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "resumed",
		"resumed_queues": len(entries),
		"from_index":     firstIdx,
		"targets_left":   totalRemaining,
	})
}

// handleQueueClear clears an interrupted queue state
func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.clearQueueState()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleGetScan returns a specific scan's full data.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL: /api/scans/{id}
	scanID := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if scanID == "" || scanID == "latest" {
		// Find the latest top-level scan by StartedAt using the events-free
		// summaries (cheap), then load only that one record with an event tail.
		summaries := []scanEntry{}
		for _, entry := range s.findAllScanSummaries() {
			if entry.rec.ParentTarget != "" {
				continue
			}
			summaries = append(summaries, entry)
		}
		if len(summaries) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		sort.Slice(summaries, func(i, j int) bool {
			return summaries[i].rec.StartedAt > summaries[j].rec.StartedAt
		})
		rec, ok := s.loadScanRecordForDetail(summaries[0].dir, detailEventTail)
		if !ok || rec == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		s.applyInstanceSnapshot(rec, true)
		s.attachWildcardSubScans(rec)
		finalizeScanRecordForResponse(rec)
		finalizeEventsMeta(rec)
		s.markDiscordWebhookConfigured(rec)
		s.markTelegramConfigured(rec)
		data, _ := json.Marshal(rec)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	// DELETE /api/scans/{id} — delete scan from disk and in-memory instances
	// Handle this BEFORE findScanByID because instance IDs (from runMultiScan)
	// may differ from scan record IDs (directory slugs). We need to clean up both.
	if r.Method == http.MethodDelete {
		// Try to find and delete from disk
		dir, rec := s.findScanByID(scanID)
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
		if rec != nil {
			for _, entry := range s.findAllScans() {
				if entry.dir == dir {
					continue
				}
				if isChildOfScan(rec, &entry.rec) {
					_ = os.RemoveAll(entry.dir)
				}
			}
		}
		instanceIDs := []string{scanID}
		if rec != nil {
			instanceIDs = append(instanceIDs, rec.ID, rec.InstanceID)
		}
		seenInstanceIDs := make(map[string]bool, len(instanceIDs))
		s.instancesMu.Lock()
		for _, id := range instanceIDs {
			if id == "" || seenInstanceIDs[id] {
				continue
			}
			seenInstanceIDs[id] = true
			// Deleting a scan must HALT it, not just drop the map entry. Mark
			// the instance stopped (so runMultiScan's queue loop breaks on its
			// captured pointer), cancel the in-flight target's context, and
			// stop the agent so the current LLM/tool loop aborts immediately.
			// Without this the queue kept scanning in the background and
			// consuming tokens after deletion (issue #239).
			if inst := s.instances[id]; inst != nil {
				inst.mu.Lock()
				if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
					inst.Status = "stopped"
					inst.StopReason = "user_deleted"
					inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
					normalizeTerminalWildcardInstanceLocked(inst)
				}
				if inst.cancel != nil {
					inst.cancel()
				}
				if inst.agent != nil {
					inst.agent.Stop()
				}
				inst.mu.Unlock()
			}
			// Remove the persisted resume file so the startup auto-resume
			// goroutine never replays this queue (previously the only fix was
			// wiping the whole .xalgorix data dir).
			s.clearQueueState(id)
			delete(s.instances, id)
		}
		s.instancesMu.Unlock()
		s.invalidateScanListCache()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	if r.Method == http.MethodGet {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if rec := s.scanRecordFromInstance(inst); rec != nil {
			if dir, ok := s.resolveScanDirByID(scanID); ok {
				if persisted, ok2 := s.loadScanRecordForDetail(dir, detailEventTail); ok2 && persisted != nil {
					s.applyInstanceSnapshot(persisted, true)
					s.attachWildcardSubScans(persisted)
					finalizeScanRecordForResponse(persisted)
					finalizeEventsMeta(persisted)
					s.markDiscordWebhookConfigured(persisted)
					s.markTelegramConfigured(persisted)
					data, _ := json.Marshal(persisted)
					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
					return
				}
			}
			s.attachWildcardSubScans(rec)
			finalizeScanRecordForResponse(rec)
			finalizeEventsMeta(rec)
			s.markDiscordWebhookConfigured(rec)
			s.markTelegramConfigured(rec)
			data, _ := json.Marshal(rec)
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
	}

	dir, ok := s.resolveScanDirByID(scanID)
	if !ok {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	rec, ok := s.loadScanRecordForDetail(dir, detailEventTail)
	if !ok || rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	s.applyInstanceSnapshot(rec, true)
	s.attachWildcardSubScans(rec)
	finalizeScanRecordForResponse(rec)
	finalizeEventsMeta(rec)
	s.markDiscordWebhookConfigured(rec)
	s.markTelegramConfigured(rec)
	data, _ := json.Marshal(rec)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// finalizeEventsMeta keeps the events pagination hints coherent after other
// layers (applyInstanceSnapshot) may have swapped in a live event buffer.
// EventsTotal never claims fewer than the events actually shown, and Truncated
// is only set when older events genuinely remain to be paged.
func finalizeEventsMeta(rec *ScanRecord) {
	if rec == nil {
		return
	}
	if rec.EventsTotal < len(rec.Events) {
		rec.EventsTotal = len(rec.Events)
	}
	rec.EventsTruncated = rec.EventsTotal > len(rec.Events)
}

// handleScanEvents serves a page of a scan's event log:
// GET /api/scans/{id}/events?offset=&limit=  →  {events, total, offset, limit}
func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/events")
	dir, ok := s.resolveScanDirByID(scanID)
	if !ok {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	offset := 0
	limit := detailEventTail
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, total, ok := loadScanEventsWindow(dir, offset, limit)
	if !ok {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if events == nil {
		events = []WSEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events": events,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

// handleDeleteVuln removes a single vulnerability from a scan record.
// DELETE /api/scans/{scanId}/vulns/{vulnId}
func (s *Server) handleDeleteVuln(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	// Parse: /api/scans/{scanId}/vulns/{vulnId}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	parts := strings.SplitN(trimmed, "/vulns/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path: expected /api/scans/{id}/vulns/{id}", http.StatusBadRequest)
		return
	}
	scanID := parts[0]
	vulnID, err := url.PathUnescape(parts[1])
	if err != nil {
		http.Error(w, "invalid vuln id encoding", http.StatusBadRequest)
		return
	}

	dir, rec := s.findScanByID(scanID)
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"scan not found"}`))
		return
	}

	// Remove matching vulns
	filtered := make([]VulnSummary, 0, len(rec.Vulns))
	removed := 0
	for _, v := range rec.Vulns {
		if v.ID == vulnID {
			removed++
			continue
		}
		filtered = append(filtered, v)
	}
	if removed == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"vulnerability not found"}`))
		return
	}
	rec.Vulns = filtered

	// Persist to disk
	if dir != "" {
		s.saveScanRecordTo(rec, dir)
	}

	// Update in-memory instance if present
	s.instancesMu.Lock()
	if inst := s.instances[scanID]; inst != nil {
		inst.mu.Lock()
		inst.Vulns = filtered
		inst.VulnCount = len(filtered)
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "removed": removed, "remaining": len(filtered)})
}

// logMemStats logs current memory usage and goroutine count.
// Called between subdomain scans to track memory growth and detect leaks.
func logMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("[MEM] %s — HeapAlloc: %d MB, HeapInuse: %d MB, Sys: %d MB, NumGC: %d, Goroutines: %d",
		label,
		m.HeapAlloc/1024/1024,
		m.HeapInuse/1024/1024,
		m.Sys/1024/1024,
		m.NumGC,
		runtime.NumGoroutine(),
	)
}

func llmProviderLabel(model, apiBase string) string {
	provider := llmProviderKey(model, apiBase)
	switch provider {
	case "vercel":
		return "Vercel AI Gateway"
	case "minimax":
		return "MiniMax"
	case "openai":
		return "OpenAI"
	case "anthropic":
		return "Anthropic"
	case "google", "gemini":
		return "Google Gemini"
	case "deepseek":
		return "DeepSeek"
	case "groq":
		return "Groq"
	case "ollama":
		return "Ollama"
	case "zai":
		return "Z.AI"
	case "zai-coding-plan":
		return "Z.AI Coding Plan"
	case "":
		return "Not configured"
	default:
		return strings.ToUpper(provider[:1]) + provider[1:]
	}
}

func llmGatewayName(model, apiBase string) string {
	if llmProviderKey(model, apiBase) == "vercel" {
		return "vercel"
	}
	return ""
}

func llmProviderKey(model, apiBase string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	apiBase = strings.ToLower(strings.TrimSpace(apiBase))
	if strings.Contains(apiBase, "vercel") || strings.HasPrefix(model, "vercel/") {
		return "vercel"
	}
	if idx := strings.Index(model, "/"); idx > 0 {
		return model[:idx]
	}
	switch {
	case strings.Contains(apiBase, "minimax"):
		return "minimax"
	case strings.Contains(apiBase, "anthropic"):
		return "anthropic"
	case strings.Contains(apiBase, "generativelanguage") || strings.Contains(apiBase, "googleapis"):
		return "google"
	case strings.Contains(apiBase, "deepseek"):
		return "deepseek"
	case strings.Contains(apiBase, "groq"):
		return "groq"
	case strings.Contains(apiBase, "openai"):
		return "openai"
	case strings.Contains(apiBase, "ollama") || strings.Contains(apiBase, "localhost:11434"):
		return "ollama"
	case strings.Contains(apiBase, "api.z.ai/api/coding/"):
		return "zai-coding-plan"
	case strings.Contains(apiBase, "api.z.ai"):
		return "zai"
	case model != "":
		return model
	default:
		return ""
	}
}

// startCaidoProxy launches Caido proxy in background if it's installed and not already running.
func startCaidoProxy() {
	cfg := config.Get()
	port := cfg.CaidoPort
	if port == 0 {
		port = 8080
	}

	// Check if something is already listening on the Caido port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err == nil {
		_ = conn.Close()
		log.Printf("Caido proxy already running on port %d", port)
		return
	}

	// Check if caido binary exists
	caidoPath, err := exec.LookPath("caido")
	if err != nil {
		log.Printf("Caido not installed — proxy features will use direct HTTP (install from https://caido.io)")
		return
	}

	// Start Caido in background with --no-open (headless)
	cmd := exec.Command(caidoPath, "--no-open", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start Caido proxy: %v", err)
		return
	}

	// Don't wait for the process — let it run in background
	go func() {
		_ = cmd.Wait() // Reap zombie process
	}()

	log.Printf("✅ Caido proxy started on port %d (PID: %d)", port, cmd.Process.Pid)
}
