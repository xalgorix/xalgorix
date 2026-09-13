// Package browser provides browser automation tools via go-rod/rod.
package browser

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/v4/internal/config"
	egressproxy "github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// browserCacheDir is the on-disk root for every browser cache, extension
// extraction, and downloaded Chromium binary. Per Task 8.5 this lives under
// ~/.xalgorix/browser/ so the default policy roots admit it without any
// per-scan workspace trickery.
func browserCacheDir() string {
	return filepath.Join(config.Get().HomeDir, "browser")
}

// resolveBrowserPath canonicalizes path through Path_Policy with the
// "browser" tool name, using the active Scan_Context for ctxID when one
// exists. Every browser write (download cache, extension extraction,
// session persistence) flows through this helper so the Allow_List
// boundary is enforced uniformly (R8.5).
func resolveBrowserPath(ctxID, path string) (string, error) {
	sc := scanctx.Get(ctxID)
	return sandbox.Default().CheckResolve(sc, "browser", path)
}

// scanContextForCtx returns the active Scan_Context for ctxID, falling
// back to scanctx.Default() so callers always have a lease holder.
func scanContextForCtx(ctxID string) *scanctx.ScanContext {
	if sc := scanctx.Get(ctxID); sc != nil {
		return sc
	}
	return scanctx.Default()
}

// ── Per-instance browser stores ──
var (
	browserStores   = make(map[string]*browserStore)
	browserStoresMu sync.RWMutex
)

type browserStore struct {
	mu              sync.Mutex
	browser         *rod.Browser
	browserLauncher *launcher.Launcher
	requiredProxy   bool
	lease           *resources.ToolLease
	page            *rod.Page
	pages           map[string]*rod.Page
	nextTab         int
	currentTab      string
	savedSessions   map[string][]*proto.NetworkCookie // keyed by session name
	sessionDir      string                            // base directory for session files
}

// getBrowserStoreByID returns the browser store for a specific context ID.
// Creates a new store if one doesn't exist (double-checked locking).
func getBrowserStoreByID(id string) *browserStore {
	browserStoresMu.RLock()
	s, ok := browserStores[id]
	browserStoresMu.RUnlock()
	if ok {
		return s
	}

	browserStoresMu.Lock()
	defer browserStoresMu.Unlock()
	if s, ok := browserStores[id]; ok {
		return s
	}
	s = &browserStore{
		pages:         make(map[string]*rod.Page),
		nextTab:       1,
		savedSessions: make(map[string][]*proto.NetworkCookie),
	}
	browserStores[id] = s
	return s
}

// savedCookieEntry is a JSON-serializable cookie for disk persistence.
type savedCookieEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
}

// SetSessionPath configures where session files are saved on disk.
func SetSessionPath(dir string) {
	SetSessionPathForCtx(scanctx.Default().ID, dir)
}

// SetSessionPathForCtx configures the session directory for a specific context.
func SetSessionPathForCtx(ctxID, dir string) {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionDir = dir
}

// sanitizeSessionName strips path separators and dots to prevent directory traversal.
func sanitizeSessionName(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '.' || r == 0 {
			return '_'
		}
		return r
	}, name)
}

// sessionFilePath returns the disk path for a named session file.
func sessionFilePath(dir, name string) string {
	if dir == "" {
		return ""
	}
	if name == "" || name == "default" {
		return filepath.Join(dir, "session.json")
	}
	safe := sanitizeSessionName(name)
	return filepath.Join(dir, safe+"_session.json")
}

// GetCurrentPage returns the currently active page, or nil if the browser
// is not launched.
func GetCurrentPage() *rod.Page {
	return GetCurrentPageForCtx(scanctx.Default().ID)
}

// GetCurrentPageForCtx returns the page for a specific context.
func GetCurrentPageForCtx(ctxID string) *rod.Page {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.page
}

// GetBrowser returns the active browser instance, or nil.
func GetBrowser() *rod.Browser {
	return GetBrowserForCtx(scanctx.Default().ID)
}

// GetBrowserForCtx returns the browser for a specific context.
func GetBrowserForCtx(ctxID string) *rod.Browser {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browser
}

// CleanupContext closes the browser and removes the store for a deactivated context.
// This kills the underlying Chromium process to prevent orphaned processes.
func CleanupContext(contextID string) {
	browserStoresMu.Lock()
	defer browserStoresMu.Unlock()
	if s, ok := browserStores[contextID]; ok {
		s.mu.Lock()
		cleanupBrowserLocked(contextID, s)
		s.mu.Unlock()
		delete(browserStores, contextID)
	}
}

// Register adds browser tools to the registry.
// The registry is captured in the closure so tool execution resolves the correct
// per-session browser store via registry.GetScanContextID().
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "browser_action",
		Description: `Control a headless Chromium browser for web interaction, login flows, and security testing.

ACTIONS:
  launch       — Start browser and optionally navigate to URL
  goto         — Navigate to a URL (waits for page load)
  snapshot     — Get interactive element tree with semantic IDs (@e1, @e2...) for clicking/typing
  click        — Click an element by CSS selector or @eX ID from snapshot
  type         — Type text into an input field
  submit       — Submit a form (click submit button or press Enter on a field)
  scroll       — Scroll page up or down
  screenshot   — Capture full-page PNG screenshot
  get_html     — Get raw HTML of page or specific element
  execute_js   — Run arbitrary JavaScript (e.g., document.cookie)
  get_cookies  — Get all cookies for the current domain
  set_cookie   — Set a cookie (name, value, domain)
  save_session — Save current cookies under a session name (default: "default")
  load_session — Restore cookies from a named session (default: "default")
  list_sessions— List all saved session names
  wait         — Wait for a selector to appear or for navigation
  select       — Select an option from a dropdown
  fill_form    — Auto-fill a form: provide field=value pairs
  get_url      — Get current page URL
  iframe       — Switch into an iframe by selector/index
  main_frame   — Switch back to main page frame from iframe
  extract_links— Extract all links from the page (useful for verification emails)
  new_tab      — Open a new browser tab
  switch_tab   — Switch between tabs
  close        — Close browser
  verify_xss   — CONFIRM an XSS payload actually executes in the browser (proof of execution, not reflection). Point it at a payload that emits a unique nonce and pass nonce=<that value>; confirmed only if the nonce is observed executing. Three oracles are accepted: a JS dialog (alert/confirm/prompt('XV-8f3a')), a console call (console.log('XV-8f3a')) — useful when a filter strips alert — or a DOM marker (document.title='XV-8f3a' or window.name='XV-8f3a') for DOM-only sinks. GET (default): pass url=<URL carrying the payload>. POST-reflected XSS: pass url=<form action> plus data=<urlencoded body, e.g. search=<payload>> (method defaults to POST when data is set) — this performs a real form POST and confirms in ONE call, so do NOT hand-build form submissions with browser_action. Use before reporting XSS.

SIGNUP/LOGIN WORKFLOW:
  1. launch url=https://target.com/signup
  2. snapshot → identify form fields
  3. type selector=@e3 text=testuser123
  4. type selector=@e5 text=user@agentmail.to (from agentmail create_inbox)
  5. type selector=@e7 text=SecureP@ss123!
  6. click selector=@e9 (submit button)
  7. wait selector=".success" OR wait type=navigation
  8. Use agentmail wait_for_email to get verification link
  9. goto url=VERIFICATION_LINK
  10. get_cookies → save session tokens for authenticated testing`,
		Parameters: []tools.Parameter{
			{Name: "command", Description: "Browser action (see list above)", Required: true},
			{Name: "url", Description: "URL to navigate to (for launch/goto)", Required: false},
			{Name: "selector", Description: "CSS selector or semantic @eX ID from snapshot (for click/type/submit/wait/iframe/get_html/select)", Required: false},
			{Name: "text", Description: "Text to type (for type), option value (for select), or cookie value (for set_cookie)", Required: false},
			{Name: "code", Description: "JavaScript code to execute (for execute_js)", Required: false},
			{Name: "nonce", Description: "Unique marker your XSS payload emits (for verify_xss) via a dialog (alert/confirm/prompt), console.log(), or a DOM marker (document.title / window.name). Execution is confirmed only if this nonce is observed executing.", Required: false},
			{Name: "parameter", Description: "The injected parameter under test (for verify_xss), used to label the ledger hypothesis.", Required: false},
			{Name: "data", Description: "Request body for POST-based verify_xss: a urlencoded form body like search=<payload>&x=1 (values are decoded once, then the browser re-encodes them at submit). Providing data makes verify_xss submit a real form POST to url and confirm POST-reflected XSS in one call.", Required: false},
			{Name: "method", Description: "HTTP method for verify_xss: GET (default) navigates to url; POST (default when data is set) submits url as a form POST with body=data. Use POST for reflected XSS that only triggers on form submission.", Required: false},
			{Name: "direction", Description: "Scroll direction: up or down (for scroll)", Required: false},
			{Name: "tab_id", Description: "Tab ID (for switch_tab)", Required: false},
			{Name: "proxy", Description: "Proxy: 'caido', 'none', or proxy URL", Required: false},
			{Name: "name", Description: "Cookie name (for set_cookie)", Required: false},
			{Name: "domain", Description: "Cookie domain (for set_cookie)", Required: false},
			{Name: "timeout", Description: "Timeout in seconds for wait actions (default: 10)", Required: false},
			{Name: "fields", Description: "Form fields as key=value pairs separated by | (for fill_form). Example: email=test@mail.com|password=Pass123|name=John", Required: false},
			{Name: "session_name", Description: "Session name for save_session/load_session (default: 'default'). Use distinct names for multi-account IDOR testing, e.g. 'admin', 'user_a'.", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return browserActionForRegistry(r, args)
		},
	})
}

// detectCaidoPort detects the Caido proxy port.
func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}
	return 8080
}

// Embedded extension files extracted at launch time.
//
//go:embed extension/*
var extensionFS embed.FS

// wellKnownBrowserPaths lists absolute paths to probe when neither
// XALGORIX_BROWSER_PATH nor rod's launcher.LookPath locate a browser. It exists
// because rod's LookPath name list misses some real installs — most notably
// Google Chrome at /opt/google/chrome/chrome (commonly symlinked as
// /usr/bin/chrome). Without these entries a host whose only browser is Google
// Chrome falls through to rod's ~170MB Chromium auto-download (which then often
// fails offline), so verify_xss and every browser-backed check silently break.
func wellKnownBrowserPaths() []string {
	return []string{
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/google-chrome",
		"/usr/bin/chrome",           // Google Chrome (common symlink)
		"/opt/google/chrome/chrome", // Google Chrome default install location
		"/snap/bin/chromium",
	}
}

// getChromiumPath returns the path to a Chromium binary.
// Priority: 1) XALGORIX_BROWSER_PATH env  2) System-installed browser  3) Rod auto-download (~170MB first run)
func getChromiumPath(ctxID string) (string, error) {
	// 1. User override via config
	if p := config.Get().BrowserPath; p != "" {
		if _, err := os.Stat(p); err == nil {
			log.Printf("[browser] Using custom browser path: %s", p)
			return p, nil
		}
		return "", fmt.Errorf("XALGORIX_BROWSER_PATH set to %q but file not found", p)
	}

	// 2. System-installed browser (chromium, google-chrome, etc.)
	// This is the most reliable method — avoids Rod's auto-download which
	// frequently breaks when Chromium snapshot URLs change or are unreachable.
	if sysPath, found := launcher.LookPath(); found {
		log.Printf("[browser] Using system-installed browser: %s", sysPath)
		return sysPath, nil
	}

	// 3. Well-known browser paths (fallback for systems where LookPath misses)
	for _, p := range wellKnownBrowserPaths() {
		if _, err := os.Stat(p); err == nil {
			log.Printf("[browser] Using browser found at well-known path: %s", p)
			return p, nil
		}
	}

	// 4. Auto-download via Rod's built-in browser manager (last resort)
	rawCacheDir := browserCacheDir()
	cacheDir, err := resolveBrowserPath(ctxID, rawCacheDir)
	if err != nil {
		return "", fmt.Errorf("browser cache dir rejected by path policy: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create browser cache dir: %w", err)
	}

	log.Printf("[browser] No system browser found, downloading Chromium to %s (first run)", cacheDir)
	b := launcher.NewBrowser()
	b.RootDir = cacheDir
	path, err := b.Get()
	if err != nil {
		return "", fmt.Errorf("failed to get/download Chromium: %w\n\nFix: install a browser on your system:\n  Debian/Ubuntu: sudo apt install chromium-browser\n  Alpine:        apk add chromium\n  Or set XALGORIX_BROWSER_PATH=/path/to/chrome", err)
	}

	log.Printf("[browser] Chromium ready at: %s", path)
	return path, nil
}

// extractExtension writes the embedded extension files to disk so Chrome
// can load them via --load-extension. Returns the extension directory path.
// Files are only re-written if the directory doesn't exist or manifest changed.
//
// Per Task 8.5 the extension lives under the browser cache root
// (~/.xalgorix/browser/extension) and every write is canonicalized through
// sandbox.Default().CheckResolve with the "browser" tool name so the
// Path_Policy Allow_List always admits it.
func extractExtension(ctxID string) (string, error) {
	rawExtDir := filepath.Join(browserCacheDir(), "extension")
	extDir, err := resolveBrowserPath(ctxID, rawExtDir)
	if err != nil {
		return "", fmt.Errorf("extension dir rejected by path policy: %w", err)
	}
	rawManifestPath := filepath.Join(extDir, "manifest.json")
	manifestPath, err := resolveBrowserPath(ctxID, rawManifestPath)
	if err != nil {
		return "", fmt.Errorf("extension manifest rejected by path policy: %w", err)
	}

	// Check if already extracted and up-to-date
	embeddedManifest, err := fs.ReadFile(extensionFS, "extension/manifest.json")
	if err != nil {
		return "", fmt.Errorf("embedded manifest not found: %w", err)
	}

	if existing, err := os.ReadFile(manifestPath); err == nil {
		if string(existing) == string(embeddedManifest) {
			log.Printf("[browser] Extension already extracted at %s", extDir)
			return extDir, nil
		}
	}

	// Extract all files
	if err := os.MkdirAll(extDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir extension dir: %w", err)
	}

	entries, err := fs.ReadDir(extensionFS, "extension")
	if err != nil {
		return "", fmt.Errorf("read embedded extension: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile(extensionFS, "extension/"+entry.Name())
		if err != nil {
			return "", fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		rawDst := filepath.Join(extDir, entry.Name())
		dst, err := resolveBrowserPath(ctxID, rawDst)
		if err != nil {
			return "", fmt.Errorf("extension file %s rejected by path policy: %w", entry.Name(), err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", entry.Name(), err)
		}
	}

	log.Printf("[browser] Extension extracted to %s (%d files)", extDir, len(entries))
	return extDir, nil
}

func ensureBrowser(ctxID, proxy string) error {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	requiredProxy := config.Get().ProxyRequired || egressproxy.Required()

	if s.browser != nil {
		if requiredProxy && !s.requiredProxy {
			return fmt.Errorf("existing browser was launched without required proxy; close and relaunch it")
		}
		return nil
	}
	if requiredProxy {
		// The agent's browser_action proxy argument must not override the
		// operator's required outbound route. The loopback bridge handles
		// authenticated upstream proxies without placing credentials in
		// Chromium's process arguments.
		localURL, err := egressproxy.LocalURL()
		if err != nil {
			return fmt.Errorf("required browser proxy unavailable: %w", err)
		}
		proxy = localURL
	}

	// 1. Get Chromium binary (auto-download if needed)
	path, err := getChromiumPath(ctxID)
	if err != nil {
		return fmt.Errorf("chromium: %w", err)
	}

	// 2. Extract embedded extension
	extDir, err := extractExtension(ctxID)
	if err != nil {
		log.Printf("[browser] WARNING: Extension extraction failed: %v (launching without extension)", err)
		extDir = ""
	}

	// 3. Start WebSocket bridge for extension communication
	bridge := GetBridge()
	if err := bridge.Start(); err != nil {
		log.Printf("[browser] WARNING: WebSocket bridge start failed: %v", err)
	}

	// 4. Configure launcher
	ln := launcher.New().
		Bin(path).
		Headless(true).
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		Set("disable-web-security").           // Allow cross-origin for testing
		Set("allow-running-insecure-content"). // Allow mixed content
		Set("window-size", "1920,1080")

	// Load extension if extracted successfully
	if extDir != "" {
		ln = ln.
			Delete("headless").     // Remove --headless set by Headless(true)
			Set("headless", "new"). // Chrome 112+ new headless supports extensions
			Set("load-extension", extDir).
			Set("disable-extensions-except", extDir)
	}

	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		ln = ln.Set("proxy-server", fmt.Sprintf("http://127.0.0.1:%d", caidoPort)).
			Set("ignore-certificate-errors", "true")
	} else if proxy != "" && proxy != "none" {
		ln = ln.Set("proxy-server", proxy).
			Set("ignore-certificate-errors", "true")
		if requiredProxy {
			// Chromium otherwise bypasses proxies for loopback destinations.
			ln = ln.Set("proxy-bypass-list", "<-loopback>")
		}
	}

	// Acquire a Tool_Lease before the first browser context for this scan.
	// The lease is cached on BrowserState so it survives across multiple
	// browser_action invocations and is released exactly once when the
	// Scan_Context closes (Tasks 10.1, 10.3, 13.3). isHeavy=false because
	// a single shared Chromium process is light relative to scan-wide
	// terminal/python heavy tools — admission still throttles light slots.
	bs := scanContextForCtx(ctxID).Browser
	leaseAcquired := false
	var lease *resources.ToolLease
	if bs == nil || bs.Lease() == nil {
		l, err := resources.AcquireToolLeaseContext(browserWaitContext(ctxID), false, "browser_action")
		if err != nil {
			return fmt.Errorf("browser launch canceled while waiting for resource capacity: %w", err)
		}
		lease = l
		leaseAcquired = true
	}
	leaseAttached := false
	defer func() {
		if leaseAcquired && !leaseAttached {
			lease.Release()
		}
	}()

	u, err := ln.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	// Apply OOM/RLIMIT_AS to the freshly spawned Chromium process tree so
	// the lease's memory ceiling is enforced kernel-side (R4.4). go-rod's
	// launcher manages Chromium outside of os/exec and exposes only the
	// PID, so we use the PID-based companion to ApplyProcessLimitsWithLimit.
	// The "active" lease is either the one this call just acquired or the
	// one already cached on BrowserState from a previous launch in this
	// scan — in both cases the same memory ceiling applies. isHeavy=true
	// matches the python tool: Chromium is a memory-hungry subprocess and
	// should be reaped before xalgorix under pressure.
	pid := ln.PID()
	if pid > 0 {
		activeLease := lease
		if activeLease == nil && bs != nil {
			activeLease = bs.Lease()
		}
		var memLimitBytes int64
		if activeLease != nil {
			memLimitBytes = activeLease.MemoryLimitBytes()
		} else {
			memLimitBytes = resources.CurrentToolMemoryLimitBytes(false)
		}
		terminal.ApplyProcessLimitsToPID(pid, true, memLimitBytes)
	} else {
		log.Printf("[browser] Skipping process-limit apply: launcher reported pid=0")
	}

	br := rod.New().ControlURL(u)
	if err := br.Connect(); err != nil {
		ln.Kill()
		return fmt.Errorf("connect browser: %w", err)
	}

	s.browser = br
	s.browserLauncher = ln
	s.requiredProxy = requiredProxy
	if leaseAcquired {
		// Cache for cleanupBrowserLocked's per-store fallback release
		// (covers CleanupContext and timeout paths that don't call
		// BrowserState.Close), and attach to BrowserState so the
		// scan-context Close path can release exactly once.
		s.lease = lease
		if bs != nil {
			bs.SetLease(lease)
		}
		leaseAttached = true
	}
	log.Printf("[browser] Standalone browser launched (extension=%v, lease_acquired=%v)", extDir != "", leaseAcquired)
	return nil
}

func browserWaitContext(ctxID string) context.Context {
	if sc := scanctx.Get(ctxID); sc != nil && sc.Ctx != nil {
		return sc.Ctx
	}
	return context.Background()
}

// setupDialogHandler auto-dismisses JavaScript dialogs (alert/confirm/prompt)
// on a page — without this, calling alert() in headless Chrome blocks
// page.Eval() forever — AND records each dialog as an ExecSignal for the scan
// context. A fired dialog is concrete proof that an injected payload EXECUTED
// (not merely reflected), which the verify_xss action uses to confirm XSS.
func setupDialogHandler(ctxID string, p *rod.Page) {
	go p.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		dialogType := string(e.Type)
		msg := e.Message
		log.Printf("[browser] Auto-dismissing JS %s dialog: %q", dialogType, msg)
		recordExecSignal(ctxID, ExecSignal{
			Kind:    "dialog:" + dialogType,
			Message: msg,
			URL:     e.URL,
			At:      time.Now(),
		})
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(p)
	})()
}

// setupConsoleHandler records console.* API calls (console.log/error/warn/…) as
// ExecSignals for the scan context. Many XSS payloads prove execution without a
// dialog — a filter may strip alert() while console.log() runs, and DOM/JS-sink
// payloads commonly log a marker — so capturing the console broadens what
// verify_xss can confirm as real execution (not mere reflection). The Runtime
// domain is enabled explicitly so the events flow regardless of rod's lazy
// enabling.
func setupConsoleHandler(ctxID string, p *rod.Page) {
	_ = proto.RuntimeEnable{}.Call(p)
	go p.EachEvent(func(e *proto.RuntimeConsoleAPICalled) {
		var parts []string
		for _, arg := range e.Args {
			if arg == nil {
				continue
			}
			v := arg.Value.String()
			if v == "" {
				v = arg.Description
			}
			if v != "" {
				parts = append(parts, v)
			}
		}
		msg := strings.Join(parts, " ")
		if strings.TrimSpace(msg) == "" {
			return
		}
		recordExecSignal(ctxID, ExecSignal{
			Kind:    "console:" + string(e.Type),
			Message: msg,
			At:      time.Now(),
		})
	})()
}

// browserActionForRegistry resolves the correct browser store via the registry's ScanContextID.
func browserActionForRegistry(reg *tools.Registry, args map[string]string) (tools.Result, error) {
	ctxID := reg.GetScanContextID()
	return browserActionWithContext(ctxID, args)
}

func browserActionWithContext(ctxID string, args map[string]string) (tools.Result, error) {
	command := args["command"]

	switch command {
	case "launch":
		return launchBrowser(ctxID, args["url"], args["proxy"])
	case "goto":
		return navigateTo(ctxID, args["url"])
	case "snapshot":
		return takeSnapshot(ctxID)
	case "click":
		return clickElement(ctxID, args["selector"])
	case "type":
		return typeText(ctxID, args["selector"], args["text"])
	case "submit":
		return submitForm(ctxID, args["selector"])
	case "scroll":
		return scrollPage(ctxID, args["direction"])
	case "screenshot":
		return takeScreenshot(ctxID)
	case "get_html":
		return getHTML(ctxID, args["selector"])
	case "execute_js":
		return executeJS(ctxID, args["code"])
	case "get_cookies":
		return getCookies(ctxID)
	case "set_cookie":
		return setCookie(ctxID, args["name"], args["text"], args["domain"])
	case "save_session":
		return saveSession(ctxID, args["session_name"])
	case "load_session":
		return loadSession(ctxID, args["session_name"])
	case "list_sessions":
		return listSessions(ctxID)
	case "wait":
		return waitFor(ctxID, args["selector"], args["text"], args["timeout"])
	case "select":
		return selectOption(ctxID, args["selector"], args["text"])
	case "fill_form":
		return fillForm(ctxID, args["fields"])
	case "get_url":
		return getURL(ctxID)
	case "iframe":
		return switchToIframe(ctxID, args["selector"])
	case "main_frame":
		return switchToMainFrame(ctxID)
	case "extract_links":
		return extractLinks(ctxID)
	case "new_tab":
		return newTab(ctxID, args["url"])
	case "switch_tab":
		return switchTab(ctxID, args["tab_id"])
	case "close":
		return closeBrowser(ctxID)
	case "verify_xss":
		return verifyXSS(ctxID, args["url"], args["nonce"], args["parameter"], args["data"], args["method"])
	default:
		return tools.Result{}, fmt.Errorf("unknown browser action: %s. Available: launch, goto, snapshot, click, type, submit, scroll, screenshot, get_html, execute_js, get_cookies, set_cookie, save_session, load_session, list_sessions, wait, select, fill_form, get_url, iframe, main_frame, extract_links, new_tab, switch_tab, close, verify_xss", command)
	}
}

func launchBrowser(ctxID, rawURL, proxy string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if err := ensureBrowser(ctxID, proxy); err != nil {
		return tools.Result{}, err
	}

	p := s.browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", s.nextTab)
	s.nextTab++
	s.pages[tabID] = p
	s.currentTab = tabID
	s.page = p

	// Auto-dismiss JavaScript dialogs (alert/confirm/prompt) to prevent
	// page.Eval() from blocking forever in headless mode during XSS testing,
	// and record them as execution proof for verify_xss.
	setupDialogHandler(ctxID, p)
	setupConsoleHandler(ctxID, p)

	// Set a realistic user agent for login flows
	s.page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	})

	if rawURL != "" {
		err := p.Timeout(20 * time.Second).Navigate(rawURL)
		if err == nil {
			_ = p.Timeout(10 * time.Second).WaitStable(time.Second)
		}
	}

	return pageState(ctxID, "Browser launched", tabID)
}

func navigateTo(ctxID, rawURL string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched — use launch first")
	}

	err := s.page.Timeout(20 * time.Second).Navigate(rawURL)
	if err == nil {
		// Wait for both DOM and network to become stable natively
		_ = s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	}
	return pageState(ctxID, "Navigated", s.currentTab)
}

func parseSelector(selector string) string {
	if strings.HasPrefix(selector, "@e") {
		return fmt.Sprintf(`[data-xalgo-id="%s"]`, strings.TrimPrefix(selector, "@"))
	}
	return selector
}

func clickElement(ctxID, selector string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := s.page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	// Scroll element into view first
	el.MustScrollIntoView()
	el.MustClick()
	// Wait for any navigation or AJAX that results from the click
	time.Sleep(500 * time.Millisecond)
	_ = s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState(ctxID, fmt.Sprintf("Clicked: %s", selector), s.currentTab)
}

func typeText(ctxID, selector, text string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := s.page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	// Clear existing content and type new text
	el.MustScrollIntoView()
	el.MustSelectAllText().MustInput(text)
	return pageState(ctxID, fmt.Sprintf("Typed into: %s", selector), s.currentTab)
}

// submitForm submits a form — either clicks the submit button or presses Enter
func submitForm(ctxID, selector string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if selector != "" {
		// Click the specified submit button/element
		selector = parseSelector(selector)
		el, err := s.page.Timeout(10 * time.Second).Element(selector)
		if err != nil {
			return tools.Result{}, fmt.Errorf("submit element not found: %s", selector)
		}
		el.MustScrollIntoView()
		el.MustClick()
	} else {
		// Try to find and click the first submit button in the page
		// Look for: button[type=submit], input[type=submit], button with submit text
		submitSelectors := []string{
			`button[type="submit"]`,
			`input[type="submit"]`,
			`button:not([type])`, // Buttons without type default to submit in forms
		}
		clicked := false
		for _, sel := range submitSelectors {
			el, err := s.page.Timeout(2 * time.Second).Element(sel)
			if err == nil {
				el.MustScrollIntoView()
				el.MustClick()
				clicked = true
				break
			}
		}
		if !clicked {
			// Fallback: press Enter on the active element
			_ = s.page.Keyboard.Press(input.Enter)
		}
	}

	// Wait for navigation/AJAX after form submission
	time.Sleep(1 * time.Second)
	_ = s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState(ctxID, "Form submitted", s.currentTab)
}

// getCookies returns all cookies for the current page
func getCookies(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	cookies, err := s.page.Cookies([]string{})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to get cookies: %w", err)
	}

	if len(cookies) == 0 {
		return tools.Result{Output: "No cookies found for current page."}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Found %d cookies:\n\n", len(cookies)))
	for _, c := range cookies {
		flags := ""
		if c.HTTPOnly {
			flags += " HttpOnly"
		}
		if c.Secure {
			flags += " Secure"
		}
		if c.SameSite != "" {
			flags += " SameSite=" + string(c.SameSite)
		}
		b.WriteString(fmt.Sprintf("  %s = %s\n    Domain: %s  Path: %s  Expires: %s%s\n",
			c.Name, truncate(c.Value, 80), c.Domain, c.Path,
			formatExpiry(c.Expires), flags))
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"cookie_count": len(cookies),
		},
	}, nil
}

// setCookie sets a cookie on the current page
func setCookie(ctxID, name, value, domain string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if name == "" || value == "" {
		return tools.Result{}, fmt.Errorf("name and text (value) are required for set_cookie")
	}

	// Auto-detect domain from current URL if not provided
	if domain == "" {
		info, _ := s.page.Info()
		if info != nil {
			u, err := url.Parse(info.URL)
			if err == nil {
				domain = u.Hostname()
			}
		}
	}

	err := s.page.SetCookies([]*proto.NetworkCookieParam{
		{
			Name:   name,
			Value:  value,
			Domain: domain,
			Path:   "/",
		},
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to set cookie: %w", err)
	}

	return tools.Result{
		Output: fmt.Sprintf("Cookie set: %s=%s (domain: %s)", name, truncate(value, 40), domain),
	}, nil
}

// saveSession saves all current cookies under a named session (memory + disk)
func saveSession(ctxID, sessionName string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if sessionName == "" {
		sessionName = "default"
	}

	cookies, err := s.page.Cookies([]string{})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to get cookies: %w", err)
	}

	s.savedSessions[sessionName] = cookies

	// Persist to disk
	diskPath := sessionFilePath(s.sessionDir, sessionName)
	if diskPath != "" {
		entries := make([]savedCookieEntry, 0, len(cookies))
		for _, c := range cookies {
			entries = append(entries, savedCookieEntry{
				Name:     c.Name,
				Value:    c.Value,
				Domain:   c.Domain,
				Path:     c.Path,
				Secure:   c.Secure,
				HTTPOnly: c.HTTPOnly,
			})
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err == nil {
			// Route the session-persistence write through Path_Policy
			// (R8.5). The session directory is provided by the agent
			// (SetSessionPathForCtx); without this guard a misconfigured
			// path could escape the Allow_List.
			canonical, perr := resolveBrowserPath(ctxID, diskPath)
			if perr != nil {
				log.Printf("[browser] Warning: refusing to save session '%s' to %s: %v", sessionName, diskPath, perr)
			} else if err := os.WriteFile(canonical, data, 0600); err != nil {
				log.Printf("[browser] Warning: failed to save session '%s' to %s: %v", sessionName, canonical, err)
			} else {
				log.Printf("[browser] Session '%s' saved to disk: %s (%d cookies)", sessionName, canonical, len(entries))
			}
		}
	}

	return tools.Result{
		Output:   fmt.Sprintf("✅ Session '%s' saved: %d cookies stored (memory + disk). Use load_session session_name=%s to restore.", sessionName, len(cookies), sessionName),
		Metadata: map[string]any{"cookies_saved": len(cookies), "session_name": sessionName},
	}, nil
}

// loadSession restores cookies from a named session (memory first, then disk fallback)
func loadSession(ctxID, sessionName string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if sessionName == "" {
		sessionName = "default"
	}

	// Check in-memory first
	cookies := s.savedSessions[sessionName]

	// Try disk fallback if no in-memory cookies
	if len(cookies) == 0 {
		diskPath := sessionFilePath(s.sessionDir, sessionName)
		if diskPath != "" {
			if data, err := os.ReadFile(diskPath); err == nil {
				var entries []savedCookieEntry
				if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
					log.Printf("[browser] Loading session '%s' from disk: %s (%d cookies)", sessionName, diskPath, len(entries))
					params := make([]*proto.NetworkCookieParam, 0, len(entries))
					for _, e := range entries {
						params = append(params, &proto.NetworkCookieParam{
							Name:     e.Name,
							Value:    e.Value,
							Domain:   e.Domain,
							Path:     e.Path,
							Secure:   e.Secure,
							HTTPOnly: e.HTTPOnly,
						})
					}
					// Clear existing cookies before restoring to avoid mixed auth state
					_ = proto.NetworkClearBrowserCookies{}.Call(s.page)
					if err := s.page.SetCookies(params); err != nil {
						return tools.Result{}, fmt.Errorf("failed to restore session '%s' from disk: %w", sessionName, err)
					}
					if err := s.page.Timeout(10 * time.Second).Reload(); err != nil {
						log.Printf("[browser] Warning: page reload after session '%s' restore failed: %v", sessionName, err)
					}
					if err := s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second); err != nil {
						log.Printf("[browser] Warning: page wait-stable after session '%s' restore failed: %v", sessionName, err)
					}
					return tools.Result{
						Output:   fmt.Sprintf("✅ Session '%s' restored from disk: %d cookies loaded and page refreshed.", sessionName, len(entries)),
						Metadata: map[string]any{"session_name": sessionName, "cookies_loaded": len(entries)},
					}, nil
				}
			}
		}
	}

	if len(cookies) == 0 {
		avail := listSessionNames(s)
		if len(avail) > 0 {
			return tools.Result{Output: fmt.Sprintf("No session named '%s' found. Available sessions: %s", sessionName, strings.Join(avail, ", "))}, nil
		}
		return tools.Result{Output: fmt.Sprintf("No session named '%s' found. Use save_session session_name=%s first after logging in.", sessionName, sessionName)}, nil
	}

	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, c := range cookies {
		params = append(params, &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		})
	}

	// Clear existing cookies before restoring to avoid mixed auth state
	_ = proto.NetworkClearBrowserCookies{}.Call(s.page)
	if err := s.page.SetCookies(params); err != nil {
		return tools.Result{}, fmt.Errorf("failed to restore session '%s': %w", sessionName, err)
	}

	// Reload page to apply cookies
	if err := s.page.Timeout(10 * time.Second).Reload(); err != nil {
		log.Printf("[browser] Warning: page reload after session '%s' restore failed: %v", sessionName, err)
	}
	if err := s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second); err != nil {
		log.Printf("[browser] Warning: page wait-stable after session '%s' restore failed: %v", sessionName, err)
	}

	return tools.Result{
		Output:   fmt.Sprintf("✅ Session '%s' restored: %d cookies loaded and page refreshed.", sessionName, len(cookies)),
		Metadata: map[string]any{"session_name": sessionName, "cookies_loaded": len(cookies)},
	}, nil
}

// listSessions returns all saved session names for a context
func listSessions(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()

	names := listSessionNames(s)

	// Also check disk for any sessions not in memory
	if s.sessionDir != "" {
		files, err := os.ReadDir(s.sessionDir)
		if err == nil {
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				name := f.Name()
				if name == "session.json" {
					// default session on disk
					found := false
					for _, n := range names {
						if n == "default" {
							found = true
							break
						}
					}
					if !found {
						names = append(names, "default (disk)")
					}
				} else if strings.HasSuffix(name, "_session.json") {
					sessName := strings.TrimSuffix(name, "_session.json")
					found := false
					for _, n := range names {
						if n == sessName {
							found = true
							break
						}
					}
					if !found {
						names = append(names, sessName+" (disk)")
					}
				}
			}
		}
	}

	if len(names) == 0 {
		return tools.Result{Output: "No saved sessions. Use save_session session_name=NAME after logging in."}, nil
	}

	return tools.Result{
		Output:   fmt.Sprintf("Saved sessions: %s\nUse load_session session_name=NAME to switch.", strings.Join(names, ", ")),
		Metadata: map[string]any{"sessions": names},
	}, nil
}

// listSessionNames returns in-memory session names
func listSessionNames(s *browserStore) []string {
	names := make([]string, 0, len(s.savedSessions))
	for name := range s.savedSessions {
		names = append(names, name)
	}
	return names
}

// waitFor waits for an element to appear, navigation to complete, or a timeout
func waitFor(ctxID, selector, waitType, timeoutStr string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	timeout := 10 * time.Second
	if timeoutStr != "" {
		var secs int
		_, _ = fmt.Sscanf(timeoutStr, "%d", &secs)
		if secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}

	if waitType == "navigation" || waitType == "nav" {
		// Wait for navigation to complete (URL change)
		info, _ := s.page.Info()
		oldURL := ""
		if info != nil {
			oldURL = info.URL
		}

		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			info, _ = s.page.Info()
			if info != nil && info.URL != oldURL {
				_ = s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
				return pageState(ctxID, "Navigation detected", s.currentTab)
			}
		}
		return pageState(ctxID, "Wait completed (no navigation detected)", s.currentTab)
	}

	if selector != "" {
		selector = parseSelector(selector)
		_, err := s.page.Timeout(timeout).Element(selector)
		if err != nil {
			return tools.Result{Output: fmt.Sprintf("Element '%s' did not appear within %v", selector, timeout)}, nil
		}
		return pageState(ctxID, fmt.Sprintf("Element found: %s", selector), s.currentTab)
	}

	// Default: just wait for page to stabilize
	_ = s.page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState(ctxID, "Page stabilized", s.currentTab)
}

// selectOption selects an option from a <select> dropdown
func selectOption(ctxID, selector, value string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := s.page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("select element not found: %s", selector)
	}

	// Try selecting by value first, then by visible text
	err = el.Select([]string{value}, true, rod.SelectorTypeText)
	if err != nil {
		// Fallback: try by value attribute
		_, evalErr := s.page.Eval(fmt.Sprintf(`() => {
			const el = document.querySelector('%s');
			if (el) {
				for (const opt of el.options) {
					if (opt.value === '%s' || opt.text === '%s') {
						el.value = opt.value;
						el.dispatchEvent(new Event('change', { bubbles: true }));
						return true;
					}
				}
			}
			return false;
		}`, selector, value, value))
		if evalErr != nil {
			return tools.Result{}, fmt.Errorf("failed to select option '%s': %w", value, err)
		}
	}

	return tools.Result{Output: fmt.Sprintf("Selected '%s' in %s", value, selector)}, nil
}

// fillForm auto-fills multiple form fields at once
func fillForm(ctxID, fields string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if fields == "" {
		return tools.Result{}, fmt.Errorf("fields parameter is required. Format: field1=value1|field2=value2")
	}

	pairs := strings.Split(fields, "|")
	filled := []string{}

	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		fieldName := strings.TrimSpace(parts[0])
		fieldValue := strings.TrimSpace(parts[1])

		// Try multiple selector strategies to find the field
		selectors := []string{
			fmt.Sprintf(`input[name="%s"]`, fieldName),
			fmt.Sprintf(`input[id="%s"]`, fieldName),
			fmt.Sprintf(`input[placeholder*="%s" i]`, fieldName),
			fmt.Sprintf(`textarea[name="%s"]`, fieldName),
			fmt.Sprintf(`select[name="%s"]`, fieldName),
			fmt.Sprintf(`[aria-label*="%s" i]`, fieldName),
		}

		found := false
		for _, sel := range selectors {
			el, err := s.page.Timeout(2 * time.Second).Element(sel)
			if err == nil {
				tag, _ := el.Eval(`() => this.tagName.toLowerCase()`)
				if tag != nil && tag.Value.String() == "select" {
					_ = el.Select([]string{fieldValue}, true, rod.SelectorTypeText)
				} else {
					el.MustScrollIntoView()
					el.MustSelectAllText().MustInput(fieldValue)
				}
				filled = append(filled, fieldName)
				found = true
				break
			}
		}
		if !found {
			filled = append(filled, fieldName+" (NOT FOUND)")
		}
	}

	return tools.Result{
		Output: fmt.Sprintf("Form filled: %s\n\nTip: Use 'submit' command to submit the form.", strings.Join(filled, ", ")),
	}, nil
}

// getURL returns the current page URL
func getURL(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	info, _ := s.page.Info()
	if info == nil {
		return tools.Result{Output: "Unable to get page info"}, nil
	}

	return tools.Result{
		Output:   info.URL,
		Metadata: map[string]any{"url": info.URL, "title": info.Title},
	}, nil
}

// switchToIframe switches page context into an iframe
func switchToIframe(ctxID, selector string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if selector == "" {
		selector = "iframe"
	}
	selector = parseSelector(selector)

	el, err := s.page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("iframe not found: %s", selector)
	}

	frame, err := el.Frame()
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to access iframe: %w", err)
	}

	// Store the main page and switch context to the iframe's page
	iframeURL := ""
	frameInfo, _ := frame.Info()
	if frameInfo != nil {
		iframeURL = frameInfo.URL
	}

	// Create a virtual tab for the iframe
	tabID := fmt.Sprintf("iframe_%d", s.nextTab)
	s.nextTab++
	s.pages[tabID] = frame
	s.currentTab = tabID
	s.page = frame

	return tools.Result{
		Output: fmt.Sprintf("Switched to iframe: %s\n  URL: %s\n  Tab ID: %s (use main_frame to switch back)", selector, iframeURL, tabID),
	}, nil
}

// switchToMainFrame switches back to the main page from an iframe
func switchToMainFrame(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	// Find the first non-iframe tab
	for id, p := range s.pages {
		if !strings.HasPrefix(id, "iframe_") {
			s.page = p
			s.currentTab = id
			return pageState(ctxID, "Switched to main frame", s.currentTab)
		}
	}
	return tools.Result{Output: "No main frame found"}, nil
}

// extractLinks extracts all links from the current page
func extractLinks(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		const links = [];
		document.querySelectorAll('a[href]').forEach(a => {
			const href = a.href;
			const text = (a.innerText || a.title || a.getAttribute('aria-label') || '').trim().substring(0, 60);
			if (href && !href.startsWith('javascript:')) {
				links.push(text ? text + ' → ' + href : href);
			}
		});
		return links.join('\n');
	}`

	result, err := s.page.Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to extract links: %w", err)
	}

	output := result.Value.String()
	if output == "" {
		output = "No links found on the page."
	}

	// Count links
	linkCount := len(strings.Split(output, "\n"))

	return tools.Result{
		Output:   fmt.Sprintf("Found %d links:\n\n%s", linkCount, output),
		Metadata: map[string]any{"link_count": linkCount},
	}, nil
}

func scrollPage(ctxID, direction string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	switch strings.ToLower(direction) {
	case "down":
		s.page.Mouse.MustScroll(0, 500)
	case "up":
		s.page.Mouse.MustScroll(0, -500)
	default:
		s.page.Mouse.MustScroll(0, 500)
	}

	time.Sleep(500 * time.Millisecond)
	return pageState(ctxID, fmt.Sprintf("Scrolled %s", direction), s.currentTab)
}

func takeScreenshot(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	img, err := s.page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: nil,
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("screenshot failed: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(img)

	return tools.Result{
		Output: fmt.Sprintf("Screenshot captured (%d bytes)", len(img)),
		Metadata: map[string]any{
			"screenshot": b64,
			"format":     "png",
			"size_bytes": len(img),
		},
	}, nil
}

// takeSnapshot returns an enhanced accessibility tree with form-aware element detection
func takeSnapshot(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		let output = [];
		let counter = 1;
		
		// Enhanced selector: includes form elements, labels, and more interactive elements
		const elements = document.querySelectorAll(
			'a, button, input, select, textarea, label, ' +
			'[role="button"], [role="link"], [role="textbox"], [role="checkbox"], [role="radio"], ' +
			'[role="combobox"], [role="listbox"], [role="menuitem"], [role="tab"], ' +
			'[tabindex]:not([tabindex="-1"]), [contenteditable="true"], ' +
			'form, details, summary'
		);
		
		elements.forEach(el => {
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return;
			const style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return;
			
			let id = 'e' + counter++;
			el.setAttribute('data-xalgo-id', id);
			
			let tag = el.tagName.toLowerCase();
			let type = el.type ? '(' + el.type + ')' : '';
			let name = el.name ? ' name="' + el.name + '"' : '';
			let placeholder = el.placeholder ? ' placeholder="' + el.placeholder + '"' : '';
			
			// Get text — priority: innerText > value > placeholder > aria-label > alt > title
			let text = '';
			if (tag === 'input' || tag === 'textarea') {
				text = el.value || el.placeholder || el.getAttribute('aria-label') || '';
			} else if (tag === 'select') {
				const selected = el.options[el.selectedIndex];
				text = selected ? selected.text : '';
			} else if (tag === 'label') {
				text = el.innerText || '';
				// Link label to its input
				const forEl = el.htmlFor ? document.getElementById(el.htmlFor) : el.querySelector('input,select,textarea');
				if (forEl) {
					const forId = forEl.getAttribute('data-xalgo-id');
					if (forId) text += ' → @' + forId;
				}
			} else {
				text = (el.innerText || el.getAttribute('aria-label') || el.alt || el.title || '').trim();
			}
			text = text.replace(/\n/g, ' ').substring(0, 60);
			
			// Build descriptor
			let desc = '[@' + id + '] ' + tag + type + name;
			if (text) desc += ' "' + text + '"';
			if (placeholder) desc += placeholder;
			
			// Mark required fields
			if (el.required) desc += ' [REQUIRED]';
			// Mark disabled
			if (el.disabled) desc += ' [DISABLED]';
			
			output.push(desc);
		});
		
		// Also note any visible forms
		const forms = document.querySelectorAll('form');
		if (forms.length > 0) {
			output.unshift('--- Page has ' + forms.length + ' form(s) ---');
		}
		
		return output.join('\n');
	}`

	result, err := s.page.Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("snapshot failed: %w", err)
	}

	info, _ := s.page.Info()
	urlStr := ""
	if info != nil {
		urlStr = "\nURL: " + info.URL + "\n"
	}

	return tools.Result{
		Output: "Interactive Elements Tree:" + urlStr + "\n" + result.Value.String(),
	}, nil
}

func getHTML(ctxID, selector string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	var html string
	if selector != "" {
		selector = parseSelector(selector)
		el, err := s.page.Timeout(10 * time.Second).Element(selector)
		if err != nil {
			return tools.Result{}, fmt.Errorf("element not found: %s", selector)
		}
		html, _ = el.HTML()
	} else {
		html = s.page.MustHTML()
	}

	if len(html) > 20000 {
		html = html[:20000] + "\n\n... [HTML TRUNCATED]"
	}

	return tools.Result{Output: html}, nil
}

func executeJS(ctxID, code string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	// Use a timeout to prevent blocking forever (e.g., alert() in headless Chrome).
	// The dialog handler auto-dismisses alerts, but we add a timeout as a safety net.
	result, err := s.page.Timeout(10 * time.Second).Eval(code)
	if err != nil {
		// If it timed out, it's likely a blocking dialog that wasn't caught
		if strings.Contains(err.Error(), "context deadline") || strings.Contains(err.Error(), "timeout") {
			return tools.Result{
				Output: "⚠️ JS execution timed out (likely a blocking dialog like alert/confirm/prompt). The dialog was triggered, which confirms JavaScript execution. Use page.Eval with a non-blocking approach instead.",
			}, nil
		}
		return tools.Result{}, fmt.Errorf("JS error: %w", err)
	}

	return tools.Result{Output: result.Value.String()}, nil
}

func newTab(ctxID, rawURL string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.browser == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	p := s.browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", s.nextTab)
	s.nextTab++
	s.pages[tabID] = p
	s.currentTab = tabID
	s.page = p

	// Auto-dismiss JavaScript dialogs on new tabs too, and capture console output
	setupDialogHandler(ctxID, p)
	setupConsoleHandler(ctxID, p)

	if rawURL != "" {
		err := p.Timeout(20 * time.Second).Navigate(rawURL)
		if err == nil {
			_ = p.Timeout(10 * time.Second).WaitStable(1 * time.Second)
		}
	}

	return pageState(ctxID, "New tab opened", tabID)
}

func switchTab(ctxID, tabID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	p, ok := s.pages[tabID]
	if !ok {
		return tools.Result{}, fmt.Errorf("tab not found: %s (available: %v)", tabID, tabListForCtx(ctxID))
	}

	s.page = p
	s.currentTab = tabID
	return pageState(ctxID, "Switched tab", tabID)
}

func closeBrowser(ctxID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanupBrowserLocked(ctxID, s)

	return tools.Result{Output: "Browser closed"}, nil
}

// cleanupBrowserLocked closes browser resources (must hold s.mu).
func cleanupBrowserLocked(ctxID string, s *browserStore) {
	closed := false
	s.savedSessions = make(map[string][]*proto.NetworkCookie)
	if s.browser != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[browser] cleanupBrowserLocked: MustClose recovered: %v", r)
				}
			}()
			s.browser.MustClose()
			closed = true
		}()
		s.browser = nil
		s.page = nil
		s.pages = make(map[string]*rod.Page)
	}
	if !closed && s.browserLauncher != nil {
		s.browserLauncher.Kill()
	}
	s.browserLauncher = nil
	s.requiredProxy = false
	if s.lease != nil {
		s.lease.Release()
		s.lease = nil
	}
	// Keep BrowserState cache in sync so the next launch in this scan
	// re-acquires a fresh lease. Without this the bs.Lease() != nil guard
	// in ensureBrowser would short-circuit re-acquire on a stale, already-
	// released lease pointer. Note: ToolLease.Release is idempotent so
	// this is safe even if Task 10.3 later adds a release in
	// BrowserState.Close — only the first call deducts from the
	// semaphore.
	if sc := scanctx.Get(ctxID); sc != nil && sc.Browser != nil {
		sc.Browser.DropLease()
	}
}

// CleanupBrowser safely closes any open browser and resets state.
// Called between scan phases and on agent stop to prevent stale connection usage.
func CleanupBrowser() {
	ctxID := scanctx.Default().ID
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	defer s.mu.Unlock()
	cleanupBrowserLocked(ctxID, s)
}

func pageState(ctxID, action, tabID string) (tools.Result, error) {
	s := getBrowserStoreByID(ctxID)
	if s.page == nil {
		return tools.Result{Output: action}, nil
	}

	info, _ := s.page.Info()
	rawURL := ""
	title := ""
	if info != nil {
		rawURL = info.URL
		title = info.Title
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n", action))
	b.WriteString(fmt.Sprintf("  Tab: %s\n", tabID))
	if rawURL != "" {
		b.WriteString(fmt.Sprintf("  URL: %s\n", rawURL))
	}
	if title != "" {
		b.WriteString(fmt.Sprintf("  Title: %s\n", title))
	}

	// List all tabs
	if len(s.pages) > 1 {
		b.WriteString("  All tabs: ")
		b.WriteString(strings.Join(tabListForCtx(ctxID), ", "))
		b.WriteString("\n")
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"url":    rawURL,
			"title":  title,
			"tab_id": tabID,
		},
	}, nil
}

func tabListForCtx(ctxID string) []string {
	s := getBrowserStoreByID(ctxID)
	tabs := make([]string, 0, len(s.pages))
	for id := range s.pages {
		tabs = append(tabs, id)
	}
	return tabs
}

// Helper: truncate string for display
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Helper: format cookie expiry timestamp
func formatExpiry(ts proto.TimeSinceEpoch) string {
	if ts == 0 {
		return "Session"
	}
	t := ts.Time()
	if t.IsZero() {
		return "Session"
	}
	return t.Format("2006-01-02 15:04")
}

// ExtractVerificationURL extracts verification/confirmation URLs from email body text.
// Useful for the agent to programmatically find verification links.
func ExtractVerificationURL(emailBody string) string {
	// Common verification URL patterns
	urlRegex := regexp.MustCompile(`https?://[^\s<>"']+(?:verif|confirm|activate|valid|token|auth|callback|reset|click)[^\s<>"']*`)
	match := urlRegex.FindString(emailBody)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	// Fallback: find any URL with a long token/hash parameter
	tokenURLRegex := regexp.MustCompile(`https?://[^\s<>"']*[?&][^\s<>"']*=[a-zA-Z0-9_-]{20,}[^\s<>"']*`)
	match = tokenURLRegex.FindString(emailBody)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	return ""
}
