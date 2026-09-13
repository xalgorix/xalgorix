// Package config provides configuration management for Xalgorix.
// All configuration is loaded from environment variables with XALGORIX_ prefix.
package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/scanheaders"
)

// Config holds all Xalgorix configuration.
type Config struct {
	// LLM settings
	LLM             string // XALGORIX_LLM — provider-native model ID (for example, "gpt-5.6" or "zai-org/glm-4.5")
	LLMProvider     string // XALGORIX_LLM_PROVIDER — explicit provider ID; keeps provider routing separate from the model name
	APIBase         string // XALGORIX_API_BASE — API endpoint
	APIKey          string // XALGORIX_API_KEY — API key
	LLMProfile      string // XALGORIX_LLM_PROFILE — active credential pointer "<provider>:<profileId>" (v4.4.22+)
	ReasoningEffort string // XALGORIX_REASONING_EFFORT — "none", "low", "medium", "high", or "xhigh"

	// Language is the output language for human-readable AI content — agent
	// reasoning, notes, vulnerability findings, and post-scan chat. It does
	// NOT change tool call structure or technical tokens (payloads, commands,
	// URLs, CVE/CWE IDs). XALGORIX_LANGUAGE, canonical code (e.g. "en",
	// "zh-CN"); default "en" (English) so existing scans are unchanged.
	Language         string
	OllamaCompatible bool     // XALGORIX_OLLAMA_COMPATIBLE — force Ollama request semantics for a custom endpoint
	Temperature      *float64 // XALGORIX_TEMPERATURE — LLM temperature (0.0-2.0), default 0.2; pointer to distinguish unset from 0.0
	LLMMaxRetries    int      // XALGORIX_LLM_MAX_RETRIES
	// MaxRateLimitWaitSec bounds how long a scan waits for a provider rate
	// limit before stopping cleanly. XALGORIX_MAX_RATE_LIMIT_WAIT, default
	// 1800 seconds (30 minutes).
	MaxRateLimitWaitSec int
	MemCompTimeout      int // XALGORIX_MEMORY_COMPRESSOR_TIMEOUT
	// MaxOutputTokens caps the model's completion length per call (the
	// OpenAI-compatible `max_tokens` / Anthropic `max_tokens`). Reasoning
	// models spend part of this budget on hidden thinking BEFORE emitting a
	// tool call, so a small provider default truncates large calls like report_vulnerability mid-stream. Set an explicit, generous
	// budget so the full call fits. XALGORIX_MAX_OUTPUT_TOKENS, default 8192.
	MaxOutputTokens int

	// GeminiSafetyThreshold sets the HarmBlockThreshold applied to every
	// adjustable safety category (harassment, hate speech, sexually explicit,
	// dangerous content) on the NATIVE Gemini API path
	// (generativelanguage.googleapis.com). Xalgorix is an authorized
	// security-testing tool: Gemini's default filter classifies legitimate
	// exploit payloads and offensive-security methodology as
	// HARM_CATEGORY_DANGEROUS_CONTENT and blocks the response, which surfaces
	// as an empty candidate (finishReason SAFETY) and a failed agent turn.
	// XALGORIX_GEMINI_SAFETY. Accepted values (case-insensitive): BLOCK_NONE
	// (default), OFF, BLOCK_ONLY_HIGH, BLOCK_MEDIUM_AND_ABOVE,
	// BLOCK_LOW_AND_ABOVE, or DEFAULT/"" to send no safetySettings and use
	// Google's server-side defaults. This ONLY affects Gemini content
	// filtering — it does not touch scope enforcement, target authorization,
	// the destructive-command guard, logging, or audit trails.
	GeminiSafetyThreshold string

	// ContextCompactTokens is an OPTIONAL absolute override for the compaction
	// trigger. When > 0, the agent auto-compacts older turns into a structured
	// digest (+ saved notes) once the running message history is estimated to
	// exceed this many tokens. When 0, auto-compaction is DISABLED. When < 0
	// (the default "auto" mode), the trigger is derived from the model's
	// context window instead — LLMContextWindow × ContextCompactRatio — so
	// compaction only fires when the window is genuinely filling up rather than
	// at an arbitrary fixed budget. XALGORIX_CONTEXT_COMPACT_TOKENS, default -1
	// (auto / window-relative).
	ContextCompactTokens int

	// LLMContextWindow is the total context window (in tokens) of the
	// configured model, used as the basis for window-relative auto-compaction.
	// XALGORIX_LLM_CONTEXT_WINDOW, default 128000. Set this to your model's real
	// window (e.g. 1000000 for a 1M-token model) so compaction waits until the
	// window is actually filling up instead of compacting far too early.
	LLMContextWindow int

	// ContextCompactRatio is the fraction of LLMContextWindow at which
	// window-relative auto-compaction triggers (only used when
	// ContextCompactTokens is in auto mode). XALGORIX_CONTEXT_COMPACT_RATIO,
	// default 0.75 — i.e. compact once the running context reaches ~75% of the
	// window. Clamped to a sane 0.5–0.9 range. Compacting earlier than this
	// tends to discard useful working context and hurt output quality.
	ContextCompactRatio float64

	// Runtime settings
	RuntimeBackend string // XALGORIX_RUNTIME_BACKEND — always "native"
	Workspace      string // XALGORIX_WORKSPACE — workspace root dir
	DataDir        string // Active per-installation data root. Defaults to ~/.xalgorix/data/. Override via XALGORIX_DATA_DIR.
	WorkspaceRoot  string // Resolution root used by Filesystem_Tools when no Scan_Context.ScanDir is in effect. Equals DataDir.
	legacyCWD      string // Captured os.Getwd() at config load time. Used only by the migration warning.
	DisableBrowser bool   // XALGORIX_DISABLE_BROWSER
	MaxIterations  int    // XALGORIX_MAX_ITERATIONS — 0 = unlimited
	MinIterations  int    // XALGORIX_MIN_ITERATIONS — minimum testing floor (default 50)
	// MaxWildcardSubdomains optionally caps the number of full agent sessions
	// spawned by one wildcard target. XALGORIX_MAX_WILDCARD_SUBDOMAINS,
	// default -1 (unlimited). Set a positive value only as an explicit
	// emergency resource cap; coverage is the default priority.
	MaxWildcardSubdomains int

	// NoToolAbortAt is how many CONSECUTIVE no-tool-call responses force-stop a
	// scan (the "reasoning loop" abort). XALGORIX_NO_TOOL_ABORT_AT, default 30.
	// Set to 0 only when an operator explicitly wants unbounded recovery.
	NoToolAbortAt int

	// MaxFinishRejections is how many times the agent's finish call will be
	// rejected by the gatekeeper before allowing a deadlock bypass.
	// XALGORIX_MAX_FINISH_REJECTIONS, default 15.
	MaxFinishRejections int

	// TargetAuth carries operator-supplied authenticated-session credentials
	// for the target(s), so the agent can test post-authentication attack
	// surface (IDOR/BOLA, privilege escalation, business logic) — where the
	// high-value bugs live. Format: one "Header-Name: value" per line or
	// separated by ';'. e.g. "Cookie: session=abc; Authorization: Bearer xyz".
	// XALGORIX_TARGET_AUTH. Applied automatically to the http_request tool and
	// surfaced to the agent for use with curl/other tools.
	TargetAuth string

	// TargetAuthSecondary is a SECOND account's credentials (same format as
	// TargetAuth). It is NOT auto-applied — it is surfaced to the agent so it
	// can prove horizontal access-control flaws (IDOR/BOLA): reach an object
	// created by account A using account B's session. XALGORIX_TARGET_AUTH_B.
	TargetAuthSecondary string

	// Out-of-band (OAST) callback infrastructure for confirming blind
	// vulnerabilities (blind SSRF/RCE/XSS/XXE). OOBPublicURL is the address
	// targets can reach (e.g. https://oob.xalgorix.com), OOBPort is the local
	// listener port. OOB is enabled only when OOBPublicURL is set.
	// XALGORIX_OOB_PUBLIC_URL / XALGORIX_OOB_PORT.
	OOBPublicURL string
	OOBPort      int

	// Interactsh (ProjectDiscovery OAST) is the zero-config OOB backend used
	// automatically when no self-hosted OOBPublicURL is set. It captures
	// DNS/HTTP/SMTP callbacks via public servers (oast.pro, oast.live, …) so
	// blind-vuln confirmation works without the operator exposing a listener.
	// InteractshServer overrides the server list (comma-separated) and
	// InteractshToken authenticates a self-hosted interactsh server. Set
	// OOBDisable=true to turn OOB off entirely.
	// XALGORIX_INTERACTSH_SERVER / XALGORIX_INTERACTSH_TOKEN / XALGORIX_OOB_DISABLE.
	InteractshServer string
	InteractshToken  string
	OOBDisable       bool

	// OOBInteractions restricts which out-of-band interaction PROTOCOLS are
	// returned. Comma-separated subset of dns,http,smtp; empty = all three.
	// DNS-only activity is retained as a lead but is not sufficient SSRF proof;
	// the reporting gate requires a non-scanner-origin HTTP interaction.
	OOBInteractions string

	// SourceRepo enables whitebox / source-assisted assessment: the agent
	// reads the target's source code and reasons code → dangerous sink →
	// exploit against the live target. Accepts a Git URL (shallow-cloned into
	// the scan workspace) or an existing local directory path. When set, the
	// code_search tool and a whitebox methodology are activated.
	// XALGORIX_SOURCE_REPO.
	SourceRepo string

	// ScanContext points at operator-supplied context artifacts — an OpenAPI /
	// Swagger spec, a HAR capture, or a Postman collection (a single file or a
	// directory of them). The engine parses them into a seeded attack surface
	// (real endpoints + params + example bodies) and harvests any auth material,
	// turning a blind black-box scan into an informed one. XALGORIX_SCAN_CONTEXT.
	ScanContext string

	// ScanHeaders are operator-supplied custom HTTP headers ("Name: value")
	// injected into all TARGET-facing scan traffic to identify an authorized
	// Xalgorix run: the agent's HTTP client and, via their -H flag, bundled
	// tools (httpx, nuclei). Built-in equivalent of Nuclei's -H/-header. Bug-
	// bounty programs often require such a header (e.g. "X-Bug-Bounty: user");
	// it also lets a target's WAF/SOC allow-list the scan. Never attached to
	// non-target destinations (LLM APIs, notifications, the dashboard).
	// XALGORIX_SCAN_HEADERS (';'/newline-separated) and/or
	// XALGORIX_SCAN_HEADERS_FILE (one per line); repeatable -H on the CLI.
	ScanHeaders []string

	// Per-scan resource budgets with graceful early-stopping (MAPTA §2.7/§3.3).
	// A scan halts cleanly (keeping findings already reported) once any cap is
	// hit. 0 = unlimited (default), so behavior is unchanged unless configured.
	// XALGORIX_MAX_TOOL_CALLS / XALGORIX_MAX_DURATION (seconds) / XALGORIX_MAX_TOKENS.
	MaxToolCalls   int
	MaxDurationSec int
	MaxTokens      int

	// ScanRetentionDays controls automatic pruning of old scan output
	// directories under DataDir. XALGORIX_SCAN_RETENTION_DAYS — when > 0, a
	// background job deletes scan directories whose finished/started time is
	// older than this many days. 0 (default) disables retention so nothing is
	// ever deleted automatically.
	ScanRetentionDays int // XALGORIX_SCAN_RETENTION_DAYS — 0 = disabled (keep forever)

	// Rate limiting & API settings
	RateLimitRequests int // XALGORIX_RATE_LIMIT_REQUESTS — requests per window
	RateLimitWindow   int // XALGORIX_RATE_LIMIT_WINDOW — window in seconds
	RateLimitRPS      float64
	RateLimitBurst    int
	TLSSkipVerify     bool

	// Caido proxy
	CaidoPort     int    // CAIDO_PORT
	CaidoAPIToken string // CAIDO_API_TOKEN

	// Telemetry
	Telemetry    bool   // XALGORIX_TELEMETRY
	OTelEndpoint string // XALGORIX_OTEL_ENDPOINT

	// Web Search API
	GeminiAPIKey string // GEMINI_API_KEY - for web search using Gemini

	// AgentMail - temp email for sign-up verification
	AgentMailAPIKey string // AGENTMAIL_API_KEY - AgentMail API key
	AgentMailPod    string // AGENTMAIL_POD - AgentMail pod (e.g., "am_us_pod_47")

	// Discord notifications
	DiscordWebhook     string // XALGORIX_DISCORD_WEBHOOK - notification webhook URL
	DiscordMinSeverity string // XALGORIX_DISCORD_MIN_SEVERITY - minimum severity to notify

	// Telegram notifications
	TelegramBotToken    string // XALGORIX_TELEGRAM_BOT_TOKEN - bot token from @BotFather (secret)
	TelegramChatID      string // XALGORIX_TELEGRAM_CHAT_ID - target chat/channel ID (numeric or @username)
	TelegramMinSeverity string // XALGORIX_TELEGRAM_MIN_SEVERITY - minimum severity to notify

	// Scan-completion summary notification.
	// When false (default) the "Scan Finished" summary is suppressed and only
	// per-vulnerability alerts are sent; set true to also get an end-of-scan summary.
	NotifyScanComplete bool // XALGORIX_NOTIFY_SCAN_COMPLETE - send the "Scan Finished" summary after every scan

	// Dashboard auth
	Username     string // XALGORIX_USERNAME - dashboard login username
	Password     string // XALGORIX_PASSWORD - dashboard login password (DEPRECATED: prefer PasswordHash)
	PasswordHash string // XALGORIX_PASSWORD_HASH - bcrypt hash of the dashboard password (preferred)

	// Network binding
	// BindAddr controls which interface the web server listens on. Defaults to
	// 127.0.0.1 so a fresh install is not exposed to the network. Set
	// XALGORIX_BIND=0.0.0.0 (or a specific interface IP) to expose externally —
	// but in that case Username + (Password|PasswordHash) MUST be configured or
	// the server will refuse to start.
	BindAddr string // XALGORIX_BIND - listen address (default 127.0.0.1)

	// AllowLocalTargets opts a self-hosted install into scanning locally-hosted
	// apps — loopback, localhost, or one of this machine's own interface IPs
	// (e.g. a demo/staging environment on the same box), which are blocked by
	// default as "self". The dashboard's own listener is ALWAYS protected
	// regardless of this flag. XALGORIX_ALLOW_LOCAL_TARGETS (default false).
	// Leave OFF on any shared/hosted deployment — it would let a user reach
	// the operator's own machine.
	AllowLocalTargets bool

	// Auto-install gating — the LLM-driven terminal tool can call apt/cargo/npm
	// for missing binaries. Letting that happen under sudo on a multi-user box
	// is a privilege-escalation surface, so it's now opt-in.
	AllowAutoInstall     bool // XALGORIX_ALLOW_AUTO_INSTALL - permit package auto-install (default false unless root)
	AllowAutoInstallSudo bool // XALGORIX_AUTO_INSTALL_SUDO  - permit sudo-prefixed installs (default false)

	// Proxy settings
	UseProxy      bool   // XALGORIX_USE_PROXY — enable proxy support
	ProxyRequired bool   // XALGORIX_PROXY_REQUIRED — require one configured proxy for target-facing HTTP/browser traffic
	ProxyFile     string // XALGORIX_PROXY_FILE — path to proxies.txt
	ProxyRotation string // XALGORIX_PROXY_ROTATION — "roundrobin" (default) or "random"
	ProxyURL      string // XALGORIX_PROXY_URL — single proxy URL (overrides file)

	// Paths
	HomeDir     string // ~/.xalgorix
	SkillsDir   string // embedded or local skills directory
	BrowserPath string // XALGORIX_BROWSER_PATH — override auto-download with custom Chrome path

	// Filesystem read deny-list. Reads outside the Allow_List are
	// permitted by default so tools can use system wordlists, payload
	// directories, and other shared assets. Entries here are
	// canonicalized prefix matches that REVOKE that default for
	// sensitive locations (~/.ssh, ~/.aws, /etc/shadow, etc.). Set
	// XALGORIX_READ_DENY_LIST to a colon-separated list of additional
	// roots; defaults are merged in. See sandbox.Policy.CheckRead.
	ReadDenyList []string // XALGORIX_READ_DENY_LIST
}

var (
	globalConfig *Config
	configOnce   sync.Once
)

// Get returns the global configuration singleton.
func Get() *Config {
	configOnce.Do(func() {
		globalConfig = load()
	})
	return globalConfig
}

// load reads all configuration from environment variables with defaults.
// It first loads env files so config works even under sudo.
func load() *Config {
	// Load env files (lower priority first, later files override)
	loadEnvFile("/etc/xalgorix.env")
	// Try the actual user's home (works even under sudo)
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		loadEnvFile(filepath.Join("/home", sudoUser, ".xalgorix.env"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: failed to get home directory: %v (using /root)", err)
		home = "/root"
	}
	loadEnvFile(filepath.Join(home, ".xalgorix.env"))

	xalgorixHome := filepath.Join(home, ".xalgorix")

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("Warning: failed to get working directory: %v", err)
		cwd = home
	}
	// Capture the user's *original* intent for Data_Dir / Workspace selection
	// before the backwards-compat shim runs. The migration-warning
	// suppression check (R7.4) needs to see whether the user explicitly
	// pinned a workspace path; if we sampled XALGORIX_DATA_DIR after the
	// shim ran, the shim's synthetic value would always look like an
	// override and we'd never warn legitimate cases.
	originalDataDirEnv := os.Getenv("XALGORIX_DATA_DIR")
	originalWorkspaceEnv := os.Getenv("XALGORIX_WORKSPACE")
	// Backwards-compat shim for legacy XALGORIX_WORKSPACE: if it's set and
	// XALGORIX_DATA_DIR is not, treat XALGORIX_WORKSPACE as if it were
	// XALGORIX_DATA_DIR and emit a deprecation notice. External scripts that
	// pin a workspace path therefore keep working without change.
	if originalWorkspaceEnv != "" && originalDataDirEnv == "" {
		log.Printf("[config] WARN XALGORIX_WORKSPACE is deprecated; please use XALGORIX_DATA_DIR=%s", originalWorkspaceEnv)
		_ = os.Setenv("XALGORIX_DATA_DIR", originalWorkspaceEnv)
	}
	// Resolve the per-installation Data_Dir (R6.1–R6.3, R6.7). On failure we
	// emit a non-fatal warning and fall back to $CWD so the binary doesn't
	// crash hard during startup; Task 3.4 adds the strict Validate() guard
	// that turns this into a fatal error.
	dataDir, err := resolveDataDir(home)
	if err != nil {
		log.Printf("[config] WARN Data_Dir resolution failed: %v — falling back to CWD", err)
		dataDir = cwd
	}
	// Workspace is now an alias for DataDir (R6.4). The legacy
	// XALGORIX_WORKSPACE env var is honored above as a backwards-compat shim.
	workspace := dataDir

	cfg := &Config{
		// LLM
		LLM:                  envOr("XALGORIX_LLM", ""),
		LLMProvider:          envOr("XALGORIX_LLM_PROVIDER", ""),
		APIBase:              envOr("XALGORIX_API_BASE", ""),
		APIKey:               envOr("XALGORIX_API_KEY", ""),
		LLMProfile:           envOr("XALGORIX_LLM_PROFILE", ""),
		ReasoningEffort:      envOr("XALGORIX_REASONING_EFFORT", "high"),
		Language:             NormalizeLanguage(envOr("XALGORIX_LANGUAGE", DefaultLanguage)),
		OllamaCompatible:     envOrBool("XALGORIX_OLLAMA_COMPATIBLE", false),
		Temperature:          envOrFloatPtr("XALGORIX_TEMPERATURE", 0.2),
		LLMMaxRetries:        envOrInt("XALGORIX_LLM_MAX_RETRIES", 5),
		MaxRateLimitWaitSec:  envOrInt("XALGORIX_MAX_RATE_LIMIT_WAIT", 30*60),
		MaxOutputTokens:      envOrInt("XALGORIX_MAX_OUTPUT_TOKENS", 8192),
		ContextCompactTokens: envOrInt("XALGORIX_CONTEXT_COMPACT_TOKENS", -1),
		LLMContextWindow:     envOrInt("XALGORIX_LLM_CONTEXT_WINDOW", 128000),
		ContextCompactRatio:  envOrFloat("XALGORIX_CONTEXT_COMPACT_RATIO", 0.75),
		MemCompTimeout:       envOrInt("XALGORIX_MEMORY_COMPRESSOR_TIMEOUT", 30),

		// Gemini content-filter posture (native Gemini API path only). Default
		// BLOCK_NONE so authorized security-testing output is not refused;
		// DEFAULT / "" restores Google's server-side defaults.
		GeminiSafetyThreshold: envOr("XALGORIX_GEMINI_SAFETY", "BLOCK_NONE"),

		// Runtime
		RuntimeBackend:        "native", // Always native in Go version
		Workspace:             workspace,
		DataDir:               dataDir,
		WorkspaceRoot:         dataDir,
		legacyCWD:             cwd,
		DisableBrowser:        envOrBool("XALGORIX_DISABLE_BROWSER", false),
		MaxIterations:         envOrInt("XALGORIX_MAX_ITERATIONS", 0),
		MinIterations:         envOrInt("XALGORIX_MIN_ITERATIONS", 50),
		MaxWildcardSubdomains: envOrInt("XALGORIX_MAX_WILDCARD_SUBDOMAINS", -1),
		NoToolAbortAt:         envOrInt("XALGORIX_NO_TOOL_ABORT_AT", 30),
		MaxFinishRejections:   envOrInt("XALGORIX_MAX_FINISH_REJECTIONS", 15),
		TargetAuth:            envOr("XALGORIX_TARGET_AUTH", ""),
		TargetAuthSecondary:   envOr("XALGORIX_TARGET_AUTH_B", ""),
		OOBPublicURL:          envOr("XALGORIX_OOB_PUBLIC_URL", ""),
		OOBPort:               envOrInt("XALGORIX_OOB_PORT", 0),
		InteractshServer:      envOr("XALGORIX_INTERACTSH_SERVER", ""),
		InteractshToken:       envOr("XALGORIX_INTERACTSH_TOKEN", ""),
		OOBDisable:            envOrBool("XALGORIX_OOB_DISABLE", false),
		OOBInteractions:       envOr("XALGORIX_OOB_INTERACTIONS", ""),
		SourceRepo:            envOr("XALGORIX_SOURCE_REPO", ""),
		ScanContext:           envOr("XALGORIX_SCAN_CONTEXT", ""),
		ScanHeaders:           loadScanHeaders(),
		MaxToolCalls:          envOrInt("XALGORIX_MAX_TOOL_CALLS", 0),
		MaxDurationSec:        envOrInt("XALGORIX_MAX_DURATION", 0),
		MaxTokens:             envOrInt("XALGORIX_MAX_TOKENS", 0),

		// Scan retention: 0 disables automatic pruning (keep forever).
		ScanRetentionDays: envOrInt("XALGORIX_SCAN_RETENTION_DAYS", 0),

		// Rate limiting (defaults: 60 requests per 60 seconds)
		RateLimitRequests: envOrInt("XALGORIX_RATE_LIMIT_REQUESTS", 60),
		RateLimitWindow:   envOrInt("XALGORIX_RATE_LIMIT_WINDOW", 60),
		RateLimitRPS:      envOrFloat("XALGORIX_RATE_RPS", 10),
		RateLimitBurst:    envOrInt("XALGORIX_RATE_BURST", 20),
		TLSSkipVerify:     envOrBool("XALGORIX_TLS_SKIP_VERIFY", envOrBool("XALGORIX_TLS_INSECURE_SKIP_VERIFY", false)),

		// Caido
		CaidoPort:     envOrInt("CAIDO_PORT", 0), // 0 = auto-detect
		CaidoAPIToken: envOr("CAIDO_API_TOKEN", ""),

		// Telemetry
		Telemetry:    envOrBool("XALGORIX_TELEMETRY", true),
		OTelEndpoint: envOr("XALGORIX_OTEL_ENDPOINT", ""),

		// Web Search API
		GeminiAPIKey:    envOr("GEMINI_API_KEY", ""),
		AgentMailAPIKey: envOr("AGENTMAIL_API_KEY", ""),
		AgentMailPod:    envOr("AGENTMAIL_POD", ""),

		// Discord notifications
		DiscordWebhook:     envOr("XALGORIX_DISCORD_WEBHOOK", ""),
		DiscordMinSeverity: envOr("XALGORIX_DISCORD_MIN_SEVERITY", ""),

		// Telegram notifications
		TelegramBotToken:    envOr("XALGORIX_TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:      envOr("XALGORIX_TELEGRAM_CHAT_ID", ""),
		TelegramMinSeverity: envOr("XALGORIX_TELEGRAM_MIN_SEVERITY", ""),

		// Scan-completion summary notification (opt-in; default off).
		NotifyScanComplete: envOrBool("XALGORIX_NOTIFY_SCAN_COMPLETE", false),

		// Dashboard auth
		Username:     envOr("XALGORIX_USERNAME", ""),
		Password:     envOr("XALGORIX_PASSWORD", ""),
		PasswordHash: envOr("XALGORIX_PASSWORD_HASH", ""),

		// Network binding — loopback-only by default.
		BindAddr: envOr("XALGORIX_BIND", "127.0.0.1"),

		// Self-hosted opt-in to scan locally-hosted apps (off by default; the
		// dashboard's own listener stays protected regardless).
		AllowLocalTargets: envOrBool("XALGORIX_ALLOW_LOCAL_TARGETS", false),

		// Auto-install gates — default off for non-root; root sessions keep the
		// historical behavior so existing systemd deployments keep working.
		AllowAutoInstall:     envOrBool("XALGORIX_ALLOW_AUTO_INSTALL", os.Getuid() == 0),
		AllowAutoInstallSudo: envOrBool("XALGORIX_AUTO_INSTALL_SUDO", false),

		// Proxy
		UseProxy:      envOrBool("XALGORIX_USE_PROXY", false),
		ProxyRequired: envOrBool("XALGORIX_PROXY_REQUIRED", false),
		ProxyFile:     envOr("XALGORIX_PROXY_FILE", ""),
		ProxyRotation: envOr("XALGORIX_PROXY_ROTATION", "roundrobin"),
		ProxyURL:      envOr("XALGORIX_PROXY_URL", ""),

		// Paths
		HomeDir:     xalgorixHome,
		SkillsDir:   filepath.Join(xalgorixHome, "skills"),
		BrowserPath: envOr("XALGORIX_BROWSER_PATH", ""),

		// Filesystem read deny-list. Defaults applied in resolveReadDenyList
		// (sensitive home and system paths); user list extends them.
		ReadDenyList: resolveReadDenyList(home, os.Getenv("XALGORIX_READ_DENY_LIST")),
	}

	// Debug: show loaded config so users can verify correct env was picked up.
	// Gated behind XALGORIX_DEBUG_CONFIG so it doesn't pollute every CLI
	// invocation; the install/setup flows that benefit from this can opt in
	// by exporting the var, and the dashboard logs an explicit "Loaded
	// config" message at boot anyway.
	if envOrBool("XALGORIX_DEBUG_CONFIG", false) {
		maskedKey := ""
		if len(cfg.APIKey) > 8 {
			maskedKey = cfg.APIKey[:4] + "****" + cfg.APIKey[len(cfg.APIKey)-4:]
		} else if cfg.APIKey != "" {
			maskedKey = "****"
		}
		fmt.Printf("[config] Loaded: LLM=%q APIBase=%q APIKey=%s UseProxy=%v\n", cfg.LLM, cfg.APIBase, maskedKey, cfg.UseProxy)
	}

	// R6.7: announce the resolved Data_Dir / Workspace_Root once at startup
	// so operators can see at a glance where artifacts will land.
	log.Printf("[config] Data_Dir=%s Workspace_Root=%s", cfg.DataDir, cfg.WorkspaceRoot)

	// R7: emit the Migration_Warning when a legacy $CWD layout is detected.
	// Suppressed by an explicit XALGORIX_DATA_DIR or the legacy
	// XALGORIX_WORKSPACE override (R7.4); idempotence (R7.3) is provided by
	// configOnce since this only runs from load().
	suppressMigrationWarning := originalDataDirEnv != "" || originalWorkspaceEnv != ""
	maybeEmitMigrationWarning(cwd, cfg.DataDir, suppressMigrationWarning)

	return cfg
}

// ResolveModel resolves a model name.
func (c *Config) ResolveModel() string {
	model := c.LLM
	if model == "" {
		return ""
	}
	return model
}

// WorkspacePath resolves a path relative to the workspace root.
//
// Per R6.4, Workspace_Root is the canonical resolution root for relative
// inputs and equals Data_Dir. Workspace remains as an alias for backwards
// compatibility, but new resolution logic (and any code reading from this
// helper) goes through WorkspaceRoot so the intent is explicit and the
// behavior stays correct if the two ever diverge.
func (c *Config) WorkspacePath(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(c.WorkspaceRoot, rel)
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	// R6.5: refuse to start when Data_Dir resolution failed. load() logs a
	// non-fatal warning and falls back to CWD so the binary doesn't crash
	// before Validate() runs, but any boot path that calls Validate() must
	// surface this as a hard error rather than silently scribbling files
	// into the user's working directory.
	if c.DataDir == "" {
		return fmt.Errorf("DataDir is empty — Data_Dir resolution failed; check XALGORIX_DATA_DIR or HOME and verify the binary can create ~/.xalgorix/data with mode 0o700")
	}
	if c.LLM == "" {
		return fmt.Errorf("XALGORIX_LLM is required. Set it to a provider-native model ID such as 'gpt-5.6' or 'claude-fable-5'")
	}
	if c.APIKey == "" && c.LLMProfile == "" && !c.providerAllowsNoAuth() {
		return fmt.Errorf("XALGORIX_API_KEY is required for the selected provider. Run 'xalgorix --setup' to configure it")
	}
	return nil
}

func (c *Config) providerAllowsNoAuth() bool {
	providerID := strings.ToLower(strings.TrimSpace(c.LLMProvider))
	if providerID == "" {
		if slash := strings.IndexByte(c.LLM, '/'); slash > 0 {
			providerID = strings.ToLower(strings.TrimSpace(c.LLM[:slash]))
		}
	}
	entry, ok := providers.LookupBuiltin(providerID)
	if !ok {
		return false
	}
	for _, method := range entry.AuthMethods {
		if method == "none" {
			return true
		}
	}
	return false
}

// CheckEnvFile checks whether the per-user configuration is ready for a scan.
// It uses the same rules as Config.Validate, including profile-based and
// credential-free local providers.
func CheckEnvFile() error {
	envPath := EnvFilePath()
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s\n\nRun: xalgorix --setup", envPath)
	} else if err != nil {
		return fmt.Errorf("inspect configuration file: %w", err)
	}

	values, err := ReadEnvFile(envPath)
	if err != nil {
		return err
	}
	candidate := &Config{
		DataDir:     "configured",
		LLM:         values["XALGORIX_LLM"],
		LLMProvider: values["XALGORIX_LLM_PROVIDER"],
		APIKey:      values["XALGORIX_API_KEY"],
		LLMProfile:  values["XALGORIX_LLM_PROFILE"],
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("configuration file %s is incomplete: %w\n\nRun: xalgorix --setup", envPath, err)
	}
	return nil
}

// resolveDataDir picks the active Data_Dir, canonicalizes it, and creates it
// with mode 0o700 if it doesn't exist yet (R6.1, R6.2, R6.3). When the env
// var XALGORIX_DATA_DIR is unset it falls back to ~/.xalgorix/data/. Existing
// directories are tightened to 0o700 so we never trust looser ambient perms.
func resolveDataDir(home string) (string, error) {
	raw := os.Getenv("XALGORIX_DATA_DIR")
	if raw == "" {
		raw = filepath.Join(home, ".xalgorix", "data")
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("data dir %q: %w", raw, err)
	}
	abs = filepath.Clean(abs)
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("create data dir %q: %w", abs, err)
	}
	_ = os.Chmod(abs, 0o700) //nolint:gosec // G302: directory needs the execute bit; 0700 is correct for a dir
	return abs, nil
}

// maybeEmitMigrationWarning emits a single WARN-level [MIGRATION] log line
// when the binary is launched from a directory that looks like the legacy
// $CWD-rooted Xalgorix workspace layout (notes.json, _schedules/,
// vulnerabilities.json, or YYYY-MM-DD/scan-* output dirs) and the user has
// not pinned the workspace via XALGORIX_DATA_DIR or XALGORIX_WORKSPACE.
//
// Idempotence (R7.3) is provided by configOnce since the only call site is
// load(). This function never reads, copies, modifies, or deletes any
// legacy file (R7.5); it only stat()s known marker names.
func maybeEmitMigrationWarning(cwd, dataDir string, suppressed bool) {
	if suppressed {
		return // R7.4: explicit Data_Dir/Workspace override suppresses
	}
	if cwd == "" || filepath.Clean(cwd) == filepath.Clean(dataDir) {
		return
	}
	legacy := []string{
		"notes.json",
		"_schedules",
		"vulnerabilities.json",
	}
	found := ""
	for _, name := range legacy {
		if _, err := os.Stat(filepath.Join(cwd, name)); err == nil {
			found = name
			break
		}
	}
	if found == "" {
		// Glob date-pattern dirs (YYYY-MM-DD/scan-*).
		matches, _ := filepath.Glob(filepath.Join(cwd, "20??-??-??", "scan-*"))
		if len(matches) > 0 {
			found = "date-stamped scan output"
		}
	}
	if found == "" {
		return
	}
	log.Printf("[MIGRATION] Detected legacy workspace layout under %s "+
		"(matched %q). The default data directory has changed in this "+
		"release to %s. To keep writing to the legacy location, run with "+
		"XALGORIX_DATA_DIR=%s", cwd, found, dataDir, cwd)
}

// loadScanHeaders assembles the operator-configured scan/attribution headers
// from XALGORIX_SCAN_HEADERS (';'/newline-separated) and an optional
// XALGORIX_SCAN_HEADERS_FILE (one "Name: value" per line), de-duplicated with
// the env entries taking precedence. A missing/unreadable file is a non-fatal
// warning so a scan still runs (just without the file's headers).
func loadScanHeaders() []string {
	env := scanheaders.Parse(os.Getenv("XALGORIX_SCAN_HEADERS"))
	var fromFile []string
	if path := strings.TrimSpace(os.Getenv("XALGORIX_SCAN_HEADERS_FILE")); path != "" {
		hs, err := scanheaders.ParseFile(path)
		if err != nil {
			log.Printf("[config] Warning: XALGORIX_SCAN_HEADERS_FILE %q: %v", path, err)
		}
		fromFile = hs
	}
	return scanheaders.Merge(env, fromFile)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envOrFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return fallback
}

// envOrFloatPtr reads a float from the env and returns a pointer.
// This lets callers distinguish "not set" (returns &fallback) from
// "explicitly set to 0.0" (returns &0.0). Used by Temperature so that
// setting XALGORIX_TEMPERATURE=0 sends temperature=0.0 to the API
// instead of omitting it.
func envOrFloatPtr(key string, fallback float64) *float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return &n
		}
	}
	return &fallback
}

func envOrBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		v = strings.ToLower(v)
		return v == "1" || v == "true" || v == "yes"
	}
	return fallback
}

// loadEnvFile reads a KEY=VALUE env file and sets env vars.
// Later calls override earlier ones, so higher-priority files should be loaded last.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // File doesn't exist, skip silently
	}
	defer f.Close()

	// Warn (and tighten when we own the file) if perms are loose. The env
	// file holds API keys and the dashboard password in plaintext, so any
	// group/other read bit is a leak. Skipped on Windows where Unix mode
	// bits are not meaningful.
	if runtime.GOOS != "windows" {
		if info, statErr := f.Stat(); statErr == nil {
			mode := info.Mode().Perm()
			if mode&0o077 != 0 {
				log.Printf("[config] Warning: %s is mode %#o — contains plaintext secrets. Tightening to 0600.", path, mode)
				if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
					log.Printf("[config] Could not chmod %s to 0600: %v (please fix manually)", path, chmodErr)
				}
			}
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse KEY=VALUE (strip optional "export " prefix and quotes)
		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Strip surrounding quotes
		value = strings.Trim(value, "\"'")
		// Always set — later files override earlier ones
		_ = os.Setenv(key, value)
	}
}

// defaultReadDenyList returns the built-in deny-list applied to every
// Filesystem_Tool read. Reads outside the Allow_List are permitted by
// default (so tools can consume /usr/share/wordlists, payload dirs,
// system binaries, etc.); these entries REVOKE that default for
// sensitive locations only.
//
// Each entry is canonicalized at Policy construction time and treated
// as a prefix match (entry == path OR entry/ is a prefix of path).
func defaultReadDenyList(home string) []string {
	if home == "" {
		home = "/root"
	}
	return []string{
		// User secrets
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".azure"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".docker"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".pgpass"),
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		// System secrets
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/ssh",
		"/root/.ssh",
		"/root/.aws",
		"/root/.gnupg",
		// Process / kernel keyrings & memory
		"/proc/kcore",
		"/proc/kallsyms",
		// Encrypted volume keys
		"/etc/luks",
	}
}

// resolveReadDenyList composes the default deny-list with any extra
// entries supplied via XALGORIX_READ_DENY_LIST. Entries in the env var
// are colon-separated (Linux PATH convention); an empty string yields
// the defaults. Empty tokens are skipped.
func resolveReadDenyList(home, raw string) []string {
	out := defaultReadDenyList(home)
	if raw == "" {
		return out
	}
	for _, entry := range strings.Split(raw, ":") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			out = append(out, entry)
		}
	}
	return out
}
