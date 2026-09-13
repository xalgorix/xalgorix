package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
)

type envSettingDefinition struct {
	Key             string   `json:"key"`
	Label           string   `json:"label"`
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	DefaultValue    string   `json:"defaultValue,omitempty"`
	Placeholder     string   `json:"placeholder,omitempty"`
	InputType       string   `json:"inputType"`
	Options         []string `json:"options,omitempty"`
	Sensitive       bool     `json:"sensitive"`
	RequiresRestart bool     `json:"requiresRestart"`
}

type envSettingValue struct {
	envSettingDefinition
	Value    string `json:"value"`
	HasValue bool   `json:"hasValue"`
}

type environmentSettingsResponse struct {
	EnvFile         string            `json:"envFile"`
	Variables       []envSettingValue `json:"variables"`
	RestartRequired bool              `json:"restartRequired,omitempty"`
}

type llmSettingsResponse struct {
	Model                     string `json:"model"`
	APIBase                   string `json:"apiBase"`
	APIKey                    string `json:"apiKey"`
	HasAPIKey                 bool   `json:"hasApiKey"`
	ReasoningEffort           string `json:"reasoningEffort"`
	OllamaCompatible          bool   `json:"ollamaCompatible"`
	LLMMaxRetries             int    `json:"llmMaxRetries"`
	MemoryCompressorTimeout   int    `json:"memoryCompressorTimeout"`
	MaxIterations             int    `json:"maxIterations"`
	GeminiAPIKey              string `json:"geminiApiKey"`
	HasGeminiAPIKey           bool   `json:"hasGeminiApiKey"`
	EnvFile                   string `json:"envFile"`
	EnvironmentRestartWarning bool   `json:"environmentRestartWarning"`
	// v4.4.22: catalog-aware fields driving the new LLM Settings
	// tab. Provider mirrors the active provider id derived from
	// LLMProfile (or the legacy XALGORIX_LLM "<provider>/<model>"
	// prefix when no profile is active). AuthMethod tracks which
	// branch the resolver currently dispatches through. Profiles
	// is the masked list of saved profiles for the active
	// provider only — see handleLLMSettings GET for filtering.
	Provider         string              `json:"provider"`
	AuthMethod       string              `json:"authMethod"`
	ActiveProfileKey string              `json:"activeProfileKey"`
	Profiles         []llmProfileSummary `json:"profiles"`
}

// llmProfileSummary is the masked, dashboard-friendly view of one
// auth.Profile filtered to the active provider in the LLM tab.
// Wire shape mirrors maskedProfile in handlers_profiles.go but is
// declared independently so we never import handlers_profiles types.
type llmProfileSummary struct {
	Key             string `json:"key"`
	Provider        string `json:"provider"`
	ProfileID       string `json:"profileId"`
	Type            string `json:"type"`
	HasAccessToken  bool   `json:"hasAccessToken"`
	HasAPIKey       bool   `json:"hasApiKey"`
	APIBaseOverride string `json:"apiBaseOverride,omitempty"`
	ExpiresAt       string `json:"expiresAt,omitempty"`
	RequiresReauth  bool   `json:"requiresReauth,omitempty"`
}

// llmSettingsRequest is the shared decoded shape of POST
// /api/settings/llm. Both the legacy field set
// (model/apiBase/apiKey/...) and the v4.4.22 field set
// (provider/authMethod/profileId/activeProfileKey/...) decode into
// this struct; handleLLMSettings sniffs which branch to take by
// presence of provider/authMethod/activeProfileKey.
type llmSettingsRequest struct {
	// Legacy fields (kept for backwards compat).
	Model                   string `json:"model"`
	APIBase                 string `json:"apiBase"`
	APIKey                  string `json:"apiKey"`
	ReasoningEffort         string `json:"reasoningEffort"`
	OllamaCompatible        *bool  `json:"ollamaCompatible"`
	LLMMaxRetries           int    `json:"llmMaxRetries"`
	MemoryCompressorTimeout int    `json:"memoryCompressorTimeout"`
	MaxIterations           int    `json:"maxIterations"`
	GeminiAPIKey            string `json:"geminiApiKey"`

	// v4.4.22 fields.
	Provider         string `json:"provider"`
	AuthMethod       string `json:"authMethod"`
	ProfileID        string `json:"profileId"`
	APIBaseOverride  string `json:"apiBaseOverride"`
	ActiveProfileKey string `json:"activeProfileKey"`
}

var envSettingKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func allEnvSettingDefinitions() []envSettingDefinition {
	autoInstallDefault := "false"
	if os.Getuid() == 0 {
		autoInstallDefault = "true"
	}
	return []envSettingDefinition{
		{Key: "XALGORIX_LLM", Label: "LLM model", Category: "LLM", Description: "Provider-native model ID used by scans and post-scan chat. For best results, choose a current frontier model with strong reasoning and tool calling.", Placeholder: "gpt-5.6", InputType: "text"},
		{Key: "XALGORIX_LLM_PROVIDER", Label: "LLM provider", Category: "LLM", Description: "Explicit provider ID used to route the selected model without adding a provider prefix to its model name.", Placeholder: "ollama", InputType: "text"},
		{Key: "XALGORIX_API_KEY", Label: "LLM API key", Category: "LLM", Description: "Provider API key for the configured model.", Placeholder: "sk-...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_API_BASE", Label: "API base URL", Category: "LLM", Description: "Optional custom provider endpoint. Leave blank to use provider defaults.", Placeholder: "https://api.openai.com/v1", InputType: "url"},
		{Key: "XALGORIX_LLM_PROFILE", Label: "Active LLM profile", Category: "LLM", Description: "Active credential pointer (\"<provider>:<profileId>\"). Set by the LLM Settings tab; takes precedence over XALGORIX_API_KEY/XALGORIX_LLM when present.", Placeholder: "openai:default", InputType: "text"},
		{Key: "XALGORIX_REASONING_EFFORT", Label: "Reasoning effort", Category: "LLM", Description: "Reasoning depth for providers that support it.", DefaultValue: "high", InputType: "select", Options: []string{"none", "low", "medium", "high", "xhigh"}},
		{Key: "XALGORIX_LANGUAGE", Label: "Output language", Category: "LLM", Description: "Language for AI-generated human-readable output: agent reasoning, notes, vulnerability findings, report content, and post-scan chat. Technical tokens (payloads, commands, URLs, CVE/CWE IDs) always stay in their original form. English is the default. Non-Latin languages render in the dashboard and HTML report automatically; for the PDF export, also set a CJK font path below.", DefaultValue: "en", InputType: "select", Options: []string{"en", "zh-CN"}},
		{Key: "XALGORIX_PDF_CJK_FONT", Label: "PDF CJK font path", Category: "LLM", Description: "Absolute path to a TrueType (.ttf) font with CJK glyphs, used to render non-Latin languages (e.g. Simplified Chinese) in the exported PDF report. Only .ttf is supported (not .ttc/.otf). Leave blank for English. Takes effect on restart.", Placeholder: "/usr/share/fonts/truetype/noto/NotoSansSC-Regular.ttf", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_OLLAMA_COMPATIBLE", Label: "Ollama-compatible endpoint", Category: "LLM", Description: "Force Ollama reasoning semantics for a custom endpoint that does not use port 11434.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_LLM_MAX_RETRIES", Label: "LLM max retries", Category: "LLM", Description: "Retry count for transient LLM provider failures.", DefaultValue: "5", InputType: "number"},
		{Key: "XALGORIX_MAX_RATE_LIMIT_WAIT", Label: "Provider rate-limit wait (seconds)", Category: "LLM", Description: "Maximum cumulative wait after a provider 429/usage-window error before stopping the scan. Default 1800 seconds; use a negative value only to disable the safety cap.", DefaultValue: "1800", InputType: "number"},
		{Key: "XALGORIX_MAX_OUTPUT_TOKENS", Label: "Max output tokens", Category: "LLM", Description: "Per-call completion cap (max_tokens). Reasoning models spend part of this on hidden thinking before a tool call, so a small provider default can truncate large calls. Clamped to a 1024 floor.", DefaultValue: "8192", InputType: "number"},
		{Key: "XALGORIX_LLM_CONTEXT_WINDOW", Label: "LLM context window (tokens)", Category: "LLM", Description: "Total context window of your model, in tokens. Auto-compaction fires at a fraction of this (see compaction ratio) so the running context is only compacted when the window is genuinely filling up. Set to your model's real window (e.g. 1000000 for a 1M-token model). Default 128000.", DefaultValue: "128000", InputType: "number"},
		{Key: "XALGORIX_CONTEXT_COMPACT_RATIO", Label: "Context compaction ratio", Category: "LLM", Description: "Fraction of the context window at which to auto-compact (0.5–0.9). Default 0.75 = compact at ~75% full. Compacting earlier discards useful working context and hurts output quality; going higher risks hitting the provider's hard limit first.", DefaultValue: "0.75", InputType: "number"},
		{Key: "XALGORIX_CONTEXT_COMPACT_TOKENS", Label: "Context compaction budget (tokens, override)", Category: "LLM", Description: "Optional ABSOLUTE override for the compaction trigger. Leave at -1 (auto) to derive the trigger from the context window × ratio above. Set a positive token count to force a fixed budget instead. 0 disables auto-compaction. Default -1 (auto).", DefaultValue: "-1", InputType: "number"},
		{Key: "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT", Label: "Memory compressor timeout", Category: "LLM", Description: "Timeout in seconds for context compression.", DefaultValue: "30", InputType: "number"},
		{Key: "XALGORIX_MAX_ITERATIONS", Label: "Max iterations", Category: "Runtime", Description: "Maximum agent iterations per scan. 0 means unlimited.", DefaultValue: "0", InputType: "number"},
		{Key: "XALGORIX_MIN_ITERATIONS", Label: "Min iterations (testing floor)", Category: "Runtime", Description: "Minimum testing floor in iterations before the gatekeeper permits finish. Ensures deep probing (OAST, ReDoS, fuzzing) before concluding.", DefaultValue: "50", InputType: "number"},
		{Key: "XALGORIX_NO_TOOL_ABORT_AT", Label: "No-tool loop limit", Category: "Runtime", Description: "Consecutive assistant responses without a parsed tool call before cleanly stopping. Default 30; 0 disables this safety limit.", DefaultValue: "30", InputType: "number"},
		{Key: "XALGORIX_MAX_WILDCARD_SUBDOMAINS", Label: "Wildcard subdomain cap", Category: "Runtime", Description: "Optional maximum full LLM sessions expanded from one wildcard target. Default -1 means unlimited; set a positive value only for an explicit emergency resource cap.", DefaultValue: "-1", InputType: "number"},
		{Key: "XALGORIX_MAX_FINISH_REJECTIONS", Label: "Max finish rejections", Category: "Runtime", Description: "Number of times the agent's finish call will be rejected by the gatekeeper before allowing a deadlock bypass, enforcing deeper testing coverage.", DefaultValue: "15", InputType: "number"},
		{Key: "XALGORIX_MAX_TOOL_CALLS", Label: "Max tool calls (budget)", Category: "Runtime", Description: "Per-scan tool-call cap; the scan stops cleanly when reached (findings preserved). 0 = unlimited.", DefaultValue: "0", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_MAX_DURATION", Label: "Max duration seconds (budget)", Category: "Runtime", Description: "Per-scan wall-clock cap in seconds; the scan stops cleanly when reached. 0 = unlimited.", DefaultValue: "0", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_MAX_TOKENS", Label: "Max LLM tokens (budget)", Category: "Runtime", Description: "Per-scan total-token cap; the scan stops cleanly when reached. 0 = unlimited.", DefaultValue: "0", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_TARGET_AUTH", Label: "Target auth (authenticated scanning)", Category: "Runtime", Description: "Authenticated-session credentials for the target so the agent tests post-auth surface (IDOR/BOLA, privilege escalation, business logic). One 'Header-Name: value' per line or separated by ';'. e.g. 'Cookie: session=abc; Authorization: Bearer xyz'. Auto-applied to http_request.", Placeholder: "Cookie: session=...; Authorization: Bearer ...", InputType: "text", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_SCAN_HEADERS", Label: "Scan headers (attribution)", Category: "Runtime", Description: "Identifying header(s) added to ALL target-facing scan traffic (agent HTTP client + httpx/nuclei via -H) so an authorized Xalgorix run is attributable in the target's logs and can be allow-listed by its WAF/SOC. Bug-bounty programs often require one, e.g. 'X-Bug-Bounty: <handle>'. One 'Header-Name: value' per entry, separated by ';'. Never attached to LLM APIs, notifications, or the dashboard.", Placeholder: "X-Bug-Bounty: ulises2k; X-Scan-ID: engagement-42", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_HEADERS_FILE", Label: "Scan headers file", Category: "Runtime", Description: "Path to a file of scan/attribution headers, one 'Name: value' per line ('#' comments and blank lines ignored). Merged with XALGORIX_SCAN_HEADERS; the inline value wins on a name clash.", Placeholder: "/path/to/scan-headers.txt", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_OOB_PUBLIC_URL", Label: "OOB callback URL", Category: "OOB", Description: "Public address targets can reach for out-of-band verification of blind vulns (blind SSRF/RCE/XSS/XXE), e.g. https://oob.example.com. Enables the self-hosted oob_callback listener. Leave blank to use the zero-config interactsh backend.", Placeholder: "https://oob.example.com", InputType: "url", RequiresRestart: true},
		{Key: "XALGORIX_OOB_PORT", Label: "OOB listener port", Category: "OOB", Description: "Local port the OOB callback listener binds (0.0.0.0). Expose/reverse-proxy it to the OOB callback URL above.", Placeholder: "8888", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_OOB_INTERACTIONS", Label: "OOB interaction types", Category: "OOB", Description: "Which out-of-band interaction types count as a callback (proof). All selected = default (any DNS/HTTP/SMTP hit is proof). Deselect DNS to suppress DNS-only false positives from cloud infra (e.g. AWS resolvers that merely resolve the callback host). HTTP also covers HTTPS. Other interactsh channels (LDAP for JNDI/Log4Shell, SMB, FTP) are always kept. Note the self-hosted listener (OOB callback URL) only ever reports HTTP(S), so a DNS-only selection suppresses all of its callbacks.", DefaultValue: "dns,http,smtp", InputType: "multiselect", Options: []string{"dns", "http", "smtp"}, RequiresRestart: true},
		{Key: "XALGORIX_SOURCE_REPO", Label: "Whitebox source (repo/path)", Category: "Runtime", Description: "Enable whitebox / source-assisted assessment. A Git URL (shallow-cloned) or a local directory path to the target's source. Activates the code_search tool and source→sink→exploit methodology — where RCE, injection, and secret-exposure bugs are found.", Placeholder: "https://github.com/org/app.git", InputType: "text", RequiresRestart: true},
		{Key: "GEMINI_API_KEY", Label: "Gemini web-search key", Category: "LLM", Description: "Optional Gemini key for web search enrichment.", Placeholder: "AIza...", InputType: "secret", Sensitive: true},

		{Key: "XALGORIX_DISCORD_WEBHOOK", Label: "Discord webhook", Category: "Notifications", Description: "Global Discord webhook used when a scan does not provide its own.", Placeholder: "https://discord.com/api/webhooks/...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_DISCORD_MIN_SEVERITY", Label: "Discord minimum severity", Category: "Notifications", Description: "Minimum severity sent to Discord.", InputType: "select", Options: []string{"", "info", "low", "medium", "high", "critical"}},

		{Key: "XALGORIX_TELEGRAM_BOT_TOKEN", Label: "Telegram bot token", Category: "Notifications", Description: "Bot token from @BotFather. Required to enable Telegram notifications.", Placeholder: "123456789:ABC-DEF...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_TELEGRAM_CHAT_ID", Label: "Telegram chat ID", Category: "Notifications", Description: "Target chat/channel ID. Numeric ID (e.g. -1001234567890) or @channelusername.", Placeholder: "-1001234567890", InputType: "text"},
		{Key: "XALGORIX_TELEGRAM_MIN_SEVERITY", Label: "Telegram minimum severity", Category: "Notifications", Description: "Minimum severity sent to Telegram.", InputType: "select", Options: []string{"", "info", "low", "medium", "high", "critical"}},
		{Key: "XALGORIX_NOTIFY_SCAN_COMPLETE", Label: "Notify on scan completion", Category: "Notifications", Description: "Send the \"Scan Finished\" summary (report ready / clean scan) to the configured channels after every scan. Off by default so only per-vulnerability alerts are sent.", DefaultValue: "false", InputType: "boolean"},

		{Key: "AGENTMAIL_POD", Label: "AgentMail pod", Category: "AgentMail", Description: "AgentMail pod identifier.", Placeholder: "am_us_pod_47", InputType: "text"},
		{Key: "AGENTMAIL_API_KEY", Label: "AgentMail API key", Category: "AgentMail", Description: "AgentMail API key for inbound email triage.", Placeholder: "ak_...", InputType: "secret", Sensitive: true},

		{Key: "XALGORIX_RATE_LIMIT_REQUESTS", Label: "Rate-limit requests", Category: "Rate limits", Description: "Requests allowed per dashboard rate-limit window.", DefaultValue: "60", InputType: "number"},
		{Key: "XALGORIX_RATE_LIMIT_WINDOW", Label: "Rate-limit window", Category: "Rate limits", Description: "Rate-limit window in seconds.", DefaultValue: "60", InputType: "number"},
		{Key: "XALGORIX_RATE_RPS", Label: "Outbound RPS", Category: "Rate limits", Description: "Sustained per-domain outbound request rate.", DefaultValue: "10", InputType: "number"},
		{Key: "XALGORIX_RATE_BURST", Label: "Outbound burst", Category: "Rate limits", Description: "Per-domain outbound burst size.", DefaultValue: "20", InputType: "number"},

		{Key: "XALGORIX_USE_PROXY", Label: "Use proxy", Category: "Proxy", Description: "Enable proxy routing for outbound traffic. Takes effect after restart.", DefaultValue: "false", InputType: "boolean", RequiresRestart: true},
		{Key: "XALGORIX_PROXY_REQUIRED", Label: "Require proxy for scan HTTP", Category: "Proxy", Description: "Reject missing proxy configuration; route built-in scan HTTP/browser via the proxy and fail requests if it is down. Shell tools still require network isolation. Takes effect after restart.", DefaultValue: "false", InputType: "boolean", RequiresRestart: true},
		{Key: "XALGORIX_PROXY_URL", Label: "Proxy URL", Category: "Proxy", Description: "Single proxy URL. Overrides proxy file when set. Takes effect after restart.", Placeholder: "socks5://user:pass@127.0.0.1:1080", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_PROXY_FILE", Label: "Proxy file", Category: "Proxy", Description: "Path to a file with one proxy per line. Takes effect after restart.", Placeholder: "/path/to/proxies.txt", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_PROXY_ROTATION", Label: "Proxy rotation", Category: "Proxy", Description: "Proxy rotation strategy. Takes effect after restart.", DefaultValue: "roundrobin", InputType: "select", Options: []string{"roundrobin", "random"}, RequiresRestart: true},
		{Key: "XALGORIX_TLS_SKIP_VERIFY", Label: "Skip TLS verification", Category: "Proxy", Description: "Allow insecure TLS verification for proxied/testing traffic.", DefaultValue: "false", InputType: "boolean"},

		{Key: "XALGORIX_WORKSPACE", Label: "Workspace", Category: "Runtime", Description: "Workspace root for scan execution.", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_DISABLE_BROWSER", Label: "Disable browser", Category: "Runtime", Description: "Disable browser automation tools.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_BROWSER_PATH", Label: "Browser path", Category: "Runtime", Description: "Custom Chrome/Chromium executable path.", InputType: "path"},
		{Key: "XALGORIX_ALLOW_AUTO_INSTALL", Label: "Allow auto-install", Category: "Runtime", Description: "Permit the agent to auto-install missing packages.", DefaultValue: autoInstallDefault, InputType: "boolean"},
		{Key: "XALGORIX_AUTO_INSTALL_SUDO", Label: "Allow sudo auto-install", Category: "Runtime", Description: "Permit sudo-prefixed auto-installs.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_ALLOW_ABSOLUTE_FILEEDIT", Label: "Allow absolute file edits", Category: "Runtime", Description: "Allow file-edit tooling to write absolute paths.", DefaultValue: "false", InputType: "boolean"},

		{Key: "XALGORIX_USERNAME", Label: "Dashboard username", Category: "Security", Description: "Dashboard login username.", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD", Label: "Dashboard password", Category: "Security", Description: "Plaintext dashboard password. Prefer XALGORIX_PASSWORD_HASH.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD_HASH", Label: "Dashboard password hash", Category: "Security", Description: "Bcrypt dashboard password hash.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_BIND", Label: "Bind address", Category: "Security", Description: "Web server listen address.", DefaultValue: "127.0.0.1", Placeholder: "127.0.0.1", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_ALLOW_LOCAL_TARGETS", Label: "Allow local targets", Category: "Security", Description: "Permit scanning locally-hosted apps (localhost / 127.0.0.1 / private IPs) — for self-hosted demo/staging on the same box. The dashboard's own listener is always protected. Leave OFF on shared/hosted deployments.", DefaultValue: "false", InputType: "boolean"},

		{Key: "CAIDO_PORT", Label: "Caido port", Category: "Integrations", Description: "Caido proxy port. 0 means auto-detect.", DefaultValue: "0", InputType: "number"},
		{Key: "CAIDO_API_TOKEN", Label: "Caido API token", Category: "Integrations", Description: "Caido API token for proxy integration.", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_TELEMETRY", Label: "Telemetry", Category: "Integrations", Description: "Enable OpenTelemetry export.", DefaultValue: "true", InputType: "boolean"},
		{Key: "XALGORIX_OTEL_ENDPOINT", Label: "OTel endpoint", Category: "Integrations", Description: "OpenTelemetry collector endpoint.", InputType: "url"},

		{Key: "XALGORIX_CPU_CAUTION_PCT", Label: "CPU caution percent", Category: "Resources", Description: "CPU load caution threshold.", DefaultValue: "70", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_CPU_CRITICAL_PCT", Label: "CPU critical percent", Category: "Resources", Description: "CPU load critical threshold.", DefaultValue: "90", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_RAM_CAUTION_MB", Label: "RAM caution MB", Category: "Resources", Description: "Available RAM caution threshold.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_RAM_CRITICAL_MB", Label: "RAM critical MB", Category: "Resources", Description: "Available RAM critical threshold.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_DISK_CAUTION_MB", Label: "Disk caution MB", Category: "Resources", Description: "Free disk caution threshold.", DefaultValue: "2048", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_DISK_CRITICAL_MB", Label: "Disk critical MB", Category: "Resources", Description: "Free disk critical threshold.", DefaultValue: "1024", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_MAX_INSTANCES", Label: "Max instances", Category: "Resources", Description: "Authoritative concurrent scan capacity when set; automatic RAM-based capacity is used when unset.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_CPU_LOAD", Label: "Heavy tool CPU load", Category: "Resources", Description: "Expected CPU load per heavy terminal tool. Empty means auto-scale from CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_MEMORY_BUDGET_MB", Label: "Scan memory budget MB", Category: "Resources", Description: "Memory budget per active scan. Empty means auto-scale from RAM and CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_OVERHEAD_MB", Label: "Scan overhead MB", Category: "Resources", Description: "Reserved memory overhead per scan. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", Label: "Heavy tool memory limit MB", Category: "Resources", Description: "Optional hard address-space limit for heavy terminal tools. Empty or 0 leaves hard limiting disabled; dynamic admission still uses live RAM headroom.", Placeholder: "disabled", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_GO_MEM_LIMIT_MB", Label: "Go memory limit MB", Category: "Resources", Description: "Soft memory limit for the Xalgorix parent process. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
	}
}

func envDefinitionByKey() map[string]envSettingDefinition {
	defs := allEnvSettingDefinitions()
	out := make(map[string]envSettingDefinition, len(defs))
	for _, def := range defs {
		out[def.Key] = def
	}
	return out
}

func (s *Server) handleLLMSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.llmSettings(r.Context()))
	case http.MethodPost:
		var req llmSettingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Sniff which shape the client sent. Any of provider /
		// authMethod / activeProfileKey present → catalog-aware
		// path. Otherwise → legacy free-text path. The legacy
		// path is kept verbatim (Requirement: backwards-compat
		// for older WebUI builds and for anyone scripting against
		// the API).
		isCatalogShape := strings.TrimSpace(req.Provider) != "" ||
			strings.TrimSpace(req.AuthMethod) != "" ||
			strings.TrimSpace(req.ActiveProfileKey) != ""

		if isCatalogShape {
			if err := s.applyCatalogLLMSettings(r.Context(), req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(s.llmSettings(r.Context()))
			return
		}

		// Legacy shape — unchanged from v4.4.21.
		req.LLMMaxRetries = clampInt(req.LLMMaxRetries, 0, 20)
		req.MemoryCompressorTimeout = clampInt(req.MemoryCompressorTimeout, 5, 600)
		req.MaxIterations = clampInt(req.MaxIterations, 0, 1000)
		reasoning := strings.ToLower(strings.TrimSpace(req.ReasoningEffort))
		if reasoning == "" {
			reasoning = "high"
		}
		if !oneOf(reasoning, []string{"none", "low", "medium", "high", "xhigh"}) {
			http.Error(w, "invalid reasoning effort", http.StatusBadRequest)
			return
		}

		updates := map[string]string{
			"XALGORIX_LLM":                       strings.TrimSpace(req.Model),
			"XALGORIX_API_BASE":                  strings.TrimSpace(req.APIBase),
			"XALGORIX_REASONING_EFFORT":          reasoning,
			"XALGORIX_LLM_MAX_RETRIES":           strconv.Itoa(req.LLMMaxRetries),
			"XALGORIX_MEMORY_COMPRESSOR_TIMEOUT": strconv.Itoa(req.MemoryCompressorTimeout),
			"XALGORIX_MAX_ITERATIONS":            strconv.Itoa(req.MaxIterations),
		}
		if req.OllamaCompatible != nil {
			updates["XALGORIX_OLLAMA_COMPATIBLE"] = strconv.FormatBool(*req.OllamaCompatible)
		}
		if !isMaskedSettingValue(req.APIKey) {
			updates["XALGORIX_API_KEY"] = strings.TrimSpace(req.APIKey)
		}
		if !isMaskedSettingValue(req.GeminiAPIKey) {
			updates["GEMINI_API_KEY"] = strings.TrimSpace(req.GeminiAPIKey)
		}
		if _, err := s.applyEnvironmentUpdates(updates); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(s.llmSettings(r.Context()))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyCatalogLLMSettings handles the v4.4.22 LLM settings POST
// shape: a (provider, authMethod, ...) bundle that maps onto the
// catalog + Profile_Store. Three sub-branches:
//
//  1. activeProfileKey supplied without new credentials → just
//     write XALGORIX_LLM_PROFILE so the resolver picks up the
//     existing Profile next request.
//  2. authMethod=api_key with apiKey supplied → upsert an
//     auth.Profile{Type: APIKey} for "<provider>:<profileId or
//     'default'>", also write XALGORIX_LLM/XALGORIX_API_KEY/
//     XALGORIX_API_BASE for legacy callers, and finally point
//     XALGORIX_LLM_PROFILE at the new key so the resolver
//     dispatches through the catalog branch.
//  3. authMethod=oauth or none with no profile work → just sync
//     the env-var side-channel (model + provider hint) so the
//     legacy path still has something usable; OAuth profile work
//     happens through /api/auth/profiles/oauth/{start,complete}.
func (s *Server) applyCatalogLLMSettings(ctx context.Context, req llmSettingsRequest) error {
	provider := strings.TrimSpace(req.Provider)
	authMethod := strings.ToLower(strings.TrimSpace(req.AuthMethod))
	activeProfileKey := strings.TrimSpace(req.ActiveProfileKey)
	profileID := strings.TrimSpace(req.ProfileID)
	if profileID == "" {
		profileID = "default"
	}

	// Validate provider against the compiled-in catalog whenever
	// it's supplied. The dashboard never sends a provider that
	// isn't in the dropdown, but a hand-crafted POST can — we
	// reject those with a 400 so the resolver never receives a
	// stale pointer.
	if provider != "" && s.catalog != nil {
		if _, ok, err := s.catalog.Get(ctx, provider); err != nil {
			return fmt.Errorf("catalog lookup: %w", err)
		} else if !ok {
			return fmt.Errorf("unknown provider %q", provider)
		}
	}

	updates := map[string]string{}
	if provider != "" {
		updates["XALGORIX_LLM_PROVIDER"] = provider
	}

	// API_KEY path: persist the credential AS a profile, then point
	// XALGORIX_LLM_PROFILE at it. We also continue to write the
	// legacy XALGORIX_LLM / XALGORIX_API_KEY / XALGORIX_API_BASE
	// trio so anyone still consuming those env vars (legacy
	// scripts, the legacyResolver fallback) keeps working.
	//
	// The pointer must move whenever the operator switches provider —
	// even if they leave the masked **** key in place (the UI tells them
	// to keep it to preserve the saved key). Previously this whole branch
	// was gated on a freshly-typed key, so switching provider with a
	// masked key updated only the model env var and the provider reverted
	// to the stale profile on reload.
	if authMethod == "api_key" && provider != "" {
		if s.profiles == nil {
			return fmt.Errorf("profile store not initialized")
		}
		typedKey := strings.TrimSpace(req.APIKey)
		hasTypedKey := typedKey != "" && !isMaskedSettingValue(req.APIKey)
		if hasTypedKey {
			// New key supplied: create/update the profile for this provider.
			baseOverride := strings.TrimSpace(req.APIBaseOverride)
			if baseOverride == "" {
				baseOverride = strings.TrimSpace(req.APIBase)
			}
			prof := auth.Profile{
				Provider:        provider,
				ProfileID:       profileID,
				Type:            auth.APIKey,
				APIKey:          typedKey,
				APIBaseOverride: baseOverride,
			}
			if err := s.profiles.Put(ctx, prof); err != nil {
				return fmt.Errorf("save profile: %w", err)
			}
			activeProfileKey = prof.Key()
		} else if activeProfileKey == "" {
			// Masked/empty key and no explicit profile selected. Persist the
			// provider switch without rewriting any credential:
			//   1. If a profile already exists for <provider>:<profileId>,
			//      point at it (preserving its stored key/base).
			//   2. Otherwise carry over the current saved key (the masked
			//      value the UI is showing == cfg.APIKey, or the active
			//      profile's key) into a new profile for this provider so the
			//      selection sticks.
			target := auth.Profile{Provider: provider, ProfileID: profileID}
			if existing, ok, err := s.profiles.Get(ctx, target.Key()); err != nil {
				return fmt.Errorf("look up profile %q: %w", target.Key(), err)
			} else if ok {
				activeProfileKey = existing.Key()
			} else {
				carry := strings.TrimSpace(s.cfg.APIKey)
				if carry == "" && strings.TrimSpace(s.cfg.LLMProfile) != "" {
					if prof, ok, err := s.profiles.Get(ctx, strings.TrimSpace(s.cfg.LLMProfile)); err == nil && ok {
						carry = strings.TrimSpace(prof.APIKey)
					}
				}
				if carry != "" {
					baseOverride := strings.TrimSpace(req.APIBaseOverride)
					if baseOverride == "" {
						baseOverride = strings.TrimSpace(req.APIBase)
					}
					prof := auth.Profile{
						Provider:        provider,
						ProfileID:       profileID,
						Type:            auth.APIKey,
						APIKey:          carry,
						APIBaseOverride: baseOverride,
					}
					if err := s.profiles.Put(ctx, prof); err != nil {
						return fmt.Errorf("save profile: %w", err)
					}
					activeProfileKey = prof.Key()
				}
			}
		}
	}

	// Credential-free providers must clear any previously active credential
	// profile. Otherwise a stale cloud profile keeps winning over the newly
	// selected local provider in the composite resolver.
	if authMethod == "none" {
		activeProfileKey = ""
		updates["XALGORIX_LLM_PROFILE"] = ""
		updates["XALGORIX_API_KEY"] = ""
	}

	// activeProfileKey wins as the source of truth for
	// XALGORIX_LLM_PROFILE. Either the api_key branch above set
	// it, or the operator picked an existing profile from the
	// list, or both fields are empty (auth_method=none / oauth-
	// only flow) and we leave the pointer alone.
	if activeProfileKey != "" {
		// Guard against pointing the resolver at a profile that was never
		// persisted (e.g. the operator clicked Save before completing the
		// OAuth sign-in). Without this, XALGORIX_LLM_PROFILE would name a
		// missing profile and every scan would fail the credential lookup.
		if s.profiles != nil {
			if _, ok, err := s.profiles.Get(ctx, activeProfileKey); err != nil {
				return fmt.Errorf("look up profile %q: %w", activeProfileKey, err)
			} else if !ok {
				return fmt.Errorf("no saved credential for %q — complete the OAuth sign-in (or save an API key) before selecting it", activeProfileKey)
			}
		}
		updates["XALGORIX_LLM_PROFILE"] = activeProfileKey
	}

	// Legacy env-var sync. Always written when the operator
	// supplied a model so the legacy path stays runnable.
	if model := modelForConfiguredProvider(strings.TrimSpace(req.Model), provider); model != "" {
		updates["XALGORIX_LLM"] = model
	}

	// Legacy env-var sync: XALGORIX_API_BASE.
	// The WebUI sends apiBase only for the "custom" provider; for
	// catalog providers it sends apiBaseOverride instead. Fall
	// through: req.APIBase → req.APIBaseOverride → catalog entry
	// BaseURL, so switching provider always updates the env file.
	{
		base := strings.TrimSpace(req.APIBase)
		if base == "" {
			base = strings.TrimSpace(req.APIBaseOverride)
		}
		if base == "" && provider != "" && s.catalog != nil {
			if entry, ok, err := s.catalog.Get(ctx, provider); err == nil && ok {
				base = strings.TrimSpace(entry.BaseURL)
			}
		}
		ollamaCompatible := req.OllamaCompatible != nil && *req.OllamaCompatible
		if authMethod == "none" || ollamaCompatible || hasOllamaPort(base) {
			base = containerReachableLocalBase(base)
		}
		if base != "" {
			updates["XALGORIX_API_BASE"] = base
		}
	}
	if !isMaskedSettingValue(req.APIKey) && strings.TrimSpace(req.APIKey) != "" {
		updates["XALGORIX_API_KEY"] = strings.TrimSpace(req.APIKey)
	}
	if !isMaskedSettingValue(req.GeminiAPIKey) {
		updates["GEMINI_API_KEY"] = strings.TrimSpace(req.GeminiAPIKey)
	}
	// Numeric settings still come through both shapes.
	if req.LLMMaxRetries > 0 {
		updates["XALGORIX_LLM_MAX_RETRIES"] = strconv.Itoa(clampInt(req.LLMMaxRetries, 0, 20))
	}
	if req.MemoryCompressorTimeout > 0 {
		updates["XALGORIX_MEMORY_COMPRESSOR_TIMEOUT"] = strconv.Itoa(clampInt(req.MemoryCompressorTimeout, 5, 600))
	}
	if req.MaxIterations > 0 {
		updates["XALGORIX_MAX_ITERATIONS"] = strconv.Itoa(clampInt(req.MaxIterations, 0, 1000))
	}
	if reasoning := strings.ToLower(strings.TrimSpace(req.ReasoningEffort)); reasoning != "" {
		if !oneOf(reasoning, []string{"none", "low", "medium", "high", "xhigh"}) {
			return fmt.Errorf("invalid reasoning effort %q", req.ReasoningEffort)
		}
		updates["XALGORIX_REASONING_EFFORT"] = reasoning
	}
	if req.OllamaCompatible != nil {
		updates["XALGORIX_OLLAMA_COMPATIBLE"] = strconv.FormatBool(*req.OllamaCompatible)
	}

	if len(updates) == 0 {
		return nil
	}
	if _, err := s.applyEnvironmentUpdates(updates); err != nil {
		return err
	}
	return nil
}

func containerReachableLocalBase(raw string) string {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
		return raw
	}
	port := strings.TrimSpace(u.Port())
	u.Host = "host.docker.internal"
	if port != "" {
		u.Host += ":" + port
	}
	return u.String()
}

func hasOllamaPort(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Port() == "11434"
}

func (s *Server) handleEnvironmentSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.environmentSettings(false))
	case http.MethodPost:
		var req struct {
			Values map[string]string `json:"values"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		restartRequired, err := s.applyEnvironmentUpdates(req.Values)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(s.environmentSettings(restartRequired))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) llmSettings(ctx context.Context) llmSettingsResponse {
	resp := llmSettingsResponse{
		Model:                   s.cfg.LLM,
		APIBase:                 s.cfg.APIBase,
		APIKey:                  maskSecretValue(s.cfg.APIKey),
		HasAPIKey:               s.cfg.APIKey != "",
		ReasoningEffort:         s.cfg.ReasoningEffort,
		OllamaCompatible:        s.cfg.OllamaCompatible,
		LLMMaxRetries:           s.cfg.LLMMaxRetries,
		MemoryCompressorTimeout: s.cfg.MemCompTimeout,
		MaxIterations:           s.cfg.MaxIterations,
		GeminiAPIKey:            maskSecretValue(s.cfg.GeminiAPIKey),
		HasGeminiAPIKey:         s.cfg.GeminiAPIKey != "",
		EnvFile:                 xalgorixEnvFilePath(),
		ActiveProfileKey:        s.cfg.LLMProfile,
		Profiles:                []llmProfileSummary{},
	}

	// Provider derivation: prefer the explicit provider, then the active
	// profile, and finally a legacy "<provider>/<model>" model value.
	provider := strings.TrimSpace(s.cfg.LLMProvider)
	if key := strings.TrimSpace(s.cfg.LLMProfile); key != "" {
		if i := strings.Index(key, ":"); i > 0 {
			provider = key[:i]
		}
	}
	if provider == "" {
		if i := strings.Index(s.cfg.LLM, "/"); i > 0 {
			provider = strings.ToLower(s.cfg.LLM[:i])
		}
	}
	resp.Provider = provider
	resp.Model = modelForConfiguredProvider(s.cfg.LLM, provider)

	// AuthMethod derivation: dispatch precedence mirrors the
	// resolver. cfg.LLMProfile present + Profile.Type drives the
	// answer; otherwise cfg.APIKey indicates api_key; otherwise
	// "" (operator hasn't picked anything yet).
	authMethod := ""
	if s.profiles != nil && strings.TrimSpace(s.cfg.LLMProfile) != "" {
		if prof, ok, err := s.profiles.Get(ctx, strings.TrimSpace(s.cfg.LLMProfile)); err == nil && ok {
			switch prof.Type {
			case auth.OAuth:
				authMethod = "oauth"
			case auth.APIKey:
				authMethod = "api_key"
			}
		}
	}
	if authMethod == "" && s.cfg.APIKey != "" {
		authMethod = "api_key"
	}
	if authMethod == "" && provider != "" && s.catalog != nil {
		if entry, ok, err := s.catalog.Get(ctx, provider); err == nil && ok {
			for _, method := range entry.AuthMethods {
				if method == "none" {
					authMethod = "none"
					break
				}
			}
		}
	}
	resp.AuthMethod = authMethod

	// Profiles: filter to the active provider only. The full list
	// surface lives at /api/auth/profiles; this field is a
	// dashboard convenience so the LLM tab can render the saved
	// credentials picker without a second roundtrip.
	if s.profiles != nil && provider != "" {
		all, err := s.profiles.List(ctx)
		if err == nil {
			for _, p := range all {
				if p.Provider != provider {
					continue
				}
				resp.Profiles = append(resp.Profiles, llmProfileSummaryFor(p))
			}
		}
	}

	return resp
}

// llmProfileSummaryFor produces the masked, dashboard-friendly view
// of one auth.Profile. Credentials are NEVER returned in plaintext;
// only the boolean has* flags + masked metadata.
func llmProfileSummaryFor(p auth.Profile) llmProfileSummary {
	out := llmProfileSummary{
		Key:             p.Key(),
		Provider:        p.Provider,
		ProfileID:       p.ProfileID,
		Type:            string(p.Type),
		HasAccessToken:  p.AccessToken != "",
		HasAPIKey:       p.APIKey != "",
		APIBaseOverride: p.APIBaseOverride,
		RequiresReauth:  p.RequiresReauth,
	}
	if !p.ExpiresAt.IsZero() {
		out.ExpiresAt = p.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (s *Server) environmentSettings(restartRequired bool) environmentSettingsResponse {
	defs := allEnvSettingDefinitions()
	values := make([]envSettingValue, 0, len(defs))
	for _, def := range defs {
		value := s.envSettingValue(def.Key)
		hasValue := os.Getenv(def.Key) != ""
		if def.Sensitive {
			value = maskSecretValue(value)
		}
		values = append(values, envSettingValue{
			envSettingDefinition: def,
			Value:                value,
			HasValue:             hasValue,
		})
	}
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Category != values[j].Category {
			return values[i].Category < values[j].Category
		}
		return values[i].Key < values[j].Key
	})
	return environmentSettingsResponse{
		EnvFile:         xalgorixEnvFilePath(),
		Variables:       values,
		RestartRequired: restartRequired,
	}
}

func (s *Server) applyEnvironmentUpdates(values map[string]string) (bool, error) {
	if len(values) == 0 {
		return false, nil
	}
	defs := envDefinitionByKey()
	effective := make(map[string]string, len(values))
	restartRequired := false

	for key, value := range values {
		key = strings.TrimSpace(key)
		if !envSettingKeyRe.MatchString(key) {
			return false, fmt.Errorf("invalid environment variable name %q", key)
		}
		def, ok := defs[key]
		if !ok {
			return false, fmt.Errorf("unsupported environment variable %q", key)
		}
		if def.Sensitive && isMaskedSettingValue(value) {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.ContainsAny(value, "\r\n") {
			return false, fmt.Errorf("%s cannot contain newlines", key)
		}
		normalized, err := normalizeEnvSettingValue(def, value)
		if err != nil {
			return false, err
		}
		value = normalized
		effective[key] = value
		if def.RequiresRestart {
			restartRequired = true
		}
	}
	if len(effective) == 0 {
		return restartRequired, nil
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	if err := updateXalgorixEnvFile(xalgorixEnvFilePath(), effective); err != nil {
		return false, err
	}
	for key, value := range effective {
		if value == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, value)
		}
	}
	s.applyEnvironmentToRuntimeConfig(effective)
	return restartRequired, nil
}

func (s *Server) applyEnvironmentToRuntimeConfig(values map[string]string) {
	rateChanged := false
	for key, value := range values {
		switch key {
		case "XALGORIX_LLM":
			s.cfg.LLM = value
		case "XALGORIX_LLM_PROVIDER":
			s.cfg.LLMProvider = value
		case "XALGORIX_API_BASE":
			s.cfg.APIBase = value
		case "XALGORIX_API_KEY":
			s.cfg.APIKey = value
		case "XALGORIX_LLM_PROFILE":
			s.cfg.LLMProfile = value
		case "XALGORIX_REASONING_EFFORT":
			s.cfg.ReasoningEffort = valueOrDefault(value, "high")
		case "XALGORIX_LANGUAGE":
			s.cfg.Language = config.NormalizeLanguage(value)
		case "XALGORIX_OLLAMA_COMPATIBLE":
			s.cfg.OllamaCompatible = parseBoolSetting(value, false)
		case "XALGORIX_LLM_MAX_RETRIES":
			s.cfg.LLMMaxRetries = parseIntSetting(value, 5)
		case "XALGORIX_MAX_RATE_LIMIT_WAIT":
			s.cfg.MaxRateLimitWaitSec = parseIntSetting(value, 30*60)
		case "XALGORIX_MAX_OUTPUT_TOKENS":
			s.cfg.MaxOutputTokens = parseIntSetting(value, 8192)
		case "XALGORIX_CONTEXT_COMPACT_TOKENS":
			s.cfg.ContextCompactTokens = parseIntSetting(value, -1)
		case "XALGORIX_LLM_CONTEXT_WINDOW":
			s.cfg.LLMContextWindow = parseIntSetting(value, 128000)
		case "XALGORIX_CONTEXT_COMPACT_RATIO":
			s.cfg.ContextCompactRatio = parseFloatSetting(value, 0.75)
		case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
			s.cfg.MemCompTimeout = parseIntSetting(value, 30)
		case "XALGORIX_MAX_ITERATIONS":
			s.cfg.MaxIterations = parseIntSetting(value, 0)
		case "XALGORIX_MIN_ITERATIONS":
			s.cfg.MinIterations = parseIntSetting(value, 50)
		case "XALGORIX_MAX_WILDCARD_SUBDOMAINS":
			s.cfg.MaxWildcardSubdomains = parseIntSetting(value, -1)
		case "XALGORIX_NO_TOOL_ABORT_AT":
			s.cfg.NoToolAbortAt = parseIntSetting(value, 30)
		case "XALGORIX_MAX_FINISH_REJECTIONS":
			s.cfg.MaxFinishRejections = parseIntSetting(value, 15)
		case "XALGORIX_WORKSPACE":
			if value != "" {
				s.cfg.Workspace = value
			}
		case "XALGORIX_DISABLE_BROWSER":
			s.cfg.DisableBrowser = parseBoolSetting(value, false)
		case "XALGORIX_RATE_LIMIT_REQUESTS":
			s.cfg.RateLimitRequests = parseIntSetting(value, 60)
			rateChanged = true
		case "XALGORIX_RATE_LIMIT_WINDOW":
			s.cfg.RateLimitWindow = parseIntSetting(value, 60)
			rateChanged = true
		case "XALGORIX_RATE_RPS":
			s.cfg.RateLimitRPS = parseFloatSetting(value, 10)
		case "XALGORIX_RATE_BURST":
			s.cfg.RateLimitBurst = parseIntSetting(value, 20)
		case "XALGORIX_TLS_SKIP_VERIFY":
			s.cfg.TLSSkipVerify = parseBoolSetting(value, false)
		case "XALGORIX_ALLOW_LOCAL_TARGETS":
			s.cfg.AllowLocalTargets = parseBoolSetting(value, false)
		case "CAIDO_PORT":
			s.cfg.CaidoPort = parseIntSetting(value, 0)
		case "CAIDO_API_TOKEN":
			s.cfg.CaidoAPIToken = value
		case "XALGORIX_TELEMETRY":
			s.cfg.Telemetry = parseBoolSetting(value, true)
		case "XALGORIX_OTEL_ENDPOINT":
			s.cfg.OTelEndpoint = value
		case "GEMINI_API_KEY":
			s.cfg.GeminiAPIKey = value
		case "AGENTMAIL_API_KEY":
			s.cfg.AgentMailAPIKey = value
		case "AGENTMAIL_POD":
			s.cfg.AgentMailPod = value
		case "XALGORIX_DISCORD_WEBHOOK":
			s.cfg.DiscordWebhook = value
			s.discordWebhook = value
		case "XALGORIX_DISCORD_MIN_SEVERITY":
			s.cfg.DiscordMinSeverity = value
			s.discordMinSeverity = strings.ToLower(strings.TrimSpace(value))
		case "XALGORIX_TELEGRAM_BOT_TOKEN":
			s.cfg.TelegramBotToken = value
			s.telegramBotToken = value
		case "XALGORIX_TELEGRAM_CHAT_ID":
			s.cfg.TelegramChatID = value
			s.telegramChatID = value
		case "XALGORIX_TELEGRAM_MIN_SEVERITY":
			s.cfg.TelegramMinSeverity = value
			s.telegramMinSeverity = strings.ToLower(strings.TrimSpace(value))
		case "XALGORIX_NOTIFY_SCAN_COMPLETE":
			enabled := parseBoolSetting(value, false)
			s.cfg.NotifyScanComplete = enabled
			s.notifyScanComplete.Store(enabled)
		case "XALGORIX_USERNAME":
			s.cfg.Username = value
		case "XALGORIX_PASSWORD":
			s.cfg.Password = value
		case "XALGORIX_PASSWORD_HASH":
			s.cfg.PasswordHash = value
		case "XALGORIX_BIND":
			s.cfg.BindAddr = valueOrDefault(value, "127.0.0.1")
		case "XALGORIX_ALLOW_AUTO_INSTALL":
			s.cfg.AllowAutoInstall = parseBoolSetting(value, os.Getuid() == 0)
		case "XALGORIX_AUTO_INSTALL_SUDO":
			s.cfg.AllowAutoInstallSudo = parseBoolSetting(value, false)
		case "XALGORIX_USE_PROXY":
			s.cfg.UseProxy = parseBoolSetting(value, false)
		case "XALGORIX_PROXY_REQUIRED":
			s.cfg.ProxyRequired = parseBoolSetting(value, false)
		case "XALGORIX_PROXY_FILE":
			s.cfg.ProxyFile = value
		case "XALGORIX_PROXY_ROTATION":
			s.cfg.ProxyRotation = valueOrDefault(value, "roundrobin")
		case "XALGORIX_PROXY_URL":
			s.cfg.ProxyURL = value
		case "XALGORIX_BROWSER_PATH":
			s.cfg.BrowserPath = value
		}
	}
	if rateChanged {
		requests := clampInt(s.cfg.RateLimitRequests, 1, 1000)
		window := clampInt(s.cfg.RateLimitWindow, 10, 3600)
		s.cfg.RateLimitRequests = requests
		s.cfg.RateLimitWindow = window
		if s.rateLimiter != nil {
			s.rateLimiter.Stop()
		}
		s.rateLimiter = NewRateLimiter(requests, time.Duration(window)*time.Second)
		log.Printf("Rate limiting updated: %d requests/%ds per IP", requests, window)
	}
}

func (s *Server) envSettingValue(key string) string {
	switch key {
	case "XALGORIX_LLM":
		return s.cfg.LLM
	case "XALGORIX_API_BASE":
		return s.cfg.APIBase
	case "XALGORIX_API_KEY":
		return s.cfg.APIKey
	case "XALGORIX_LLM_PROFILE":
		return s.cfg.LLMProfile
	case "XALGORIX_REASONING_EFFORT":
		return valueOrDefault(s.cfg.ReasoningEffort, "high")
	case "XALGORIX_LANGUAGE":
		return config.NormalizeLanguage(s.cfg.Language)
	case "XALGORIX_OLLAMA_COMPATIBLE":
		return strconv.FormatBool(s.cfg.OllamaCompatible)
	case "XALGORIX_LLM_MAX_RETRIES":
		return strconv.Itoa(s.cfg.LLMMaxRetries)
	case "XALGORIX_MAX_RATE_LIMIT_WAIT":
		return strconv.Itoa(s.cfg.MaxRateLimitWaitSec)
	case "XALGORIX_MAX_OUTPUT_TOKENS":
		return strconv.Itoa(s.cfg.MaxOutputTokens)
	case "XALGORIX_CONTEXT_COMPACT_TOKENS":
		return strconv.Itoa(s.cfg.ContextCompactTokens)
	case "XALGORIX_LLM_CONTEXT_WINDOW":
		return strconv.Itoa(s.cfg.LLMContextWindow)
	case "XALGORIX_CONTEXT_COMPACT_RATIO":
		return strconv.FormatFloat(s.cfg.ContextCompactRatio, 'g', -1, 64)
	case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
		return strconv.Itoa(s.cfg.MemCompTimeout)
	case "XALGORIX_MAX_ITERATIONS":
		return strconv.Itoa(s.cfg.MaxIterations)
	case "XALGORIX_MIN_ITERATIONS":
		return strconv.Itoa(s.cfg.MinIterations)
	case "XALGORIX_MAX_WILDCARD_SUBDOMAINS":
		return strconv.Itoa(s.cfg.MaxWildcardSubdomains)
	case "XALGORIX_NO_TOOL_ABORT_AT":
		return strconv.Itoa(s.cfg.NoToolAbortAt)
	case "XALGORIX_MAX_FINISH_REJECTIONS":
		return strconv.Itoa(s.cfg.MaxFinishRejections)
	case "XALGORIX_WORKSPACE":
		return s.cfg.Workspace
	case "XALGORIX_DISABLE_BROWSER":
		return strconv.FormatBool(s.cfg.DisableBrowser)
	case "XALGORIX_RATE_LIMIT_REQUESTS":
		return strconv.Itoa(s.cfg.RateLimitRequests)
	case "XALGORIX_RATE_LIMIT_WINDOW":
		return strconv.Itoa(s.cfg.RateLimitWindow)
	case "XALGORIX_RATE_RPS":
		return strconv.FormatFloat(s.cfg.RateLimitRPS, 'f', -1, 64)
	case "XALGORIX_RATE_BURST":
		return strconv.Itoa(s.cfg.RateLimitBurst)
	case "XALGORIX_TLS_SKIP_VERIFY":
		return strconv.FormatBool(s.cfg.TLSSkipVerify)
	case "XALGORIX_ALLOW_LOCAL_TARGETS":
		return strconv.FormatBool(s.cfg.AllowLocalTargets)
	case "CAIDO_PORT":
		return strconv.Itoa(s.cfg.CaidoPort)
	case "CAIDO_API_TOKEN":
		return s.cfg.CaidoAPIToken
	case "XALGORIX_TELEMETRY":
		return strconv.FormatBool(s.cfg.Telemetry)
	case "XALGORIX_OTEL_ENDPOINT":
		return s.cfg.OTelEndpoint
	case "GEMINI_API_KEY":
		return s.cfg.GeminiAPIKey
	case "AGENTMAIL_API_KEY":
		return s.cfg.AgentMailAPIKey
	case "AGENTMAIL_POD":
		return s.cfg.AgentMailPod
	case "XALGORIX_DISCORD_WEBHOOK":
		return s.cfg.DiscordWebhook
	case "XALGORIX_DISCORD_MIN_SEVERITY":
		return s.cfg.DiscordMinSeverity
	case "XALGORIX_TELEGRAM_BOT_TOKEN":
		return s.cfg.TelegramBotToken
	case "XALGORIX_TELEGRAM_CHAT_ID":
		return s.cfg.TelegramChatID
	case "XALGORIX_TELEGRAM_MIN_SEVERITY":
		return s.cfg.TelegramMinSeverity
	case "XALGORIX_NOTIFY_SCAN_COMPLETE":
		return strconv.FormatBool(s.notifyScanComplete.Load())
	case "XALGORIX_USERNAME":
		return s.cfg.Username
	case "XALGORIX_PASSWORD":
		return s.cfg.Password
	case "XALGORIX_PASSWORD_HASH":
		return s.cfg.PasswordHash
	case "XALGORIX_BIND":
		return valueOrDefault(s.cfg.BindAddr, "127.0.0.1")
	case "XALGORIX_ALLOW_AUTO_INSTALL":
		return strconv.FormatBool(s.cfg.AllowAutoInstall)
	case "XALGORIX_AUTO_INSTALL_SUDO":
		return strconv.FormatBool(s.cfg.AllowAutoInstallSudo)
	case "XALGORIX_USE_PROXY":
		return strconv.FormatBool(s.cfg.UseProxy)
	case "XALGORIX_PROXY_REQUIRED":
		return strconv.FormatBool(s.cfg.ProxyRequired)
	case "XALGORIX_PROXY_FILE":
		return s.cfg.ProxyFile
	case "XALGORIX_PROXY_ROTATION":
		return valueOrDefault(s.cfg.ProxyRotation, "roundrobin")
	case "XALGORIX_PROXY_URL":
		return s.cfg.ProxyURL
	case "XALGORIX_BROWSER_PATH":
		return s.cfg.BrowserPath
	default:
		return os.Getenv(key)
	}
}

func updateXalgorixEnvFile(path string, updates map[string]string) error {
	return config.UpdateEnvFile(path, updates)
}

func xalgorixEnvFilePath() string {
	return config.EnvFilePath()
}

func maskSecretValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 8 {
		return "****" + value[len(value)-8:]
	}
	return "****"
}

func isMaskedSettingValue(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "****") || strings.Contains(value, "••••")
}

func parseIntSetting(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseFloatSetting(value string, fallback float64) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return n
}

func parseBoolSetting(value string, fallback bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func normalizeEnvSettingValue(def envSettingDefinition, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch def.InputType {
	case "boolean":
		return strconv.FormatBool(parseBoolSetting(value, false)), nil
	case "select":
		if len(def.Options) > 0 && !oneOf(value, def.Options) {
			return "", fmt.Errorf("invalid value %q for %s", value, def.Key)
		}
	case "multiselect":
		return normalizeMultiSelect(def, value)
	case "number":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return "", fmt.Errorf("%s must be a number", def.Key)
		}
	}
	switch def.Key {
	case "XALGORIX_RATE_LIMIT_REQUESTS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 60), 1, 1000)), nil
	case "XALGORIX_RATE_LIMIT_WINDOW":
		return strconv.Itoa(clampInt(parseIntSetting(value, 60), 10, 3600)), nil
	case "XALGORIX_LLM_MAX_RETRIES":
		return strconv.Itoa(clampInt(parseIntSetting(value, 5), 0, 20)), nil
	case "XALGORIX_MAX_RATE_LIMIT_WAIT":
		return strconv.Itoa(clampInt(parseIntSetting(value, 30*60), -1, 7*24*60*60)), nil
	case "XALGORIX_MAX_OUTPUT_TOKENS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 8192), 1024, 200000)), nil
	case "XALGORIX_CONTEXT_COMPACT_TOKENS":
		// Negative = auto (window-relative, normalized to -1); 0 disables;
		// positive = explicit absolute budget clamped to a sane range (avoid a
		// tiny value that would compact every turn, or an absurd one).
		ct := parseIntSetting(value, -1)
		if ct < 0 {
			ct = -1
		} else if ct != 0 {
			ct = clampInt(ct, 20000, 2000000)
		}
		return strconv.Itoa(ct), nil
	case "XALGORIX_LLM_CONTEXT_WINDOW":
		return strconv.Itoa(clampInt(parseIntSetting(value, 128000), 8000, 2000000)), nil
	case "XALGORIX_CONTEXT_COMPACT_RATIO":
		r := parseFloatSetting(value, 0.75)
		if r < 0.5 {
			r = 0.5
		} else if r > 0.9 {
			r = 0.9
		}
		return strconv.FormatFloat(r, 'g', -1, 64), nil
	case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
		return strconv.Itoa(clampInt(parseIntSetting(value, 30), 5, 600)), nil
	case "XALGORIX_MAX_ITERATIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 0), 0, 1000)), nil
	case "XALGORIX_MIN_ITERATIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 50), 1, 500)), nil
	case "XALGORIX_NO_TOOL_ABORT_AT":
		return strconv.Itoa(clampInt(parseIntSetting(value, 30), 0, 500)), nil
	case "XALGORIX_MAX_WILDCARD_SUBDOMAINS":
		return strconv.Itoa(clampInt(parseIntSetting(value, -1), -1, 1000)), nil
	case "XALGORIX_MAX_FINISH_REJECTIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 15), 1, 100)), nil
	}
	return value, nil
}

// normalizeMultiSelect validates and canonicalizes a comma-separated
// multiselect value against def.Options: lowercased, de-duplicated, and
// re-ordered to match def.Options. Selecting every option is the default, so
// it collapses to "" (the env var stays unset). An empty selection likewise
// yields "" — meaning "all/default" — so a value can never silently disable a
// feature; use the dedicated disable flag for that.
func normalizeMultiSelect(def envSettingDefinition, value string) (string, error) {
	seen := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		if len(def.Options) > 0 && !oneOf(p, def.Options) {
			return "", fmt.Errorf("invalid value %q for %s", p, def.Key)
		}
		seen[p] = true
	}
	ordered := make([]string, 0, len(seen))
	for _, opt := range def.Options {
		if seen[opt] {
			ordered = append(ordered, opt)
		}
	}
	if len(ordered) == len(def.Options) {
		return "", nil
	}
	return strings.Join(ordered, ","), nil
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func oneOf(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
