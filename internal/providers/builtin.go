// Package providers — Builtin() returns the compiled-in list of
// known LLM providers shipped with v4.4.22. This list is the single
// authoritative source of provider metadata. There is no
// operator-editable catalog file, no openclaw importer, and no
// startup catalog write.
//
// The entries are sorted alphabetically by ID and end with the
// "custom" sentinel so the LLM tab dropdown ordering matches the
// data ordering one-to-one ("custom" is alphabetically last by
// design — it represents user-supplied endpoints rather than a
// concrete provider).
//
// Per-entry notes:
//
//   - BaseURL is filled when the provider's documented OpenAI-/
//     Anthropic-/Gemini-compatible endpoint is publicly stable.
//     Operators with providers whose base URL is unknown to us
//     should pick "Custom Provider" and fill the field manually.
//
//   - OAuth-capable entries have Flow set; for the four flows we
//     wired fully (anthropic, google, copilot, xai) the endpoint
//     fields are populated from public docs. Other OAuth-capable
//     entries (codex, opencode, openai, opencode, qwen,
//     huggingface) keep the OAuth fields empty and document the
//     beta status via Notes — the existing PKCE / device-code
//     drivers surface "endpoint not configured" errors to the
//     operator.
//
//   - For entries where the operator must supply a per-deploy
//     OAuth client ID (Google's per-app constraint is the
//     canonical case), Notes calls out the override env var and
//     ClientIDForEntry reads
//     XALGORIX_<UPPER_ID>_OAUTH_CLIENT_ID at runtime.
package providers

import (
	"os"
	"sort"
	"strings"
	"sync"
)

// builtinList is the alphabetically-sorted compiled-in catalog.
// "custom" is appended last because it represents free-form
// user-supplied endpoints rather than a discrete provider; the
// LLM tab dropdown surfaces it at the bottom of the list.
//
// Frozen + cloned through Builtin so callers cannot mutate the
// shared slice — return a fresh copy on every call.
var builtinList = []Entry{
	{
		ID:          "anthropic",
		DisplayName: "Anthropic (Claude)",
		BaseURL:     "https://api.anthropic.com",
		HeaderStyle: "anthropic",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "claude_cli_reuse",
		Notes:       "OAuth path imports an existing Claude CLI credential file (~/.claude/.credentials.json).",
	},
	{
		ID:          "arcee",
		DisplayName: "Arcee AI",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "byteplus",
		DisplayName: "BytePlus",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "cerebras",
		DisplayName: "Cerebras",
		BaseURL:     "https://api.cerebras.ai/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "chutes",
		DisplayName: "Chutes",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "cloudflare",
		DisplayName: "Cloudflare AI Gateway",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your account-specific gateway URL via Custom Provider (https://gateway.ai.cloudflare.com/v1/<account>/<gateway>/openai).",
	},
	{
		ID:          "codex",
		DisplayName: "Codex (ChatGPT Subscription)",
		BaseURL:     "https://chatgpt.com/backend-api/codex",
		HeaderStyle: "openai_responses",
		AuthMethods: []string{"oauth", "api_key"},
		Flow:        "codex_cli_reuse",
		// Reuses the official Codex CLI sign-in: run `codex login` once on
		// this host, then import here. Endpoints below are used for silent
		// token refresh. ClientID is the public Codex CLI OAuth client.
		ClientID:              "app_EMoamEEZ73f0CkXaXp7hrann",
		AuthorizationEndpoint: "https://auth.openai.com/oauth/authorize",
		TokenEndpoint:         "https://auth.openai.com/oauth/token",
		Scopes:                []string{"openid", "profile", "email", "offline_access"},
		Notes:                 "ChatGPT Plus/Pro subscription. Run `codex login` (official OpenAI Codex CLI) on this host, then click Import below. Talks the Responses API at chatgpt.com/backend-api/codex. Personal-use only per OpenAI's terms.",
	},
	{
		ID:          "copilot",
		DisplayName: "GitHub Copilot",
		BaseURL:     "https://api.githubcopilot.com",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "device_code",
		ClientID:    "Iv1.b507a08c87ecfe98",
		// Well-known GitHub Copilot CLI client. Public values from
		// the github.com/cli/cli auth flow.
		AuthorizationEndpoint:       "https://github.com/login/oauth/authorize",
		TokenEndpoint:               "https://github.com/login/oauth/access_token",
		DeviceAuthorizationEndpoint: "https://github.com/login/device/code",
		Scopes:                      []string{"read:user"},
		// Native Copilot path (internal/llm/copilot_token.go): the stored
		// GitHub credential — a device-code OAuth token (recommended) or a
		// fine-grained PAT entered as the API key — is exchanged at
		// api.github.com/copilot_internal/v2/token for a short-lived Copilot
		// bearer, then used against this OpenAI-compatible base. Requires an
		// active Copilot subscription on the account.
		Notes: "GitHub Copilot via device-code OAuth (recommended) or a fine-grained PAT (github_pat_, needs copilot access) entered as the API key. Classic ghp_ PATs are not supported by Copilot. The GitHub token is exchanged for a short-lived Copilot token automatically.",
	},
	{
		ID:          "deepinfra",
		DisplayName: "DeepInfra",
		BaseURL:     "https://api.deepinfra.com/v1/openai",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "deepseek",
		DisplayName: "DeepSeek",
		BaseURL:     "https://api.deepseek.com/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "fireworks",
		DisplayName: "Fireworks",
		BaseURL:     "https://api.fireworks.ai/inference/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "google",
		DisplayName: "Google (Gemini)",
		BaseURL:     "https://generativelanguage.googleapis.com",
		HeaderStyle: "gemini",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "pkce",
		// ClientID is intentionally empty — Google forces per-app
		// client IDs. Operators set XALGORIX_GOOGLE_OAUTH_CLIENT_ID
		// (read at lookup time by ClientIDForEntry).
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenEndpoint:         "https://oauth2.googleapis.com/token",
		Scopes:                []string{"https://www.googleapis.com/auth/cloud-platform"},
		Notes:                 "Set XALGORIX_GOOGLE_OAUTH_CLIENT_ID to your Google Cloud OAuth client.",
	},
	{
		ID:          "googlevertex",
		DisplayName: "Google Vertex",
		BaseURL:     "https://us-central1-aiplatform.googleapis.com",
		HeaderStyle: "gemini",
		AuthMethods: []string{"api_key"},
		Notes:       "Vertex auth normally uses gcloud-managed credentials picked up via env (GOOGLE_APPLICATION_CREDENTIALS).",
	},
	{
		ID:          "groq",
		DisplayName: "Groq",
		BaseURL:     "https://api.groq.com/openai/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "huggingface",
		DisplayName: "Hugging Face",
		BaseURL:     "https://router.huggingface.co/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "pkce",
		Notes:       "OAuth flow is beta — Hugging Face's OAuth client metadata is not publicly stable yet; API key path is fully tested.",
	},
	{
		ID:          "kilo",
		DisplayName: "Kilo Gateway",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "litellm",
		DisplayName: "LiteLLM",
		BaseURL:     "http://localhost:4000/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Default base URL points at the standard LiteLLM proxy (http://localhost:4000). Override via API Base if your proxy runs on a different host or port.",
	},
	{
		ID:          "lmstudio",
		DisplayName: "LM Studio",
		BaseURL:     "http://localhost:1234/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"none"},
		Notes:       "Local runtime — no credential required.",
	},
	{
		ID:          "microsoftfoundry",
		DisplayName: "Microsoft Foundry",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your tenant-specific endpoint via Custom Provider.",
	},
	{
		ID:          "minimax",
		DisplayName: "MiniMax",
		BaseURL:     "https://api.minimax.io/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "mistral",
		DisplayName: "Mistral AI",
		BaseURL:     "https://api.mistral.ai/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "moonshot",
		DisplayName: "Moonshot AI (Kimi)",
		BaseURL:     "https://api.moonshot.cn/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "nvidia",
		DisplayName: "NVIDIA",
		BaseURL:     "https://integrate.api.nvidia.com/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "novita",
		DisplayName: "Novita AI",
		BaseURL:     "https://api.novita.ai/openai/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "OpenAI-compatible LLM API. Choose Custom model for any model returned by Novita's models endpoint.",
	},
	{
		ID:          "ollama",
		DisplayName: "Ollama",
		BaseURL:     "http://localhost:11434/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"none"},
		Notes:       "Local runtime — no credential required.",
	},
	{
		ID:          "openai",
		DisplayName: "OpenAI (API Key)",
		BaseURL:     "https://api.openai.com/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "OpenAI Platform API via API key (chat-completions). For ChatGPT Plus/Pro subscription access to Codex models, use the 'Codex (ChatGPT Subscription)' provider instead.",
	},
	{
		ID:          "opencode",
		DisplayName: "OpenCode",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "pkce",
		Notes:       "OAuth flow is beta — endpoints are not publicly documented yet; API key path is fully tested.",
	},
	{
		ID:          "openrouter",
		DisplayName: "OpenRouter",
		BaseURL:     "https://openrouter.ai/api/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "qianfan",
		DisplayName: "Qianfan",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your Baidu Qianfan endpoint via Custom Provider.",
	},
	{
		ID:          "qwen",
		DisplayName: "Qwen Cloud",
		BaseURL:     "https://dashscope.aliyuncs.com/compatible-mode/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key", "oauth"},
		Flow:        "pkce",
		Notes:       "OAuth flow is beta — DashScope OAuth client metadata is not publicly stable yet; API key path is fully tested.",
	},
	{
		ID:          "runcrate",
		DisplayName: "Runcrate",
		BaseURL:     "https://api.runcrate.ai/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "OpenAI-compatible API for open-weight models. Model IDs are vendor-prefixed (for example deepseek-ai/DeepSeek-V4-Flash); choose Custom model for any ID returned by GET /v1/models.",
	},
	{
		ID:          "sglang",
		DisplayName: "SGLang",
		BaseURL:     "http://localhost:30000/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"none"},
		Notes:       "Local runtime — no credential required.",
	},
	{
		ID:          "stepfun",
		DisplayName: "StepFun",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your StepFun endpoint via Custom Provider.",
	},
	{
		ID:          "synthetic",
		DisplayName: "Synthetic",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "tencent",
		DisplayName: "Tencent Cloud",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your Tencent Hunyuan endpoint via Custom Provider.",
	},
	{
		ID:          "together",
		DisplayName: "Together AI",
		BaseURL:     "https://api.together.xyz/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
	},
	{
		ID:          "venice",
		DisplayName: "Venice AI",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Set base URL via the Custom Provider option if the default is unknown.",
	},
	{
		ID:          "vercel",
		DisplayName: "Vercel AI Gateway",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your Vercel AI Gateway endpoint via Custom Provider.",
	},
	{
		ID:          "vllm",
		DisplayName: "vLLM",
		BaseURL:     "http://localhost:8000/v1",
		HeaderStyle: "openai",
		AuthMethods: []string{"none"},
		Notes:       "Local runtime — no credential required.",
	},
	{
		ID:          "volcano",
		DisplayName: "Volcano Engine",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your Volcano Engine endpoint via Custom Provider.",
	},
	{
		ID:                    "xai",
		DisplayName:           "xAI (Grok)",
		BaseURL:               "https://api.x.ai/v1",
		HeaderStyle:           "openai",
		AuthMethods:           []string{"api_key", "oauth"},
		Flow:                  "pkce",
		AuthorizationEndpoint: "https://x.ai/oauth/authorize",
		TokenEndpoint:         "https://x.ai/oauth/token",
		Notes:                 "OAuth scopes vary by client — confirm via xAI developer console.",
	},
	{
		ID:          "xiaomi",
		DisplayName: "Xiaomi",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Configure your Xiaomi endpoint via Custom Provider.",
	},
	{
		ID:          "zai",
		DisplayName: "Z.AI (standard API)",
		BaseURL:     "https://api.z.ai/api/paas/v4",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Standard usage-based Z.AI API. For a GLM Coding Plan subscription, select Z.AI Coding Plan instead. Recommended model: glm-5.3.",
	},
	{
		ID:          "zai-coding-plan",
		DisplayName: "Z.AI Coding Plan",
		BaseURL:     "https://api.z.ai/api/coding/paas/v4",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "GLM Coding Plan subscription endpoint. Use the API key from the subscribed Z.AI account. Current models include glm-5.3 and glm-5.3-flash; usage remains subject to Z.AI's supported-tool policy.",
	},
	// Custom is the explicit "operator-supplied endpoint" entry.
	// Always last in the LLM tab dropdown.
	{
		ID:          "custom",
		DisplayName: "Custom Provider",
		BaseURL:     "",
		HeaderStyle: "openai",
		AuthMethods: []string{"api_key"},
		Notes:       "Free-form base URL + API key + model. Use this for self-hosted or unlisted providers.",
	},
}

// initOnce de-duplicates Kilo (placeholder) and sorts the slice
// once at first access. The init step is idempotent and protected
// by a sync.Once so concurrent first reads are safe.
var (
	initOnce  sync.Once
	finalList []Entry
)

// finalize collapses any accidental duplicate IDs to the first
// occurrence and sorts the slice with "custom" forced to the
// trailing position. A duplicate would be a build-time bug; we
// drop later occurrences silently rather than panic so a stray
// merge conflict cannot crash startup.
func finalize() {
	seen := make(map[string]struct{}, len(builtinList))
	deduped := make([]Entry, 0, len(builtinList))
	for _, e := range builtinList {
		if _, dup := seen[e.ID]; dup {
			continue
		}
		seen[e.ID] = struct{}{}
		deduped = append(deduped, e)
	}
	// Stable alphabetical sort, then move "custom" to the end.
	sort.SliceStable(deduped, func(i, j int) bool {
		return deduped[i].ID < deduped[j].ID
	})
	for i := range deduped {
		if deduped[i].ID == "custom" {
			cust := deduped[i]
			deduped = append(deduped[:i], deduped[i+1:]...)
			deduped = append(deduped, cust)
			break
		}
	}
	finalList = deduped
}

// Builtin returns a fresh copy of the compiled-in catalog so
// callers cannot mutate the package-level slice.
func Builtin() []Entry {
	initOnce.Do(finalize)
	out := make([]Entry, len(finalList))
	copy(out, finalList)
	return out
}

// LookupBuiltin returns the entry for id (case-insensitive trim)
// and a boolean reporting whether it exists.
func LookupBuiltin(id string) (Entry, bool) {
	initOnce.Do(finalize)
	id = strings.TrimSpace(strings.ToLower(id))
	for _, e := range finalList {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// ClientIDForEntry returns the OAuth client ID Xalgorix should use
// for the given entry. Operators can override the compiled-in
// default with the env var XALGORIX_<UPPER_ID>_OAUTH_CLIENT_ID
// (e.g. XALGORIX_GOOGLE_OAUTH_CLIENT_ID for the "google" slug).
// When the env var is unset, the entry's compiled-in ClientID
// (often empty) is returned verbatim.
//
// This is the escape hatch for providers that require per-deploy
// client IDs — Google's OAuth client constraint is the canonical
// case, and the escape hatch lets operators wire their own ID
// without rebuilding xalgorix.
func ClientIDForEntry(e Entry) string {
	upper := strings.ToUpper(strings.ReplaceAll(e.ID, "-", "_"))
	envKey := "XALGORIX_" + upper + "_OAUTH_CLIENT_ID"
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return e.ClientID
}
