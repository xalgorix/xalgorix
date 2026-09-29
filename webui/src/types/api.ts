// Types mirror Go structs in internal/web/server.go.
// These are inferred from the actual backend, not invented.

export interface VulnSummary {
  id: string;
  source_scan_id?: string;
  title: string;
  severity: string;
  target?: string;
  endpoint: string;
  cvss: number;
  cvss_vector?: string;
  description?: string;
  impact?: string;
  method?: string;
  cve?: string;
  cwe_id?: string;
  owasp?: string;
  technical_analysis?: string;
  poc_description?: string;
  poc_script?: string;
  remediation?: string;
  fix?: string;
  exploitation_proof?: string;
  verification_method?: string;
  verified?: boolean;
  // Machine-readable labels. Always carries a verification tag:
  // "verified" (independently reproduced) or "needs-manual-verification"
  // (preserved but not confirmed — a human must review it).
  tags?: string[];
}

export interface WSEvent {
  type: string;
  content?: string;
  tool_name?: string;
  tool_args?: Record<string, string>;
  output?: string;
  error?: string;
  agent_id?: string;
  instance_id?: string;
  timestamp?: string;
  vulns?: VulnSummary[];
  target_index?: number;
  total_targets?: number;
  target?: string;
  total_tokens?: number;
  sub_target_index?: number;
  sub_target_total?: number;
  parent_target?: string;
  current_phase?: number;
}

export interface ScanInstance {
  id: string;
  name?: string;
  targets: string;
  parent_target?: string;
  status: string;
  started_at: string;
  finished_at?: string;
  stop_reason?: string;
  iterations: number;
  tool_calls: number;
  vuln_count: number;
  total_tokens: number;
  scan_mode: string;
  instruction?: string;
  severity_filter?: string[];
  phases?: number[];
  recon_mode?: "active" | "passive";
  scan_intensity?: "active" | "passive";
  company_name?: string;
  logo_path?: string;
  vulns?: VulnSummary[];
  current_phase?: number;
  phase_status?: Record<string, string>;
  phases_worked?: number[];
}

export interface SubScanSummary {
  id: string;
  target: string;
  started_at?: string;
  finished_at?: string;
  status: string;
  vuln_count: number;
  total_tokens: number;
}

export interface ScanRecord {
  id: string;
  instance_id?: string;
  name?: string;
  target: string;
  parent_target?: string;
  started_at: string;
  finished_at?: string;
  status: string;
  stop_reason?: string;
  scan_mode?: string;
  instruction?: string;
  severity_filter?: string[];
  discord_webhook?: string;
  discord_webhook_configured?: boolean;
  telegram_configured?: boolean;
  recon_mode?: "active" | "passive";
  scan_intensity?: "active" | "passive";
  events: WSEvent[];
  // GET /api/scans/{id} returns only the most recent events inline. When the
  // scan's log is longer, events_truncated is true and events_total is the
  // full count; older events are paged via GET /api/scans/{id}/events.
  events_total?: number;
  events_truncated?: boolean;
  vulns: VulnSummary[];
  total_tokens: number;
  iterations: number;
  tool_calls: number;
  company_name?: string;
  logo_path?: string;
  phases?: number[];
  current_phase?: number;
  // phase_status is the authoritative per-phase disposition derived by the
  // backend from engine evidence (plan tasks, hypothesis ledger, recon
  // dimensions, terminal lifecycle): "completed" | "active" | "pending" |
  // "blocked" | "not_applicable" | "not_selected", keyed by phase id.
  phase_status?: Record<string, string>;
  // phases_worked lists phases the engine observed concrete work for.
  phases_worked?: number[];
  sub_scans?: SubScanSummary[];
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
}

/** One page of a scan's event log, from GET /api/scans/{id}/events. */
export interface ScanEventsPage {
  events: WSEvent[];
  total: number;
  offset: number;
  limit: number;
}

export interface ScanListItem {
  id: string;
  target: string;
  started_at: string;
  status: string;
  scan_mode?: string;
  vuln_count: number;
  total_tokens: number;
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
}

/** Generic server-side pagination envelope: { items, total, page, size }. */
export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

/** Query params accepted by the paginated list endpoints. */
export interface ListParams {
  page: number;
  size: number;
  q?: string;
  status?: string;
  mode?: string;
}

export interface InstancesResponse {
  instances: ScanInstance[];
  // Present when the request used server-side pagination/filtering.
  total?: number;
  page?: number;
  size?: number;
  /** Distinct scan modes across all instances, for the filter dropdown. */
  modes?: string[];
  resources: {
    cpu_cores: number;
    cpu_load_1m: number;
    ram_total_mb: number;
    ram_available_mb: number;
    disk_free_mb: number;
    process_rss_mb?: number;
    go_heap_alloc_mb?: number;
    go_heap_sys_mb?: number;
    goroutines?: number;
    level: string;
    reason: string;
    max_instances: number;
    manual_max_instances: number;
    effective_max_instances: number;
    running_instances?: number;
    unreflected_admissions?: number;
    available_instance_slots?: number;
    active_tool_leases?: number;
    active_heavy_tool_leases?: number;
    heavy_tool_slots?: number;
    light_tool_slots?: number;
    tool_mem_limit_mb?: number;
    scan_memory_budget_mb?: number;
    heavy_tool_cpu_load?: number;
    go_memory_limit_mb?: number;
  };
}

export interface StatusResponse {
  running: boolean;
  scan_id: string;
  instance_id: string;
  current_phase: number;
  vulns: number;
  running_instances: number;
}

export interface VersionInfo {
  version: string;
  ai?: {
    configured: boolean;
    provider: string;
    model?: string;
    gateway?: string;
  };
}

export interface AuthStatus {
  auth_enabled: boolean;
  authenticated: boolean;
}

export interface ScanRequest {
  targets: string[];
  instruction?: string;
  scan_mode?: string;
  model?: string;
  api_key?: string;
  api_base?: string;
  discord_webhook?: string;
  severity_filter?: string[];
  name?: string;
  save_only?: boolean;
  phases?: number[];
  recon_mode?: "active" | "passive";
  scan_intensity?: "active" | "passive";
  company_name?: string;
  logo_path?: string;
  // Server-side path to an uploaded context artifact (OpenAPI/Swagger, HAR, or
  // Postman collection). The engine parses it into a seeded attack surface and
  // harvests any captured auth. Set via POST /api/upload-context.
  scan_context?: string;
  // Authenticated-session material applied automatically to http_request
  // ("Cookie: …; Authorization: Bearer …"). Enables post-login testing.
  target_auth?: string;
  // A SECOND account's auth (same format), surfaced to the agent to prove
  // horizontal access-control flaws (IDOR/BOLA). Not auto-applied.
  target_auth_b?: string;
  // Optional "<provider>:<profileId>" key naming the AuthProfile to
  // use for this scan. When unset the legacy / catalog-default path
  // applies. Mirrors the Go ScanRequest.ProviderProfile field on
  // /api/scan and is honored only for authenticated operators
  // (Requirement 11.1, 11.5).
  provider_profile?: string;
}

// ---------------------------------------------------------------------------
// Provider catalog + auth profile contract types
//
// Mirror the JSON shapes returned by the catalog and profile HTTP
// surface added in this feature. The on-the-wire field names are
// pinned by the design — keep these types in sync with
// internal/providers/types.go (CatalogEntry ↔ providers.Entry) and
// internal/auth/profile.go (AuthProfile ↔ auth.Profile, masked at
// the HTTP boundary by internal/web/masks.go).
// ---------------------------------------------------------------------------

// CatalogEntry mirrors providers.Entry. The compiled-in LLM
// provider catalog returned by GET /api/providers in v4.4.22+.
export interface CatalogEntry {
  id: string;
  displayName: string;
  baseURL: string;
  models?: string[];
  headerStyle: "openai" | "openai_responses" | "anthropic" | "gemini";
  // v4.4.22 surfaces AuthMethods so the dashboard can render the
  // matching sub-form (api_key / oauth / none) without duplicating
  // the catalog's policy. Older servers omit this field entirely.
  authMethods?: Array<"api_key" | "oauth" | "none">;
  flow?: "" | "pkce" | "device_code" | "setup_token" | "claude_cli_reuse" | "codex_cli_reuse";
  clientID?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  deviceAuthorizationEndpoint?: string;
  revocationEndpoint?: string;
  scopes?: string[];
  audience?: string;
  // Free-form per-provider caveat surfaced as a hint in the LLM
  // tab (beta status, env-var overrides, etc.).
  notes?: string;
}

// AuthProfileType discriminates between the two stored credential
// shapes returned by GET /api/auth/profiles.
export type AuthProfileType = "api_key" | "oauth";

// AuthProfile mirrors auth.Profile. Credential strings (apiKey,
// accessToken, refreshToken) are MASKED on the wire — the server
// returns "****" for empty/short values and "****<last8>" for longer
// ones (see internal/web/masks.go, Requirements 5.1, 5.2). The
// expiresAt and updatedAt fields are RFC3339 / ISO 8601 timestamps.
export interface AuthProfile {
  // Canonical "<provider>:<profileId>" key the rest of the system
  // uses to reference this profile. Older servers (pre-v4.4.22)
  // may omit it; consumers that need a key should fall back to
  // ${provider}:${profileId}.
  key?: string;
  provider: string;
  profileId: string;
  type: AuthProfileType;
  // API_Key fields. Masked credential string when type === "api_key".
  apiKey?: string;
  // hasApiKey / hasAccessToken are convenience booleans returned by
  // the LLM settings handler (handlers_profiles.go returns the
  // masked credential directly; the LLM tab surface adds these to
  // make truthiness checks straightforward).
  hasApiKey?: boolean;
  apiBaseOverride?: string;
  // OAuth fields. Masked credential strings when type === "oauth".
  accessToken?: string;
  hasAccessToken?: boolean;
  refreshToken?: string;
  expiresAt?: string;
  scopes?: string[];
  tokenType?: string;
  requiresReauth?: boolean;
  updatedAt?: string;
}

// OAuthStartMode discriminates the three shapes returned by
// POST /api/auth/profiles/oauth/start. "loopback" includes authURL
// for an ephemeral 127.0.0.1 callback; "device" includes userCode
// and verificationURI for the device-code flow; "paste" returns
// authURL plus a flowId the dashboard feeds back to
// POST /api/auth/profiles/oauth/complete.
export type OAuthStartMode = "loopback" | "device" | "paste";

// OAuthStartSubmode disambiguates the three "paste" variants the
// dashboard renders differently. "paste_code" is the PKCE OOB
// fallback (textarea for the authorization code); "setup_token"
// is the setup_token driver (textarea for the one-time
// vendor-issued token). The empty / unspecified case is the
// claude_cli_reuse confirm-and-import UI (no input field — the
// credential file is already on disk and Complete reads it
// directly). Mirrors the Submode field on auth.StartResult (H9).
export type OAuthStartSubmode = "" | "paste_code" | "setup_token";

// OAuthStartResponse mirrors the auth.StartResult JSON envelope.
// Optional fields are populated per mode:
//   loopback: authURL, expiresAt
//   device:   userCode, verificationURI, expiresAt
//   paste:    authURL, expiresAt, submode
export interface OAuthStartResponse {
  flowId: string;
  mode: OAuthStartMode;
  // submode is only populated for mode === "paste"; older servers
  // omit it entirely. The dashboard treats undefined the same as
  // "" (claude_cli_reuse confirm-and-import) to stay backward-
  // compatible.
  submode?: OAuthStartSubmode;
  authURL?: string;
  userCode?: string;
  verificationURI?: string;
  expiresAt?: string;
}

export interface QueueStatus {
  available: boolean;
  queue_count?: number;
  total_remaining?: number;
  instance_id?: string;
  targets?: string[];
  current_idx?: number;
  remaining?: number;
  instruction?: string;
  scan_mode?: string;
  recon_mode?: "active" | "passive";
  scan_intensity?: "active" | "passive";
  paused?: boolean;
  active_target?: string;
  active_scan_id?: string;
  wildcard_active_target?: string;
  wildcard_active_scan_id?: string;
  wildcard_sub_index?: number;
  wildcard_subdomains_total?: number;
  started_at?: string;
}

export interface RateLimitSettings {
  requests: number;
  window: number;
}

export interface AgentMailSettings {
  pod: string;
  apiKey: string;
  hasApiKey: boolean;
}

export interface LLMSettings {
  model: string;
  apiBase: string;
  apiKey: string;
  hasApiKey: boolean;
  reasoningEffort: string;
  ollamaCompatible: boolean;
  llmMaxRetries: number;
  memoryCompressorTimeout: number;
  maxIterations: number;
  geminiApiKey: string;
  hasGeminiApiKey: boolean;
  envFile: string;
  // v4.4.22: catalog-aware fields driving the new LLM Settings tab.
  // Provider mirrors the active provider id. AuthMethod tracks
  // which branch the resolver currently dispatches through.
  // Profiles is the masked list of saved profiles for the active
  // provider only.
  provider?: string;
  authMethod?: "" | "api_key" | "oauth" | "none";
  activeProfileKey?: string;
  profiles?: LLMProfileSummary[];
}

// LLMProfileSummary is the masked, dashboard-friendly view of one
// auth.Profile filtered to the active provider in the LLM tab.
export interface LLMProfileSummary {
  key: string;
  provider: string;
  profileId: string;
  type: AuthProfileType;
  hasAccessToken: boolean;
  hasApiKey: boolean;
  apiBaseOverride?: string;
  expiresAt?: string;
  requiresReauth?: boolean;
}

// LLMSettingsRequest is the POST body shape accepted by
// PUT /api/settings/llm. The v4.4.22 fields (provider/authMethod/
// profileId/activeProfileKey/apiBaseOverride) drive the catalog-
// aware path; if any of those is supplied the handler dispatches
// through applyCatalogLLMSettings. Otherwise the legacy fields
// (model/apiBase/apiKey/...) take the v4.4.21 free-text path.
export interface LLMSettingsRequest {
  model?: string;
  apiBase?: string;
  apiKey?: string;
  reasoningEffort?: string;
  ollamaCompatible?: boolean;
  llmMaxRetries?: number;
  memoryCompressorTimeout?: number;
  maxIterations?: number;
  geminiApiKey?: string;
  // v4.4.22 catalog-aware fields.
  provider?: string;
  authMethod?: "api_key" | "oauth" | "none";
  profileId?: string;
  apiBaseOverride?: string;
  activeProfileKey?: string;
}

export interface EnvironmentVariableSetting {
  key: string;
  label: string;
  category: string;
  description: string;
  defaultValue?: string;
  placeholder?: string;
  inputType:
    | "text"
    | "url"
    | "path"
    | "secret"
    | "number"
    | "boolean"
    | "select"
    | "multiselect";
  options?: string[];
  sensitive: boolean;
  requiresRestart: boolean;
  value: string;
  hasValue: boolean;
}

export interface EnvironmentSettings {
  envFile: string;
  variables: EnvironmentVariableSetting[];
  restartRequired?: boolean;
}

export interface ScanSchedule {
  id: string;
  name: string;
  interval: string;
  // Wall-clock time of day the schedule fires, "HH:MM" in 24h form and
  // interpreted in `timezone`. Empty/absent keeps the legacy behavior of
  // running one interval after creation or the last run. For the "hourly"
  // interval only the minutes apply.
  run_at?: string;
  // Day within the interval: weekday for "weekly" (0=Sunday … 6=Saturday) and
  // day of month for "monthly" (1-31, clamped to the last day of shorter
  // months). Ignored for "hourly" and "daily".
  run_day?: number;
  // IANA timezone name `run_at`/`run_day` are read in, e.g.
  // "America/Argentina/Buenos_Aires". Empty means the server's local time.
  timezone?: string;
  next_run: string;
  last_run?: string;
  enabled: boolean;
  targets: string[];
  instruction?: string;
  scan_mode: string;
  severity_filter?: string[];
  phases?: number[];
  recon_mode?: "active" | "passive";
  scan_intensity?: "active" | "passive";
  company_name?: string;
  logo_path?: string;
  discord_webhook?: string;
  model?: string;
  // Optional "<provider>:<profileId>" key naming the AuthProfile this
  // schedule should run scans under (provider-catalog-and-oauth, R14.4).
  // Mirrors ScanRequest.provider_profile; persisted on the schedule
  // and re-applied on each trigger.
  provider_profile?: string;
}

// Response shape of GET /api/findings/summary. Polled every 10s by the
// Findings and Overview pages; counts are deduplicated server-side by
// (target, endpoint, title, severity) so the totals strip and the
// row list always agree. The same query key (qk.findingsSummary) is
// used on both pages so the React Query cache is shared.
export interface FindingsSummaryResponse {
  totals: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  as_of: string;
  etag: string;
}
