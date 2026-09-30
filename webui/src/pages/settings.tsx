import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Search, RefreshCw, Trash2, CheckCircle2, AlertTriangle } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { ErrorState } from "@/components/states";
import {
  useAgentMail,
  useAuthProfiles,
  useDeleteAuthProfile,
  useDiscoverProviderModels,
  useEnvironmentSettings,
  useLLMSettings,
  useProviders,
  useRateLimit,
  useRefreshAuthProfile,
  useUpdateAgentMail,
  useUpdateEnvironmentSettings,
  useUpdateLLMSettings,
  useUpdateRateLimit,
  useAuthStatus,
  useImportSettings,
} from "@/api/queries";
import { api } from "@/api/client";
import { useAuth } from "@/store/auth";
import type {
  AuthProfile,
  CatalogEntry,
  EnvironmentSettings,
  EnvironmentVariableSetting,
  LLMSettingsRequest,
  SettingsBackup,
  SettingsImportResult,
} from "@/types/api";
import OAuthModal from "./settings/oauth-modal";
import { syncLanguageFromServer, useI18n } from "@/i18n";

const settingsTabs = [
  "llm",
  "engagement",
  "notifications",
  "email",
  "environment",
  "account",
] as const;

type SettingsTab = (typeof settingsTabs)[number];

// LLMFormState mirrors the catalog-aware POST shape. We keep the
// numeric / Gemini fields here too so the bottom row of inputs
// (max retries, memory timeout, max iterations, Gemini search key)
// continues to live on the same tab. Empty string sentinels make
// the diff against the loaded settings state explicit.
interface LLMFormState {
  provider: string;
  authMethod: "" | "api_key" | "oauth" | "none";
  profileId: string;
  apiKey: string;
  apiBase: string;
  apiBaseOverride: string;
  model: string;
  reasoningEffort: string;
  ollamaCompatible: boolean;
  llmMaxRetries: number;
  memoryCompressorTimeout: number;
  maxIterations: number;
  geminiApiKey: string;
  hasApiKey: boolean;
  hasGeminiApiKey: boolean;
  envFile: string;
  activeProfileKey: string;
}

const emptyLLMForm: LLMFormState = {
  provider: "",
  authMethod: "",
  profileId: "default",
  apiKey: "",
  apiBase: "",
  apiBaseOverride: "",
  model: "",
  reasoningEffort: "high",
  ollamaCompatible: false,
  llmMaxRetries: 5,
  memoryCompressorTimeout: 30,
  maxIterations: 0,
  geminiApiKey: "",
  hasApiKey: false,
  hasGeminiApiKey: false,
  envFile: "",
  activeProfileKey: "",
};

export default function SettingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab") as SettingsTab | null;
  const activeTab = settingsTabs.includes(requestedTab as SettingsTab)
    ? (requestedTab as SettingsTab)
    : "llm";

  const { t } = useI18n();
  const rate = useRateLimit();
  const updateRate = useUpdateRateLimit();
  const mail = useAgentMail();
  const updateMail = useUpdateAgentMail();
  const llm = useLLMSettings();
  const updateLLM = useUpdateLLMSettings();
  const environment = useEnvironmentSettings();
  const updateEnvironment = useUpdateEnvironmentSettings();
  const auth = useAuthStatus();
  const logout = useAuth((s) => s.logout);
  const navigate = useNavigate();

  const providers = useProviders();
  const profiles = useAuthProfiles();
  const refreshProfile = useRefreshAuthProfile();
  const deleteProfile = useDeleteAuthProfile();

  const [rateForm, setRateForm] = useState({ requests: 10, window: 1 });
  const [mailForm, setMailForm] = useState({ pod: "", apiKey: "" });
  const [llmForm, setLLMForm] = useState<LLMFormState>(emptyLLMForm);
  const [oauthOpen, setOAuthOpen] = useState(false);
  const [notificationForm, setNotificationForm] = useState({
    webhook: "",
    minSeverity: "",
    telegramBotToken: "",
    telegramChatId: "",
    telegramMinSeverity: "",
    notifyScanComplete: false,
  });
  const [envValues, setEnvValues] = useState<Record<string, string>>({});
  const [envChanges, setEnvChanges] = useState<Record<string, string>>({});
  const [envFilter, setEnvFilter] = useState("");
  const [envRestartRequired, setEnvRestartRequired] = useState(false);
  const [savedRate, setSavedRate] = useState(false);
  const [savedMail, setSavedMail] = useState(false);
  const [savedLLM, setSavedLLM] = useState(false);
  const [savedNotifications, setSavedNotifications] = useState(false);
  const [savedEnvironment, setSavedEnvironment] = useState(false);

  useEffect(() => {
    if (rate.data) {
      setRateForm({
        requests: rate.data.requests ?? 10,
        window: rate.data.window ?? 1,
      });
    }
  }, [rate.data]);

  useEffect(() => {
    if (mail.data) {
      setMailForm({
        pod: mail.data.pod ?? "",
        apiKey: mail.data.apiKey ?? "",
      });
    }
  }, [mail.data]);

  useEffect(() => {
    if (!llm.data) return;
    // Derive the form state from the settings response. We keep
    // both the legacy fields (model/apiBase/apiKey) and the new
    // catalog fields (provider/authMethod/activeProfileKey) so a
    // user who picks a provider but doesn't change anything else
    // still sees the saved values in the lower-row inputs.
    setLLMForm({
      provider: llm.data.provider ?? "",
      authMethod: (llm.data.authMethod as LLMFormState["authMethod"]) ?? "",
      profileId: "default",
      apiKey: llm.data.apiKey ?? "",
      apiBase: llm.data.apiBase ?? "",
      apiBaseOverride: "",
      model: bareModelForProvider(llm.data.model ?? "", llm.data.provider ?? ""),
      reasoningEffort: llm.data.reasoningEffort || "high",
      ollamaCompatible: llm.data.ollamaCompatible ?? false,
      llmMaxRetries: llm.data.llmMaxRetries ?? 5,
      memoryCompressorTimeout: llm.data.memoryCompressorTimeout ?? 30,
      maxIterations: llm.data.maxIterations ?? 0,
      geminiApiKey: llm.data.geminiApiKey ?? "",
      hasApiKey: llm.data.hasApiKey ?? false,
      hasGeminiApiKey: llm.data.hasGeminiApiKey ?? false,
      envFile: llm.data.envFile ?? "",
      activeProfileKey: llm.data.activeProfileKey ?? "",
    });
  }, [llm.data]);

  useEffect(() => {
    const webhook = envValue(environment.data, "XALGORIX_DISCORD_WEBHOOK");
    const minSeverity = envValue(environment.data, "XALGORIX_DISCORD_MIN_SEVERITY");
    const telegramBotToken = envValue(environment.data, "XALGORIX_TELEGRAM_BOT_TOKEN");
    const telegramChatId = envValue(environment.data, "XALGORIX_TELEGRAM_CHAT_ID");
    const telegramMinSeverity = envValue(environment.data, "XALGORIX_TELEGRAM_MIN_SEVERITY");
    const notifyScanComplete = envValue(environment.data, "XALGORIX_NOTIFY_SCAN_COMPLETE") === "true";
    setNotificationForm({ webhook, minSeverity, telegramBotToken, telegramChatId, telegramMinSeverity, notifyScanComplete });
  }, [environment.data]);

  useEffect(() => {
    if (!environment.data) return;
    setEnvValues(
      Object.fromEntries(
        environment.data.variables.map((variable) => [
          variable.key,
          variable.value ?? "",
        ]),
      ),
    );
    setEnvChanges({});
  }, [environment.data]);

  // Adopt the operator's configured output language as the dashboard UI
  // language when this browser has no explicit preference yet, so a fresh
  // install honors XALGORIX_LANGUAGE. An explicit in-browser choice wins.
  useEffect(() => {
    const configured = envValue(environment.data, "XALGORIX_LANGUAGE");
    if (configured) syncLanguageFromServer(configured);
  }, [environment.data]);

  // Sort providers alphabetically by displayName, with the
  // "custom" sentinel pinned last because it represents free-form
  // user-supplied endpoints rather than a discrete provider.
  const sortedProviders = useMemo<CatalogEntry[]>(() => {
    const list = providers.data ?? [];
    return [...list].sort((a, b) => {
      if (a.id === "custom") return 1;
      if (b.id === "custom") return -1;
      return a.displayName.localeCompare(b.displayName);
    });
  }, [providers.data]);

  const selectedProvider = useMemo<CatalogEntry | undefined>(() => {
    if (!llmForm.provider) return undefined;
    return sortedProviders.find((p) => p.id === llmForm.provider);
  }, [sortedProviders, llmForm.provider]);

  const ollamaPortDetected = useMemo(
    () => hasOllamaPort(llmForm.apiBase),
    [llmForm.apiBase],
  );
  const ollamaMode =
    llmForm.provider === "ollama" ||
    ollamaPortDetected ||
    llmForm.ollamaCompatible;

  // Auth methods come straight from the catalog entry. Custom
  // provider always supports api_key (it's just a free-form base
  // URL + key); local-runtime providers (Ollama, LM Studio) only
  // expose "none". The default selection is the first method in
  // AuthMethods, falling back to api_key.
  const availableAuthMethods = useMemo<string[]>(() => {
    if (!selectedProvider) return [];
    return selectedProvider.id === "custom"
      ? ["api_key"]
      : selectedProvider.authMethods ?? ["api_key"];
  }, [selectedProvider]);

  // Filter the profile list to the selected provider for the
  // saved-credentials picker. The dashboard never sees plaintext
  // credentials — only the masked envelope.
  const providerProfiles = useMemo<AuthProfile[]>(() => {
    if (!llmForm.provider) return [];
    return (profiles.data ?? []).filter((p) => p.provider === llmForm.provider);
  }, [profiles.data, llmForm.provider]);

  // Every saved profile across ALL providers, enriched with the
  // catalog display name and an active flag. This is the same list
  // the schedule / scan "Provider profile" pickers draw from, so the
  // Settings page can review and delete credentials that belong to a
  // provider other than the one currently selected above.
  const allProfiles = useMemo(() => {
    const byID = new Map((providers.data ?? []).map((e) => [e.id, e]));
    return (profiles.data ?? []).map((profile) => {
      const key = profile.key ?? `${profile.provider}:${profile.profileId}`;
      return {
        profile,
        key,
        display: byID.get(profile.provider)?.displayName ?? profile.provider,
        active: key === llmForm.activeProfileKey,
      };
    });
  }, [profiles.data, providers.data, llmForm.activeProfileKey]);

  function changeTab(value: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", value);
    setSearchParams(next, { replace: true });
  }

  function changeProvider(providerId: string) {
    const entry = sortedProviders.find((p) => p.id === providerId);
    const methods = entry?.authMethods ?? ["api_key"];
    setLLMForm((current) => ({
      ...current,
      provider: providerId,
      authMethod: (methods[0] as LLMFormState["authMethod"]) ?? "api_key",
      // Never carry a model across providers. The selected provider is
      // discovered automatically when possible; otherwise the operator
      // enters the model explicitly.
      model: "",
      activeProfileKey: "",
      apiKey: "",
      hasApiKey: false,
      apiBaseOverride: "",
      ollamaCompatible: false,
      // Ollama supports none/low/medium/high, while the Responses API also
      // exposes xhigh. Keep the current value when valid and normalize only
      // the provider-specific values during a switch.
      reasoningEffort: normalizeReasoningEffort(
        current.reasoningEffort,
        providerId === "ollama",
      ),
      // apiBase resets to the catalog default; "custom" leaves the
      // current free-text base intact.
      apiBase: entry?.id === "custom" ? current.apiBase : entry?.baseURL ?? "",
    }));
  }

  function updateEnvValue(variable: EnvironmentVariableSetting, value: string) {
    setEnvValues((current) => ({ ...current, [variable.key]: value }));
    setEnvChanges((current) => {
      const next = { ...current };
      if (value === (variable.value ?? "")) {
        delete next[variable.key];
      } else {
        next[variable.key] = value;
      }
      return next;
    });
  }

  async function saveLLMSettings() {
    setSavedLLM(false);
    const profileId = llmForm.profileId || "default";
    const req: LLMSettingsRequest = {
      provider: llmForm.provider,
      authMethod: (llmForm.authMethod || "api_key") as
        | "api_key"
        | "oauth"
        | "none",
      profileId,
      model: llmForm.model,
      reasoningEffort: llmForm.reasoningEffort,
      ollamaCompatible: llmForm.ollamaCompatible,
      llmMaxRetries: llmForm.llmMaxRetries,
      memoryCompressorTimeout: llmForm.memoryCompressorTimeout,
      maxIterations: llmForm.maxIterations,
    };
    if (llmForm.authMethod === "api_key") {
      // Only send the apiKey when the user actually typed
      // something — the masked **** value means "leave the
      // saved key alone" (matches the legacy POST contract).
      if (!isMaskedSettingValue(llmForm.apiKey)) {
        req.apiKey = llmForm.apiKey;
      }
      if (llmForm.apiBaseOverride) {
        req.apiBaseOverride = llmForm.apiBaseOverride;
      }
      if (selectedProvider?.id === "custom" && llmForm.apiBase) {
        req.apiBase = llmForm.apiBase;
      }
    }
    if (llmForm.authMethod === "oauth" && llmForm.provider) {
      // OAuth providers (e.g. Codex ChatGPT subscription) finish their
      // sign-in through the OAuth modal, which persists a profile keyed
      // "<provider>:<profileId>". Saving the LLM tab must point the active
      // credential pointer (XALGORIX_LLM_PROFILE) at that profile —
      // otherwise the backend keeps the previous (legacy) provider and only
      // the model changes. Prefer an explicitly-selected profile key.
      req.activeProfileKey =
        llmForm.activeProfileKey || `${llmForm.provider}:${profileId}`;
    }
    if (llmForm.authMethod === "none") {
      req.activeProfileKey = "";
    }
    if (!isMaskedSettingValue(llmForm.geminiApiKey)) {
      req.geminiApiKey = llmForm.geminiApiKey;
    }
    await updateLLM.mutateAsync(req);
    setSavedLLM(true);
    setTimeout(() => setSavedLLM(false), 2500);
  }

  async function setActiveProfile(profile: AuthProfile) {
    await updateLLM.mutateAsync({
      activeProfileKey: profile.key ?? `${profile.provider}:${profile.profileId}`,
    });
  }

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">
          {t("settings.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          LLM provider, environment variables, integrations, and account access.
        </p>
      </header>

      <Tabs value={activeTab} onValueChange={changeTab}>
        <TabsList className="flex h-auto flex-wrap">
          <TabsTrigger value="llm">{t("settings.tab.llm")}</TabsTrigger>
          <TabsTrigger value="engagement">{t("settings.tab.engagement")}</TabsTrigger>
          <TabsTrigger value="notifications">{t("settings.tab.notifications")}</TabsTrigger>
          <TabsTrigger value="email">{t("settings.tab.email")}</TabsTrigger>
          <TabsTrigger value="environment">{t("settings.tab.environment")}</TabsTrigger>
          <TabsTrigger value="account">{t("settings.tab.account")}</TabsTrigger>
        </TabsList>

        <TabsContent value="llm">
          {llm.isLoading || providers.isLoading ? (
            <Skeleton className="h-96" />
          ) : llm.error ? (
            <ErrorState
              title="Failed to load LLM settings"
              description={llm.error instanceof Error ? llm.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => llm.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.card.llmProvider")}</CardTitle>
                <CardDescription>
                  Saved to {llmForm.envFile || "~/.xalgorix.env"} and used by new scans.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="llm-provider">Provider</Label>
                    <Select
                      value={llmForm.provider || "__unset__"}
                      onValueChange={(value) =>
                        changeProvider(value === "__unset__" ? "" : value)
                      }
                    >
                      <SelectTrigger id="llm-provider">
                        <SelectValue placeholder="Select a provider" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__unset__">Not selected</SelectItem>
                        {sortedProviders.map((provider) => (
                          <SelectItem key={provider.id} value={provider.id}>
                            {provider.displayName}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  {selectedProvider && availableAuthMethods.length > 1 && (
                    <div className="space-y-2">
                      <Label>Authentication method</Label>
                      <div className="flex flex-wrap gap-2 rounded-md border border-border bg-muted/30 p-1">
                        {availableAuthMethods.map((method) => (
                          <Button
                            key={method}
                            type="button"
                            size="sm"
                            variant={
                              llmForm.authMethod === method ? "default" : "ghost"
                            }
                            onClick={() =>
                              setLLMForm({
                                ...llmForm,
                                authMethod: method as LLMFormState["authMethod"],
                              })
                            }
                          >
                            {prettyAuthMethod(method)}
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {selectedProvider?.notes && (
                  <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
                    {selectedProvider.notes}
                  </div>
                )}

                {selectedProvider && (
                  <CatalogModelField
                    provider={selectedProvider}
                    value={llmForm.model}
                    profileKey={
                      llmForm.authMethod === "none"
                        ? ""
                        : llmForm.activeProfileKey.startsWith(
                              `${selectedProvider.id}:`,
                            )
                          ? llmForm.activeProfileKey
                          : (providerProfiles[0]?.key ??
                            (providerProfiles[0]
                              ? `${providerProfiles[0].provider}:${providerProfiles[0].profileId}`
                              : ""))
                    }
                    autoDiscover={
                      llmForm.authMethod === "none" ||
                      providerProfiles.length > 0 ||
                      llm.data?.provider === selectedProvider.id
                    }
                    onChange={(model) =>
                      setLLMForm({ ...llmForm, model })
                    }
                  />
                )}

                {/* Auth-method-specific form */}
                {selectedProvider && llmForm.authMethod === "api_key" && (
                  <div className="grid gap-3 lg:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="llm-api-key">API key</Label>
                      <Input
                        id="llm-api-key"
                        value={llmForm.apiKey}
                        onChange={(e) =>
                          setLLMForm({ ...llmForm, apiKey: e.target.value })
                        }
                        placeholder={llmForm.hasApiKey ? "**** (saved)" : "sk-..."}
                        className="font-mono"
                      />
                      <p className="text-xs text-muted-foreground">
                        Keep the masked value to preserve the saved key.
                      </p>
                    </div>
                    {selectedProvider.id === "custom" ? (
                      <>
                        <div className="space-y-2">
                          <Label htmlFor="llm-api-base">Base URL</Label>
                          <Input
                            id="llm-api-base"
                            value={llmForm.apiBase}
                            onChange={(e) => {
                              const apiBase = e.target.value;
                              const nextOllamaMode =
                                hasOllamaPort(apiBase) ||
                                llmForm.ollamaCompatible;
                              setLLMForm({
                                ...llmForm,
                                apiBase,
                                reasoningEffort: normalizeReasoningEffort(
                                  llmForm.reasoningEffort,
                                  nextOllamaMode,
                                ),
                              });
                            }}
                            placeholder="https://api.example.com/v1"
                            className="font-mono"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="llm-header-style">Header style</Label>
                          <Select
                            value={llmForm.apiBase ? "openai" : "openai"}
                            onValueChange={() => {}}
                            disabled
                          >
                            <SelectTrigger id="llm-header-style">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="openai">openai</SelectItem>
                              <SelectItem value="anthropic">anthropic</SelectItem>
                              <SelectItem value="gemini">gemini</SelectItem>
                            </SelectContent>
                          </Select>
                          <p className="text-xs text-muted-foreground">
                            Custom providers default to OpenAI-shaped requests. Switch this from the Environment tab if your endpoint speaks Anthropic or Gemini.
                          </p>
                        </div>
                        <div className="flex items-center justify-between gap-4 rounded-md border border-border bg-muted/30 p-3 lg:col-span-2">
                          <div className="space-y-1">
                            <Label htmlFor="llm-ollama-compatible">
                              Ollama-compatible endpoint
                            </Label>
                            <p className="text-xs text-muted-foreground">
                              {ollamaPortDetected
                                ? "Detected automatically from port 11434."
                                : "Enable Ollama reasoning controls when this custom endpoint uses a different port."}
                            </p>
                          </div>
                          <Switch
                            id="llm-ollama-compatible"
                            checked={
                              ollamaPortDetected || llmForm.ollamaCompatible
                            }
                            disabled={ollamaPortDetected}
                            onCheckedChange={(checked) =>
                              setLLMForm({
                                ...llmForm,
                                ollamaCompatible: checked,
                                reasoningEffort: normalizeReasoningEffort(
                                  llmForm.reasoningEffort,
                                  checked || ollamaPortDetected,
                                ),
                              })
                            }
                          />
                        </div>
                      </>
                    ) : (
                      <div className="space-y-2 lg:col-span-2">
                        <Label htmlFor="llm-api-base-override">
                          API base override (optional)
                        </Label>
                        <Input
                          id="llm-api-base-override"
                          value={llmForm.apiBaseOverride}
                          onChange={(e) =>
                            setLLMForm({
                              ...llmForm,
                              apiBaseOverride: e.target.value,
                            })
                          }
                          placeholder={selectedProvider.baseURL}
                          className="font-mono"
                        />
                        <p className="text-xs text-muted-foreground">
                          Leave blank to use the provider default.
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {selectedProvider && llmForm.authMethod === "oauth" && (
                  <div className="space-y-3 rounded-md border border-border bg-muted/30 p-4">
                    <p className="text-sm">
                      Sign in with {selectedProvider.displayName} to create a
                      new OAuth profile. The dashboard polls until the new
                      credential appears in the saved list below.
                    </p>
                    <Button
                      type="button"
                      onClick={() => setOAuthOpen(true)}
                      disabled={!selectedProvider.flow}
                    >
                      Sign in with OAuth
                    </Button>
                    {!selectedProvider.flow && (
                      <p className="text-xs text-muted-foreground">
                        OAuth is not configured for this provider yet.
                      </p>
                    )}
                  </div>
                )}

                {selectedProvider && llmForm.authMethod === "none" && (
                  <div className="space-y-3 rounded-md border border-border bg-muted/30 p-4">
                    <p className="text-sm">
                      {selectedProvider.displayName} runs locally — no
                      credential required. Select or enter the model above.
                    </p>
                  </div>
                )}

                {/* Saved-credentials picker for the active provider. */}
                {selectedProvider && providerProfiles.length > 0 && (
                  <div className="space-y-2">
                    <Label>Saved credentials</Label>
                    <div className="divide-y divide-border rounded-md border border-border">
                      {providerProfiles.map((profile) => {
                        const key =
                          profile.key ??
                          `${profile.provider}:${profile.profileId}`;
                        const active = key === llmForm.activeProfileKey;
                        return (
                          <div
                            key={key}
                            className="flex flex-wrap items-center gap-3 px-3 py-2"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 text-sm font-medium">
                                {profile.profileId}
                                <Badge variant="muted">{profile.type}</Badge>
                                {active && (
                                  <CheckCircle2 className="h-4 w-4 text-success" />
                                )}
                                {profile.requiresReauth && (
                                  <Badge variant="warning">
                                    <AlertTriangle className="mr-1 h-3 w-3" />
                                    re-auth required
                                  </Badge>
                                )}
                              </div>
                              <div className="font-mono text-xs text-muted-foreground">
                                {profile.type === "oauth"
                                  ? maskedTokenLabel(profile)
                                  : maskedAPIKeyLabel(profile)}
                              </div>
                              {profile.expiresAt && (
                                <div className="text-xs text-muted-foreground">
                                  expires {profile.expiresAt}
                                </div>
                              )}
                            </div>
                            <div className="flex flex-wrap gap-2">
                              {!active && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={updateLLM.isPending}
                                  onClick={() => setActiveProfile(profile)}
                                >
                                  Set active
                                </Button>
                              )}
                              {profile.type === "oauth" && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={refreshProfile.isPending}
                                  onClick={() =>
                                    refreshProfile.mutateAsync(key)
                                  }
                                >
                                  <RefreshCw className="h-3.5 w-3.5" />
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={deleteProfile.isPending}
                                onClick={() => deleteProfile.mutateAsync(key)}
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* All saved provider profiles across every provider —
                    the same set the schedule / scan "Provider profile"
                    pickers offer. Lets the operator review and delete
                    credentials for providers other than the one selected
                    above (the picker there is scoped to that provider). */}
                {allProfiles.length > 0 && (
                  <div className="space-y-2">
                    <Label>All provider profiles</Label>
                    <p className="text-xs text-muted-foreground">
                      Every stored credential across all providers. These
                      are the profiles available in the schedule and scan
                      "Provider profile" pickers.
                    </p>
                    <div className="divide-y divide-border rounded-md border border-border">
                      {allProfiles.map(({ profile, key, display, active }) => (
                        <div
                          key={key}
                          className="flex flex-wrap items-center gap-3 px-3 py-2"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 text-sm font-medium">
                              {display} · {profile.profileId}
                              <Badge variant="muted">{profile.type}</Badge>
                              {active && (
                                <CheckCircle2 className="h-4 w-4 text-success" />
                              )}
                              {profile.requiresReauth && (
                                <Badge variant="warning">
                                  <AlertTriangle className="mr-1 h-3 w-3" />
                                  re-auth required
                                </Badge>
                              )}
                            </div>
                            <div className="font-mono text-xs text-muted-foreground">
                              {profile.type === "oauth"
                                ? maskedTokenLabel(profile)
                                : maskedAPIKeyLabel(profile)}
                            </div>
                            {profile.expiresAt && (
                              <div className="text-xs text-muted-foreground">
                                expires {profile.expiresAt}
                              </div>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={deleteProfile.isPending}
                              onClick={() => deleteProfile.mutateAsync(key)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <Separator />

                {/* Bottom row: numeric tuning that applies regardless
                    of provider / auth method. */}
                <div className="grid gap-3 lg:grid-cols-4">
                  <div className="space-y-2">
                    <Label htmlFor="llm-retries">LLM max retries</Label>
                    <Input
                      id="llm-retries"
                      type="number"
                      min={0}
                      max={20}
                      value={llmForm.llmMaxRetries}
                      onChange={(e) =>
                        setLLMForm({
                          ...llmForm,
                          llmMaxRetries: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="llm-memory-timeout">Memory timeout</Label>
                    <Input
                      id="llm-memory-timeout"
                      type="number"
                      min={5}
                      max={600}
                      value={llmForm.memoryCompressorTimeout}
                      onChange={(e) =>
                        setLLMForm({
                          ...llmForm,
                          memoryCompressorTimeout: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="llm-max-iterations">Max iterations</Label>
                    <Input
                      id="llm-max-iterations"
                      type="number"
                      min={0}
                      max={1000}
                      value={llmForm.maxIterations}
                      onChange={(e) =>
                        setLLMForm({
                          ...llmForm,
                          maxIterations: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="gemini-api-key">Gemini search key</Label>
                    <Input
                      id="gemini-api-key"
                      value={llmForm.geminiApiKey}
                      onChange={(e) =>
                        setLLMForm({ ...llmForm, geminiApiKey: e.target.value })
                      }
                      placeholder={
                        llmForm.hasGeminiApiKey ? "**** (saved)" : "AIza..."
                      }
                      className="font-mono"
                    />
                  </div>
                </div>

                <div className="grid gap-3 lg:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Reasoning effort</Label>
                    <Select
                      value={llmForm.reasoningEffort || "high"}
                      onValueChange={(value) =>
                        setLLMForm({ ...llmForm, reasoningEffort: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {(ollamaMode
                          ? ["none", "low", "medium", "high"]
                          : ["low", "medium", "high", "xhigh"]
                        ).map((value) => (
                          <SelectItem key={value} value={value}>
                            {value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator />
                <div className="flex items-center justify-end gap-3">
                  {savedLLM && <span className="text-xs text-success">{t("settings.savedIndicator")}</span>}
                  <Button
                    onClick={saveLLMSettings}
                    disabled={updateLLM.isPending || !llmForm.provider}
                  >
                    {updateLLM.isPending ? "Saving..." : "Save LLM settings"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* OAuth modal — opens when the user clicks "Sign in with
              OAuth". Polls /api/auth/profiles until a new entry for
              this provider appears. */}
          {selectedProvider && (
            <OAuthModal
              open={oauthOpen}
              provider={selectedProvider.id}
              displayName={selectedProvider.displayName}
              existingKeys={(profiles.data ?? []).map(
                (p) => p.key ?? `${p.provider}:${p.profileId}`,
              )}
              onClose={() => setOAuthOpen(false)}
            />
          )}
        </TabsContent>

        <TabsContent value="engagement">
          {rate.isLoading ? (
            <Skeleton className="h-72" />
          ) : rate.error ? (
            <ErrorState
              title="Failed to load rate limits"
              description={rate.error instanceof Error ? rate.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => rate.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.card.rateLimits")}</CardTitle>
                <CardDescription>
                  Applied to outbound requests issued by the agent and persisted to the env file.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="requests">Requests per window</Label>
                    <Input
                      id="requests"
                      type="number"
                      min={1}
                      max={1000}
                      value={rateForm.requests}
                      onChange={(e) =>
                        setRateForm({
                          ...rateForm,
                          requests: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="window">Window (seconds)</Label>
                    <Input
                      id="window"
                      type="number"
                      min={1}
                      max={600}
                      value={rateForm.window}
                      onChange={(e) =>
                        setRateForm({
                          ...rateForm,
                          window: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                </div>
                <div className="flex items-center justify-end gap-3">
                  {savedRate && (
                    <span className="text-xs text-success">{t("settings.savedIndicator")}</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedRate(false);
                      await updateRate.mutateAsync(rateForm);
                      setSavedRate(true);
                      setTimeout(() => setSavedRate(false), 2500);
                    }}
                    disabled={updateRate.isPending}
                  >
                    {updateRate.isPending ? "Saving..." : "Save"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="notifications">
          {environment.isLoading ? (
            <Skeleton className="h-72" />
          ) : environment.error ? (
            <ErrorState
              title="Failed to load notification settings"
              description={environment.error instanceof Error ? environment.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => environment.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <>
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.card.discord")}</CardTitle>
                <CardDescription>
                  Global defaults used unless a scan provides its own webhook.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-[1fr_220px]">
                  <div className="space-y-2">
                    <Label htmlFor="discord-webhook">Discord webhook</Label>
                    <Input
                      id="discord-webhook"
                      value={notificationForm.webhook}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          webhook: e.target.value,
                        })
                      }
                      placeholder="https://discord.com/api/webhooks/..."
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground">
                      Keep the masked value to preserve the saved webhook.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label>Minimum severity</Label>
                    <Select
                      value={notificationForm.minSeverity || "__unset__"}
                      onValueChange={(value) =>
                        setNotificationForm({
                          ...notificationForm,
                          minSeverity: value === "__unset__" ? "" : value,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__unset__">Default</SelectItem>
                        {["info", "low", "medium", "high", "critical"].map((value) => (
                          <SelectItem key={value} value={value}>
                            {value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <Separator />
                <div className="flex items-center justify-end gap-3">
                  {savedNotifications && (
                    <span className="text-xs text-success">{t("settings.savedIndicator")}</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedNotifications(false);
                      await updateEnvironment.mutateAsync({
                        XALGORIX_DISCORD_WEBHOOK: notificationForm.webhook,
                        XALGORIX_DISCORD_MIN_SEVERITY: notificationForm.minSeverity,
                        XALGORIX_TELEGRAM_BOT_TOKEN: notificationForm.telegramBotToken,
                        XALGORIX_TELEGRAM_CHAT_ID: notificationForm.telegramChatId,
                        XALGORIX_TELEGRAM_MIN_SEVERITY: notificationForm.telegramMinSeverity,
                        XALGORIX_NOTIFY_SCAN_COMPLETE: notificationForm.notifyScanComplete ? "true" : "false",
                      });
                      setSavedNotifications(true);
                      setTimeout(() => setSavedNotifications(false), 2500);
                    }}
                    disabled={updateEnvironment.isPending}
                  >
                    {updateEnvironment.isPending ? "Saving..." : "Save notifications"}
                  </Button>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.card.telegram")}</CardTitle>
                <CardDescription>
                  Send scan events and findings to a Telegram chat or channel.
                  Configure a bot via @BotFather and add it to the target chat as an admin.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-[1fr_1fr_220px]">
                  <div className="space-y-2">
                    <Label htmlFor="telegram-bot-token">Bot token</Label>
                    <Input
                      id="telegram-bot-token"
                      value={notificationForm.telegramBotToken}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramBotToken: e.target.value,
                        })
                      }
                      placeholder="123456789:ABC-DEF..."
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground">
                      Keep the masked value to preserve the saved token.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="telegram-chat-id">Chat ID</Label>
                    <Input
                      id="telegram-chat-id"
                      value={notificationForm.telegramChatId}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramChatId: e.target.value,
                        })
                      }
                      placeholder="-1001234567890 or @channelusername"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Minimum severity</Label>
                    <Select
                      value={notificationForm.telegramMinSeverity || "__unset__"}
                      onValueChange={(value) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramMinSeverity: value === "__unset__" ? "" : value,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__unset__">Default</SelectItem>
                        {["info", "low", "medium", "high", "critical"].map((value) => (
                          <SelectItem key={value} value={value}>
                            {value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <Separator />
                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <Label htmlFor="notify-scan-complete">Notify on scan completion</Label>
                    <p className="text-xs text-muted-foreground">
                      Send the &quot;Scan Finished&quot; summary (report ready / clean scan) after every scan.
                      Off by default — you only receive per-vulnerability alerts.
                    </p>
                  </div>
                  <Switch
                    id="notify-scan-complete"
                    checked={notificationForm.notifyScanComplete}
                    onCheckedChange={(checked) =>
                      setNotificationForm({
                        ...notificationForm,
                        notifyScanComplete: checked,
                      })
                    }
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  Telegram is independent of Discord — configure one or both.
                  The bot token is treated as a secret and never returned in API responses.
                </p>
              </CardContent>
            </Card>
            </>
          )}
        </TabsContent>

        <TabsContent value="email">
          {mail.isLoading ? (
            <Skeleton className="h-72" />
          ) : mail.error ? (
            <ErrorState
              title="Failed to load AgentMail settings"
              description={mail.error instanceof Error ? mail.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => mail.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.card.agentMail")}</CardTitle>
                <CardDescription>
                  Inbound triage requires a configured pod and API key.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Label htmlFor="pod">Pod</Label>
                  <Input
                    id="pod"
                    value={mailForm.pod}
                    onChange={(e) =>
                      setMailForm({ ...mailForm, pod: e.target.value })
                    }
                    placeholder="xalgorix-prod"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="apikey">API key</Label>
                  <Input
                    id="apikey"
                    value={mailForm.apiKey}
                    onChange={(e) =>
                      setMailForm({ ...mailForm, apiKey: e.target.value })
                    }
                    placeholder={mail.data?.hasApiKey ? "**** (saved)" : "ak_..."}
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave masked value untouched to keep the existing key.
                  </p>
                </div>
                <Separator />
                <div className="flex items-center justify-end gap-3">
                  {savedMail && (
                    <span className="text-xs text-success">{t("settings.savedIndicator")}</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedMail(false);
                      await updateMail.mutateAsync(mailForm);
                      setSavedMail(true);
                      setTimeout(() => setSavedMail(false), 2500);
                    }}
                    disabled={updateMail.isPending}
                  >
                    {updateMail.isPending ? "Saving..." : "Save"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="environment">
          {environment.isLoading ? (
            <Skeleton className="h-96" />
          ) : environment.error ? (
            <ErrorState
              title="Failed to load environment settings"
              description={environment.error instanceof Error ? environment.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => environment.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <div className="space-y-4">
              <BackupMigrationCard onRestartRequired={setEnvRestartRequired} />
              <Card>
                <CardContent className="space-y-4 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <p className="text-sm font-medium">Environment variables</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Editing {environment.data?.envFile || "~/.xalgorix.env"}. Masked secrets are preserved unless you replace or clear them.
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {envRestartRequired && (
                        <Badge variant="warning">Restart required for some changes</Badge>
                      )}
                      {Object.keys(envChanges).length > 0 && (
                        <Badge variant="outline">
                          {Object.keys(envChanges).length} unsaved
                        </Badge>
                      )}
                      {savedEnvironment && (
                        <span className="text-xs text-success">{t("settings.savedIndicator")}</span>
                      )}
                      <Button
                        onClick={async () => {
                          setSavedEnvironment(false);
                          const response = await updateEnvironment.mutateAsync(envChanges);
                          setEnvRestartRequired(Boolean(response.restartRequired));
                          setEnvChanges({});
                          setSavedEnvironment(true);
                          setTimeout(() => setSavedEnvironment(false), 2500);
                        }}
                        disabled={
                          updateEnvironment.isPending ||
                          Object.keys(envChanges).length === 0
                        }
                      >
                        {updateEnvironment.isPending ? "Saving..." : "Save changes"}
                      </Button>
                    </div>
                  </div>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={envFilter}
                      onChange={(e) => setEnvFilter(e.target.value)}
                      placeholder={t("settings.searchVariables")}
                      className="pl-8"
                    />
                  </div>
                </CardContent>
              </Card>

              {Object.entries(filterEnvironment(environment.data, envFilter)).map(
                ([category, variables]) => (
                  <Card key={category} className="overflow-hidden">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">{category}</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="divide-y divide-border">
                        {variables.map((variable) => (
                          <EnvironmentRow
                            key={variable.key}
                            variable={variable}
                            value={envValues[variable.key] ?? variable.value ?? ""}
                            changed={Object.prototype.hasOwnProperty.call(
                              envChanges,
                              variable.key,
                            )}
                            onChange={(value) => updateEnvValue(variable, value)}
                          />
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ),
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="account">
          <Card>
            <CardHeader>
              <CardTitle>{t("settings.card.account")}</CardTitle>
              <CardDescription>{t("settings.account.desc")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2 text-sm sm:grid-cols-2">
                <Field
                  label="Auth"
                  value={
                    auth.data?.auth_enabled
                      ? auth.data.authenticated
                        ? "Authenticated"
                        : "Logged out"
                      : "Disabled"
                  }
                />
                <Field
                  label="Session"
                  value={auth.data?.authenticated ? "Active" : "None"}
                />
              </div>
              {auth.data?.auth_enabled && (
                <>
                  <Separator />
                  <div className="flex justify-end">
                    <Button
                      variant="destructive"
                      onClick={async () => {
                        await logout();
                        navigate("/login", { replace: true });
                      }}
                    >
                      Sign out
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CatalogModelField({
  provider,
  value,
  profileKey,
  autoDiscover,
  onChange,
}: {
  provider: CatalogEntry;
  value: string;
  profileKey: string;
  autoDiscover: boolean;
  onChange: (value: string) => void;
}) {
  const discovery = useDiscoverProviderModels();
  const [discoveredModels, setDiscoveredModels] = useState<string[]>([]);
  const [manualEntry, setManualEntry] = useState(false);
  useEffect(() => {
    setDiscoveredModels([]);
    setManualEntry(false);
    discovery.reset();
    if (
      autoDiscover &&
      provider.id !== "custom" &&
      provider.baseURL
    ) {
      discovery.mutate(
        { provider: provider.id, profile: profileKey || undefined },
        {
          onSuccess: (result) => {
            setDiscoveredModels(result.models);
            if (result.models.length > 0 && !result.models.includes(value)) {
              onChange(result.models[0]);
            }
          },
        },
      );
    }
    // The provider/profile pair is the discovery identity. Mutation methods
    // are intentionally excluded so query state updates do not rescan.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider.id, profileKey, autoDiscover]);
  const models = discoveredModels;
  const options = models.map((model) => ({
    label: model,
    value: model,
  }));
  const selected = options.some((option) => option.value === value)
    ? value
    : options[0]?.value;

  return (
    <div className="space-y-2">
      <Label htmlFor="llm-model">Model</Label>
      {options.length > 0 && !manualEntry ? (
        <Select
          value={selected}
          onValueChange={(next) => {
            if (next === "__custom__") {
              setManualEntry(true);
              onChange("");
            } else {
              onChange(next);
            }
          }}
        >
          <SelectTrigger id="llm-model" className="font-mono">
            <SelectValue placeholder="Select a model" />
          </SelectTrigger>
          <SelectContent>
            {options.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
            <SelectItem value="__custom__">Custom model…</SelectItem>
          </SelectContent>
        </Select>
      ) : null}
      {(options.length === 0 || manualEntry) && (
        <Input
          id={options.length === 0 ? "llm-model" : undefined}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="model-name"
          aria-label={`Custom model for ${provider.displayName}`}
          className="font-mono"
        />
      )}
      {manualEntry && options.length > 0 && (
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={() => {
            setManualEntry(false);
            onChange(options[0].value);
          }}
        >
          Choose a discovered model
        </Button>
      )}
      <p className="text-xs text-muted-foreground">
        Models are loaded from the provider when its API supports discovery.
        Otherwise, enter the exact model ID manually.
      </p>
      {provider.id !== "custom" && provider.baseURL && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={discovery.isPending}
            onClick={() => {
              discovery.mutate(
                { provider: provider.id, profile: profileKey || undefined },
                {
                  onSuccess: (result) => {
                    setDiscoveredModels(result.models);
                    setManualEntry(false);
                    if (result.models.length > 0 && !result.models.includes(value)) {
                      onChange(result.models[0]);
                    }
                  },
                },
              );
            }}
          >
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${discovery.isPending ? "animate-spin" : ""}`} />
            {discovery.isPending ? "Scanning models…" : "Scan available models"}
          </Button>
          {discovery.isSuccess && (
            <span className="text-xs text-success">
              {discoveredModels.length} models loaded
            </span>
          )}
        </div>
      )}
      {discovery.isError && (
        <p className="text-xs text-destructive">
          {discovery.error instanceof Error
            ? discovery.error.message
            : "Model discovery failed"}
        </p>
      )}
    </div>
  );
}

function bareModelForProvider(model: string, provider: string): string {
  const prefix = `${provider.toLowerCase()}/`;
  return model.toLowerCase().startsWith(prefix)
    ? model.slice(prefix.length)
    : model;
}

function hasOllamaPort(value: string): boolean {
  try {
    return new URL(value).port === "11434";
  } catch {
    return false;
  }
}

function normalizeReasoningEffort(value: string, ollamaMode: boolean): string {
  if (ollamaMode && value === "xhigh") return "high";
  if (!ollamaMode && value === "none") return "high";
  return value;
}

function EnvironmentRow({
  variable,
  value,
  changed,
  onChange,
}: {
  variable: EnvironmentVariableSetting;
  value: string;
  changed: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-3 px-4 py-3 lg:grid-cols-[minmax(240px,360px)_1fr] lg:items-center">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="font-mono text-xs text-foreground">{variable.key}</p>
          {changed && <Badge variant="outline">edited</Badge>}
          {variable.requiresRestart && <Badge variant="warning">restart</Badge>}
          {!variable.hasValue && variable.defaultValue && (
            <Badge variant="muted">default {variable.defaultValue}</Badge>
          )}
        </div>
        <p className="text-sm font-medium">{variable.label}</p>
        <p className="text-xs text-muted-foreground">{variable.description}</p>
      </div>
      <EnvironmentControl variable={variable} value={value} onChange={onChange} />
    </div>
  );
}

function EnvironmentControl({
  variable,
  value,
  onChange,
}: {
  variable: EnvironmentVariableSetting;
  value: string;
  onChange: (value: string) => void;
}) {
  if (variable.inputType === "boolean") {
    return (
      <Select
        value={value === "" ? "__unset__" : value}
        onValueChange={(next) => onChange(next === "__unset__" ? "" : next)}
      >
        <SelectTrigger className="font-mono">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__unset__">Default / unset</SelectItem>
          <SelectItem value="true">true</SelectItem>
          <SelectItem value="false">false</SelectItem>
        </SelectContent>
      </Select>
    );
  }

  if (variable.inputType === "select") {
    return (
      <Select
        value={value === "" ? "__unset__" : value}
        onValueChange={(next) => onChange(next === "__unset__" ? "" : next)}
      >
        <SelectTrigger className="font-mono">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__unset__">Default / unset</SelectItem>
          {(variable.options ?? [])
            .filter((option) => option !== "")
            .map((option) => (
              <SelectItem key={option} value={option}>
                {option}
              </SelectItem>
            ))}
        </SelectContent>
      </Select>
    );
  }

  if (variable.inputType === "multiselect") {
    const options = variable.options ?? [];
    // Empty value means "all" (the default), so render every option selected.
    const selected =
      value.trim() === ""
        ? options.map((o) => o.toLowerCase())
        : value
            .split(",")
            .map((v) => v.trim().toLowerCase())
            .filter(Boolean);
    const toggle = (option: string) => {
      const lower = option.toLowerCase();
      const set = new Set(selected);
      if (set.has(lower)) {
        if (set.size <= 1) return; // keep at least one selected
        set.delete(lower);
      } else {
        set.add(lower);
      }
      const next = options
        .map((o) => o.toLowerCase())
        .filter((o) => set.has(o));
      // All selected == default → persist as empty (unset).
      onChange(next.length === options.length ? "" : next.join(","));
    };
    return (
      <div className="flex flex-wrap gap-2 rounded-md border border-border bg-muted/30 p-1">
        {options.map((option) => (
          <Button
            key={option}
            type="button"
            size="sm"
            variant={selected.includes(option.toLowerCase()) ? "default" : "ghost"}
            onClick={() => toggle(option)}
            className="font-mono uppercase"
          >
            {option}
          </Button>
        ))}
      </div>
    );
  }

  return (
    <Input
      type={variable.inputType === "number" ? "number" : "text"}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={variable.placeholder || variable.defaultValue || ""}
      className="font-mono"
    />
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-3">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 font-mono text-sm text-foreground">{value}</div>
    </div>
  );
}

function envValue(data: EnvironmentSettings | undefined, key: string) {
  return data?.variables.find((variable) => variable.key === key)?.value ?? "";
}

function filterEnvironment(
  data: EnvironmentSettings | undefined,
  filter: string,
) {
  const needle = filter.trim().toLowerCase();
  const variables = data?.variables ?? [];
  const filtered = needle
    ? variables.filter((variable) =>
        [
          variable.key,
          variable.label,
          variable.category,
          variable.description,
        ]
          .join(" ")
          .toLowerCase()
          .includes(needle),
      )
    : variables;
  return groupBy(filtered, (variable) => variable.category);
}

function groupBy<T, K extends string>(items: T[], getKey: (item: T) => K) {
  return items.reduce<Record<string, T[]>>((acc, item) => {
    const key = getKey(item);
    (acc[key] ||= []).push(item);
    return acc;
  }, {});
}

function isMaskedSettingValue(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.startsWith("****") || trimmed.includes("••••");
}

function prettyAuthMethod(method: string): string {
  switch (method) {
    case "api_key":
      return "API key";
    case "oauth":
      return "OAuth";
    case "none":
      return "No credentials";
    default:
      return method;
  }
}

function maskedAPIKeyLabel(profile: AuthProfile): string {
  if (profile.apiKey) return profile.apiKey;
  return "(no key)";
}

function maskedTokenLabel(profile: AuthProfile): string {
  if (profile.accessToken) return profile.accessToken;
  return "(no token)";
}

// Backup & migration: export the full configuration (environment variables,
// LLM auth profiles, provider keys — secrets in cleartext, operator-session
// only) to a JSON file, or merge a previous backup into this install.
// Import never destroys anything absent from the file.
function BackupMigrationCard({
  onRestartRequired,
}: {
  onRestartRequired: (required: boolean) => void;
}) {
  const { t } = useI18n();
  const importSettings = useImportSettings();
  const fileRef = useRef<HTMLInputElement>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onExport() {
    setError(null);
    setSummary(null);
    try {
      const blob = await api.exportSettings();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "xalgorix-settings-backup.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    }
  }

  async function onImportFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    setError(null);
    setSummary(null);
    if (!file) return;
    try {
      const backup = JSON.parse(await file.text()) as SettingsBackup;
      const counts = [
        `${Object.keys(backup.env ?? {}).length} env vars`,
        `${backup.profiles?.length ?? 0} profiles`,
        `${backup.llm_keys?.length ?? 0} provider keys`,
      ].join(", ");
      if (!window.confirm(`${t("settings.backup.confirm")}\n${counts}`)) return;
      const res: SettingsImportResult = await importSettings.mutateAsync(backup);
      const bits = [
        `${res.env_applied} env vars`,
        `${res.profiles_applied} profiles`,
        `${res.llm_keys_applied} provider keys`,
      ];
      if (res.env_skipped?.length) bits.push(`skipped: ${res.env_skipped.join(", ")}`);
      if (res.profile_warnings?.length) bits.push(`profile issues: ${res.profile_warnings.join("; ")}`);
      if (res.llm_key_warnings?.length) bits.push(`key issues: ${res.llm_key_warnings.join("; ")}`);
      if (res.general_warnings?.length) bits.push(res.general_warnings.join("; "));
      if (res.restart_required) {
        bits.push("restart required for some changes");
        onRestartRequired(true);
      }
      setSummary(bits.join(" | "));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("settings.backup.title")}</CardTitle>
        <CardDescription>{t("settings.backup.desc")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2 sm:flex-row sm:items-center sm:flex-wrap">
        <Button variant="outline" size="sm" onClick={onExport}>
          {t("settings.backup.export")}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => fileRef.current?.click()}
          disabled={importSettings.isPending}
        >
          {importSettings.isPending ? "Importing..." : t("settings.backup.import")}
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          className="hidden"
          onChange={onImportFile}
        />
        {summary && (
          <span className="text-xs text-success" role="status">
            {summary}
          </span>
        )}
        {error && (
          <span className="text-xs text-destructive" role="alert">
            {error}
          </span>
        )}
      </CardContent>
    </Card>
  );
}
