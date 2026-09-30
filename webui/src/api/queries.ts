import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { ListParams, ScanRequest, ScanSchedule } from "@/types/api";

export const qk = {
  authStatus: ["auth", "status"] as const,
  status: ["status"] as const,
  version: ["version"] as const,
  scans: ["scans"] as const,
  // Paginated scans share the ["scans"] prefix so existing
  // invalidateQueries({ queryKey: qk.scans }) calls refresh them too.
  scansPage: (params: ListParams) => ["scans", "page", params] as const,
  scan: (id: string) => ["scan", id] as const,
  instances: ["instances"] as const,
  // Paginated instances share the ["instances"] prefix for the same reason.
  instancesPage: (params: ListParams) => ["instances", "page", params] as const,
  instance: (id: string) => ["instance", id] as const,
  instanceEvents: (id: string) => ["instance", id, "events"] as const,
  queue: ["queue"] as const,
  rateLimit: ["settings", "rate-limit"] as const,
  agentMail: ["settings", "agentmail"] as const,
  llmSettings: ["settings", "llm"] as const,
  environmentSettings: ["settings", "environment"] as const,
  schedules: ["schedules"] as const,
  legacyImport: ["legacy-import", "status"] as const,
  // v4.4.22: shared cache keys for the compiled-in catalog and the
  // credential profile list. Mutations on the profile surface
  // invalidate both keys when relevant.
  authProfiles: ["auth", "profiles"] as const,
  providers: ["providers"] as const,
  // Shared between /findings and /overview so the totals widget
  // reads a single cache entry across both pages.
  findingsSummary: ["findings", "summary"] as const,
  // Flattened + deduped findings list, computed server-side in one walk.
  findingsList: ["findings", "list"] as const,
};

export function useAuthStatus() {
  return useQuery({
    queryKey: qk.authStatus,
    queryFn: api.authStatus,
    staleTime: 60_000,
  });
}

export function useStatus() {
  return useQuery({
    queryKey: qk.status,
    queryFn: api.status,
    refetchInterval: 5000,
  });
}

export function useVersion() {
  return useQuery({
    queryKey: qk.version,
    queryFn: api.version,
    staleTime: Infinity,
  });
}

export function useScansList() {
  return useQuery({
    queryKey: qk.scans,
    queryFn: api.listScans,
    refetchInterval: 15000,
  });
}

// Flattened + deduped findings across all scans, served by GET /api/findings
// in a single server-side walk. Replaces the per-scan getScan() fan-out the
// findings page used to do (an N+1 that shipped every scan's full event log
// to the browser just to render the findings table).
export function useFindingsList() {
  return useQuery({
    queryKey: qk.findingsList,
    queryFn: api.listFindings,
    refetchInterval: 15000,
  });
}

// Server-side paginated + filtered scans, used by the /scans page. Keeps the
// previous page's data visible while the next page loads (placeholderData) so
// paging/filtering does not flash an empty table.
export function useScansPage(params: ListParams) {
  return useQuery({
    queryKey: qk.scansPage(params),
    queryFn: () => api.listScansPage(params),
    refetchInterval: 15000,
    placeholderData: (prev) => prev,
  });
}

export function useTokenUsage(id?: string, running?: boolean) {
  return useQuery({
    queryKey: id ? ["scan", id, "token-usage"] : ["scan", "none", "token-usage"],
    queryFn: () => api.scanTokenUsage(id!),
    enabled: !!id,
    // Keep the prompt-tokens chart live while the scan is running.
    refetchInterval: running ? 5000 : false,
    retry: false,
  });
}

export function useScan(id?: string) {
  return useQuery({
    queryKey: id ? qk.scan(id) : ["scan", "none"],
    queryFn: () => api.getScan(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const scan = query.state.data;
      if (!scan) return 2000;
      const status = (scan.status || "").toLowerCase();
      return status === "running" || status === "pending" || status === "paused"
        ? 2000
        : false;
    },
  });
}

export function useInstances() {
  return useQuery({
    queryKey: qk.instances,
    queryFn: api.instances,
    refetchInterval: 8000,
  });
}

// Server-side paginated + filtered instances, used by the /instances page.
export function useInstancesPage(params: ListParams) {
  return useQuery({
    queryKey: qk.instancesPage(params),
    queryFn: () => api.instancesPage(params),
    refetchInterval: 8000,
    placeholderData: (prev) => prev,
  });
}

export function useInstanceEvents(id?: string) {
  return useQuery({
    queryKey: id ? qk.instanceEvents(id) : ["instance", "none", "events"],
    queryFn: () => api.instanceEvents(id!),
    enabled: !!id,
    staleTime: 1000,
    refetchInterval: 5000,
  });
}

export function useQueueStatus() {
  return useQuery({
    queryKey: qk.queue,
    queryFn: api.queueStatus,
    refetchInterval: 10000,
  });
}

export function useRateLimit() {
  return useQuery({
    queryKey: qk.rateLimit,
    queryFn: api.rateLimit,
  });
}

export function useAgentMail() {
  return useQuery({
    queryKey: qk.agentMail,
    queryFn: api.agentMail,
  });
}

export function useLLMSettings() {
  return useQuery({
    queryKey: qk.llmSettings,
    queryFn: api.llmSettings,
  });
}

export function useEnvironmentSettings() {
  return useQuery({
    queryKey: qk.environmentSettings,
    queryFn: api.environmentSettings,
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequest) => api.startScan(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: qk.status });
    },
  });
}

export function useStopAll() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.stopAll(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.status });
    },
  });
}

export function useStopInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.stopInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function usePauseInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.pauseInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useResumeInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.resumeInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useRestartInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.restartInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useStartSavedInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.startSavedInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteScan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.scans });
    },
  });
}

export function useDeleteVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ scanId, vulnId }: { scanId: string; vulnId: string }) =>
      api.deleteVuln(scanId, vulnId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
    onError: (err) => {
      console.error("Failed to delete vulnerability:", err);
    },
  });
}

export function useUpdateRateLimit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateRateLimit,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.rateLimit });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
    },
  });
}

export function useUpdateAgentMail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateAgentMail,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.agentMail });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
    },
  });
}

export function useUpdateLLMSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateLLMSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.llmSettings });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.version });
    },
  });
}

export function useUpdateEnvironmentSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateEnvironmentSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
      qc.invalidateQueries({ queryKey: qk.agentMail });
      qc.invalidateQueries({ queryKey: qk.rateLimit });
      qc.invalidateQueries({ queryKey: qk.version });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

export function useImportSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.importSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.version });
    },
  });
}

export function useQueueResume() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueResume,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

export function useQueueClear() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueClear,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.queue }),
  });
}

export function useSchedulesList() {
  return useQuery({
    queryKey: qk.schedules,
    queryFn: api.listSchedules,
    refetchInterval: 15000,
  });
}

export function useCreateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useUpdateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, schedule }: { id: string; schedule: Partial<ScanSchedule> }) =>
      api.updateSchedule(id, schedule),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useDeleteSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
    },
  });
}

export function useTriggerSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.triggerSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.schedules });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

// Legacy-import banner: fetched once on first load. The server-side count
// is only meaningful on the run that did the import (in-memory only,
// resets on restart). Stale-time Infinity prevents background refetch
// from re-showing a dismissed banner mid-session.
export function useLegacyImportStatus() {
  return useQuery({
    queryKey: qk.legacyImport,
    queryFn: api.legacyImportStatus,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
}

export function useDismissLegacyImport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.dismissLegacyImport,
    onSuccess: (data) => {
      qc.setQueryData(qk.legacyImport, data);
    },
  });
}

// Auth profile picker source. Drives the credentials list on the LLM
// Settings tab and the provider/model selector on /new-scan and
// /schedules. The staleTime keeps switching between pages snappy;
// mutations elsewhere invalidate qk.authProfiles so this stays fresh
// without a polling interval.
export function useAuthProfiles() {
  return useQuery({
    queryKey: qk.authProfiles,
    queryFn: api.listAuthProfiles,
    staleTime: 30_000,
  });
}

// Provider catalog — compiled into the binary in v4.4.22, so the
// list is effectively immutable across a session. Cached forever
// since the only way to change it is a server upgrade.
export function useProviders() {
  return useQuery({
    queryKey: qk.providers,
    queryFn: api.listProviders,
    staleTime: Infinity,
  });
}

export function useDiscoverProviderModels() {
  return useMutation({
    mutationFn: ({ provider, profile }: { provider: string; profile?: string }) =>
      api.discoverProviderModels(provider, profile),
  });
}

// ---------------------------------------------------------------------------
// Auth profile mutation hooks. The catalog is read-only in v4.4.22, so
// there is no provider-create / -update / -delete and no openclaw or
// legacy-migrate mutation. Profile CRUD is the only state-changing
// surface left.
// ---------------------------------------------------------------------------

export function useCreateAPIKeyProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createAPIKeyProfile,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
    },
  });
}

export function useOAuthStart() {
  // No cache invalidation: the start handshake is an out-of-band
  // flow that finalizes via /complete or via the loopback callback,
  // which is what produces the new profile. Components poll
  // useAuthProfiles and watch for the new entry.
  return useMutation({
    mutationFn: api.oauthStart,
  });
}

export function useOAuthComplete() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.oauthComplete,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
    },
  });
}

export function useRefreshAuthProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (key: string) => api.refreshAuthProfile(key),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
    },
  });
}

export function useDeleteAuthProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (key: string) => api.deleteAuthProfile(key),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.authProfiles });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
    },
  });
}
