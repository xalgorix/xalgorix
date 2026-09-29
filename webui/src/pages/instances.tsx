import { useEffect, useState, type ReactNode } from "react"
import { useI18n } from "@/i18n"
import { Link } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { EmptyState, ErrorState } from "@/components/states"
import {
  useInstancesPage,
  useStopInstance,
  usePauseInstance,
  useResumeInstance,
  useStartSavedInstance,
  useRestartInstance,
  useDeleteScan,
} from "@/api/queries"
import { ScanStatusPill } from "@/components/scan-status-pill"
import { PhaseProgress } from "@/components/phase-progress"
import { Pagination, DEFAULT_PAGE_SIZE } from "@/components/Pagination"
import { useDebounced } from "@/lib/use-debounced"
import { timeAgo, formatDuration, shortId } from "@/lib/utils"
import type { InstancesResponse, ScanInstance } from "@/types/api"
import {
  Cpu,
  MemoryStick,
  HardDrive,
  Play,
  Pause,
  Square,
  RotateCw,
  Layers,
  Coins,
  ShieldAlert,
  ExternalLink,
  Search,
  Trash2,
} from "lucide-react"

export default function InstancesPage() {
  const { t } = useI18n()
  const [q, setQ] = useState("")
  const [status, setStatus] = useState<string>("all")
  const [mode, setMode] = useState<string>("all")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE)
  const debouncedQ = useDebounced(q, 300)

  // Reset to the first page whenever the filters change.
  useEffect(() => {
    setPage(1)
  }, [debouncedQ, status, mode, pageSize])

  const { data, isLoading, error, refetch } = useInstancesPage({
    page,
    size: pageSize,
    q: debouncedQ,
    status,
    mode,
  })

  // Server returns the current page (already filtered), the total match count,
  // and the full distinct-mode list for the dropdown.
  const instances = data?.instances ?? []
  const total = data?.total ?? 0
  const modeOptions = data?.modes ?? []
  const filtersActive =
    debouncedQ.trim() !== "" || status !== "all" || mode !== "all"
  // Show the filter bar whenever there are matches OR a filter is active (so
  // the user can always relax a filter that returned nothing).
  const showFilterBar = total > 0 || filtersActive

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">{t("instances.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("instances.subtitle")}
        </p>
      </header>

      {error ? (
        <ErrorState
          title={t("instances.loadError")}
          description={error instanceof Error ? error.message : "Unknown error"}
          action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
        />
      ) : isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      ) : (
        <>
          {data?.resources && <ResourcesBar resources={data.resources} />}
          {!showFilterBar ? (
            <EmptyState
              title="No instances"
              description="Start a scan to see it appear here as a running instance."
            />
          ) : (
            <>
              <Card>
                <CardContent className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center">
                  <div className="relative flex-1">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={q}
                      onChange={(e) => setQ(e.target.value)}
                      placeholder="Search name, target or instance id…"
                      className="pl-9"
                    />
                  </div>
                  <Select value={status} onValueChange={setStatus}>
                    <SelectTrigger className="w-full sm:w-44">
                      <SelectValue placeholder={t("instances.allStatuses")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">{t("instances.allStatuses")}</SelectItem>
                      <SelectItem value="running">{t("status.running")}</SelectItem>
                      <SelectItem value="paused">{t("status.paused")}</SelectItem>
                      <SelectItem value="saved">{t("status.saved")}</SelectItem>
                      <SelectItem value="finished">{t("status.finished")}</SelectItem>
                      <SelectItem value="stopped">{t("status.stopped")}</SelectItem>
                      <SelectItem value="failed">{t("status.failed")}</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={mode} onValueChange={setMode}>
                    <SelectTrigger className="w-full sm:w-44">
                      <SelectValue placeholder={t("instances.allModes")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">{t("instances.allModes")}</SelectItem>
                      {modeOptions.map((m) => (
                        <SelectItem key={m} value={m}>
                          {m}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </CardContent>
              </Card>

              {total === 0 ? (
                <EmptyState
                  title={t("instances.emptyTitle")}
                  description={t("instances.emptyDescription")}
                />
              ) : (
                <>
                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {instances.map((inst) => (
                      <InstanceCard key={inst.id} instance={inst} />
                    ))}
                  </div>
                  <Card>
                    <Pagination
                      totalItems={total}
                      page={page}
                      pageSize={pageSize}
                      onPageChange={setPage}
                      onPageSizeChange={setPageSize}
                      className="border-t-0"
                    />
                  </Card>
                </>
              )}
            </>
          )}
        </>
      )}
    </div>
  )
}

function ResourcesBar({ resources }: { resources: InstancesResponse["resources"] }) {
  const cpu = Math.min(100, Math.round((resources.cpu_load_1m / Math.max(1, resources.cpu_cores)) * 100))
  const ramTotal = resources.ram_total_mb || 1
  const ramUsed = ramTotal - resources.ram_available_mb
  const ramPct = Math.min(100, Math.max(0, Math.round((ramUsed / ramTotal) * 100)))
  const diskFreeGb = (resources.disk_free_mb / 1024).toFixed(1)
  const heavyActive = resources.active_heavy_tool_leases ?? 0
  const heavySlots = resources.heavy_tool_slots ?? 0
  const toolMem = resources.tool_mem_limit_mb ?? 0
  const scanMem = resources.scan_memory_budget_mb ?? 0
  const runningInstances = resources.running_instances ?? 0
  const availableSlots = resources.available_instance_slots ?? Math.max(0, resources.effective_max_instances - runningInstances)
  const toolLimitText = toolMem > 0 ? ` · tool cap ${toolMem}MB` : " · tool cap off"
  const rss = resources.process_rss_mb ?? 0
  const heap = resources.go_heap_alloc_mb ?? 0
  const level = (resources.level || "").toLowerCase()
  const levelColor =
    level === "critical"
      ? "bg-red-500/10 border-red-500/30 text-red-700 dark:text-red-300"
      : level === "caution" || level === "warning" || level === "warn"
        ? "bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-300"
        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300"

  return (
    <Card>
      <CardContent className="grid gap-3 p-4 md:grid-cols-4">
        <ResourceStat
          icon={<Cpu className="h-3 w-3" />}
          label="HOST CPU LOAD"
          value={`${cpu}%`}
          sub={`${resources.cpu_load_1m.toFixed(2)} / ${resources.cpu_cores} cores · heavy ${heavyActive}/${heavySlots}`}
        />
        <ResourceStat
          icon={<MemoryStick className="h-3 w-3" />}
          label="HOST MEMORY"
          value={`${ramPct}%`}
          sub={(() => {
            const used = `${Math.round(ramUsed)}MB used${rss > 0 ? ` · xalgorix ${rss}MB RSS` : ""}`
            const capacity = `Capacity ${resources.effective_max_instances} · ${runningInstances} running · ${availableSlots} available`
            const cap = scanMem > 0
              ? `${capacity} · scan ${scanMem}MB${toolLimitText}`
              : capacity
            return `${used} · ${cap}`
          })()}
        />
        <ResourceStat
          icon={<HardDrive className="h-3 w-3" />}
          label="DISK FREE"
          value={`${diskFreeGb}GB`}
          sub="Used for scan logs, tool output, reports"
        />
        <div className={`rounded-md border px-3 py-2 text-xs ${levelColor}`}>
          <div className="uppercase tracking-wide opacity-70">Host resource level</div>
          <div className="mt-0.5 font-medium capitalize">{resources.level || "ok"}</div>
          {shouldShowResourceReason(resources) && (
            <div className="mt-0.5 opacity-70 line-clamp-2">{heap > 0 ? `Go heap ${heap}MB. ` : ""}{resources.reason}</div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function shouldShowResourceReason(resources?: { level?: string; reason?: string }): boolean {
  const reason = resources?.reason?.trim()
  if (!reason) return false
  const level = (resources?.level || "").trim().toLowerCase()
  return level !== "ok" && !reason.toLowerCase().startsWith("ok")
}

function ResourceStat({
  icon,
  label,
  value,
  sub,
}: {
  icon: ReactNode
  label: string
  value: string
  sub?: string
}) {
  return (
    <div className="rounded-md border border-border bg-muted/30 px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mono mt-0.5 text-xl text-foreground">{value}</div>
      {sub && <div className="text-[11px] text-muted-foreground mono">{sub}</div>}
    </div>
  )
}

function InstanceCard({ instance }: { instance: ScanInstance }) {
  const stop = useStopInstance()
  const pause = usePauseInstance()
  const resume = useResumeInstance()
  const start = useStartSavedInstance()
  const restart = useRestartInstance()
  const del = useDeleteScan()
  const status = (instance.status || "").toLowerCase()
  const canPause = status === "running"
  const canResume = status === "paused"
  const canStop = status === "running" || status === "pending" || status === "paused"
  const canStart = status === "saved" || status === "stopped" || status === "failed" || status === "finished"
  const isActive = status === "running" || status === "pending" || status === "paused"

  function handleDelete() {
    const label = isActive
      ? "This instance is still active. Deleting it will stop the scan and permanently remove the instance and its saved data. Continue?"
      : "Permanently delete this instance and its saved data?"
    if (!window.confirm(label)) return
    del.mutate(instance.id)
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3 overflow-hidden">
          <div className="min-w-0 flex-1">
            <CardTitle className="truncate mono text-sm">
              {instance.name || instance.targets || shortId(instance.id)}
            </CardTitle>
            <CardDescription className="mono text-xs truncate">
              {shortId(instance.id, 12)}
              {instance.scan_mode && <> · {instance.scan_mode}</>}
            </CardDescription>
          </div>
          <ScanStatusPill status={instance.status} className="shrink-0" />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-3 gap-2">
          <Stat
            icon={<ShieldAlert className="h-3 w-3" />}
            label="VULNS"
            value={String(instance.vuln_count ?? 0)}
          />
          <Stat
            icon={<Layers className="h-3 w-3" />}
            label="ITERS"
            value={String(instance.iterations ?? 0)}
          />
          <Stat
            icon={<Coins className="h-3 w-3" />}
            label="TOKENS"
            value={
              instance.total_tokens
                ? compactNumber(instance.total_tokens)
                : "0"
            }
          />
        </div>
        <PhaseProgress
          current={instance.current_phase}
          selected={instance.phases}
          status={instance.status}
          phaseStatus={instance.phase_status}
          worked={instance.phases_worked}
        />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2 text-xs text-muted-foreground">
          <div>
            <div>Started {timeAgo(instance.started_at)}</div>
            <div className="mono">
              {formatDuration(instance.started_at, instance.finished_at)}
            </div>
          </div>
          <Button asChild size="sm" variant="ghost" className="h-7">
            <Link to={`/scans/${instance.id}`}>
              Open <ExternalLink className="ml-1 h-3 w-3" />
            </Link>
          </Button>
        </div>
        <div className="flex flex-wrap gap-2 pt-1">
          {canStart && (
            <Button
              size="sm"
              variant="outline"
              disabled={start.isPending}
              onClick={() => start.mutate(instance.id)}
            >
              <Play className="mr-1 h-3.5 w-3.5" /> Start
            </Button>
          )}
          {canPause && (
            <Button
              size="sm"
              variant="outline"
              disabled={pause.isPending}
              onClick={() => pause.mutate(instance.id)}
            >
              <Pause className="mr-1 h-3.5 w-3.5" /> Pause
            </Button>
          )}
          {canResume && (
            <Button
              size="sm"
              variant="outline"
              disabled={resume.isPending}
              onClick={() => resume.mutate(instance.id)}
            >
              <Play className="mr-1 h-3.5 w-3.5" /> Resume
            </Button>
          )}
          {canStop && (
            <Button
              size="sm"
              variant="outline"
              disabled={stop.isPending}
              onClick={() => stop.mutate(instance.id)}
            >
              <Square className="mr-1 h-3.5 w-3.5" /> Stop
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            disabled={restart.isPending}
            onClick={() => restart.mutate(instance.id)}
          >
            <RotateCw className="mr-1 h-3.5 w-3.5" /> Restart
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
            disabled={del.isPending}
            onClick={handleDelete}
          >
            <Trash2 className="mr-1 h-3.5 w-3.5" /> Delete
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function Stat({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mono text-base text-foreground">{value}</div>
    </div>
  )
}

function compactNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}
