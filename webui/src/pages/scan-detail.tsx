import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useI18n } from "@/i18n";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { SeverityBadge } from "@/components/severity-badge";
import { Markdown } from "@/components/markdown";
import { VerificationBadge } from "@/components/verification-badge";
import {
  PhaseProgress,
  PHASES,
  phaseVisual,
  PHASE_STATUS_LABEL,
} from "@/components/phase-progress";
import { CopyButton } from "@/components/copy-button";
import { TokenUsageTab } from "@/components/token-usage";
import { ErrorState, EmptyState } from "@/components/states";
import {
  useScan,
  useStopInstance,
  usePauseInstance,
  useResumeInstance,
  useStartSavedInstance,
  useDeleteScan,
  useDeleteVuln,
} from "@/api/queries";
import { api } from "@/api/client";
import {
  filterEventsForInstance,
  mergeFeedEvents,
  toFeedEvent,
  useWSStore,
  type FeedEvent,
} from "@/store/ws";
import {
  timeAgo,
  formatTime,
  formatDuration,
  severityRank,
  normalizeSeverity,
  cn,
  menuContentClass,
  menuItemClass,
} from "@/lib/utils";
import {
  ChevronLeft,
  Download,
  ExternalLink,
  MoreHorizontal,
  X,
  Play,
  Pause,
  Trash2,
  ShieldAlert,
  Terminal,
  Sparkles,
  ListChecks,
  ArrowRight,
  Loader2,
  Send,
  Activity,
} from "lucide-react";
import { LiveFeed, type FeedFilter } from "@/components/live-feed";
import { Pagination, DEFAULT_PAGE_SIZE } from "@/components/Pagination";
import type { SubScanSummary, VulnSummary, WSEvent } from "@/types/api";

export default function ScanDetailPage() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const { scanId } = useParams<{ scanId: string }>();
  const id = scanId ?? "";
  const { data: scan, isLoading, isFetching, error, refetch } = useScan(id);
  const stop = useStopInstance();
  const pause = usePauseInstance();
  const resume = useResumeInstance();
  const start = useStartSavedInstance();
  const del = useDeleteScan();
  const subscribe = useWSStore((s) => s.subscribe);
  const unsubscribe = useWSStore((s) => s.unsubscribe);
  const liveEvents = useWSStore((s) => s.events);
  const subscriptionId = scan?.instance_id || scan?.id || id;

  // Lazy-paged older events. The detail response only carries a tail of the
  // event log (scan.events_truncated); these are the earlier events fetched on
  // demand via api.scanEvents, held in ascending order starting at
  // `earliestLoaded`.
  const [olderEvents, setOlderEvents] = useState<WSEvent[]>([]);
  const [earliestLoaded, setEarliestLoaded] = useState<number | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);

  useEffect(() => {
    if (!subscriptionId) return;
    subscribe(subscriptionId);
    return () => unsubscribe();
  }, [subscriptionId, subscribe, unsubscribe]);

  // Reset paged events whenever we navigate to a different scan.
  useEffect(() => {
    setOlderEvents([]);
    setEarliestLoaded(null);
    setLoadingOlder(false);
  }, [id]);

  const loadEarlierEvents = useCallback(async () => {
    if (!scan) return;
    const inlineCount = (scan.events ?? []).length;
    const total = scan.events_total ?? inlineCount;
    const tailStart = Math.max(0, total - inlineCount);
    const base = earliestLoaded ?? tailStart;
    if (base <= 0 || loadingOlder) return;
    const pageSize = 300;
    const offset = Math.max(0, base - pageSize);
    const limit = base - offset;
    setLoadingOlder(true);
    try {
      const page = await api.scanEvents(scan.id, offset, limit);
      setOlderEvents((prev) => [...(page.events ?? []), ...prev]);
      setEarliestLoaded(offset);
    } catch {
      /* surfaced via the disabled state resetting; user can retry */
    } finally {
      setLoadingOlder(false);
    }
  }, [scan, earliestLoaded, loadingOlder]);

  if (error)
    return (
      <ErrorState
        title="Could not load scan"
        description={error instanceof Error ? error.message : "Unknown error"}
        action={
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            Retry
          </Button>
        }
      />
    );
  if (isLoading) return <ScanDetailSkeleton />;
  if (!scan)
    return (
      <ErrorState
        title="Scan details are starting"
        description={
          isFetching
            ? "Waiting for the running scan record to become available."
            : "The scan route is open, but the backend has not returned the scan record yet."
        }
        action={
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            Retry
          </Button>
        }
      />
    );

  const status = (scan.status || "").toLowerCase();
  const canPause = status === "running";
  const canResume = status === "paused";
  const canStop =
    status === "running" || status === "pending" || status === "paused";
  const canStart =
    status === "saved" ||
    status === "stopped" ||
    status === "failed" ||
    status === "finished";

  // Combine persisted events from the scan record with the live websocket
  // feed for this instance, deduped by content. `olderEvents` are the
  // lazily-paged earlier events; concatenated with the inline tail they form a
  // contiguous run whose first global index is `effectiveEarliest`.
  const eventInstanceId = scan.instance_id || scan.id || id;
  const wsForScan = filterEventsForInstance(liveEvents, eventInstanceId);
  const inlineEvents = scan.events ?? [];
  const eventsTotal = scan.events_total ?? inlineEvents.length;
  const tailStart = Math.max(0, eventsTotal - inlineEvents.length);
  const effectiveEarliest = earliestLoaded ?? tailStart;
  const persistedCombined = [...olderEvents, ...inlineEvents];
  const persistedAsFeed: FeedEvent[] = persistedCombined.map((e, i) =>
    toFeedEvent(e, `scan:${eventInstanceId}`, effectiveEarliest + i),
  );
  const mergedEvents = mergeFeedEvents(persistedAsFeed, wsForScan);

  // Older-event paging is only offered for terminal scans: a live scan's tail
  // updates every poll and streams via WS, so mixing in backward paging would
  // race. `remainingOlder` drives the "Load earlier" affordance.
  const isLiveScan =
    status === "running" || status === "pending" || status === "paused";
  const canLoadEarlier =
    !isLiveScan && !!scan.events_truncated && effectiveEarliest > 0;
  const remainingOlder = effectiveEarliest;

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/scans"
          className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="mr-1 h-3 w-3" />
          All scans
        </Link>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2 min-w-0 flex-1">
          <div className="flex items-center gap-3 min-w-0">
            <h1 className="font-mono text-xl sm:text-2xl font-semibold tracking-tight text-foreground truncate min-w-0">
              {scan.target}
            </h1>
            <CopyButton value={scan.target} />
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span className="mono truncate max-w-full">{scan.id}</span>
            <span className="hidden sm:inline">·</span>
            <span>Started {timeAgo(scan.started_at)}</span>
            <span className="hidden sm:inline">·</span>
            <span>
              Duration {formatDuration(scan.started_at, scan.finished_at)}
            </span>
            {scan.scan_mode && (
              <>
                <span className="hidden sm:inline">·</span>
                <Badge variant="outline" className="font-normal capitalize">
                  {scan.scan_mode}
                </Badge>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <ScanStatusPill status={scan.status} />
          <Button variant="outline" size="sm" asChild>
            <a href={api.reportUrl(scan.id)} target="_blank" rel="noreferrer">
              <Download className="mr-1 h-4 w-4" /> Report
            </a>
          </Button>
          {canStart && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                // Instance-action endpoints key off the instance id, which for
                // wildcard scans differs from the scan record id (scan.id).
                start.mutate(scan.instance_id || scan.id, {
                  onSuccess: (res) => {
                    if (res.instance_id) {
                      navigate(`/scans/${res.instance_id}`);
                    } else {
                      void refetch();
                    }
                  },
                })
              }
              disabled={start.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> Start
            </Button>
          )}
          {canPause && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => pause.mutate(scan.instance_id || scan.id)}
              disabled={pause.isPending}
            >
              <Pause className="mr-1 h-4 w-4" /> Pause
            </Button>
          )}
          {canResume && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => resume.mutate(scan.instance_id || scan.id)}
              disabled={resume.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> Resume
            </Button>
          )}
          {canStop && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => stop.mutate(scan.instance_id || scan.id)}
              disabled={stop.isPending}
            >
              <X className="mr-1 h-4 w-4" /> Stop
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (
                window.confirm(
                  "Permanently delete this scan and all its events?",
                )
              ) {
                del.mutate(scan.id, {
                  onSuccess: () => {
                    navigate("/scans", { replace: true });
                  },
                });
              }
            }}
            disabled={del.isPending}
          >
            <Trash2 className="mr-1 h-4 w-4" /> Delete
          </Button>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">{t("scanDetail.phaseProgress")}</CardTitle>
            <CardDescription>
              Xalgorix runs a {PHASES.length}-phase autonomous methodology.
              Currently:{" "}
              <span className="text-foreground">
                {currentPhaseLabel(scan.current_phase)}
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <PhaseProgress
              current={scan.current_phase}
              selected={scan.phases}
              status={scan.status}
              phaseStatus={scan.phase_status}
              worked={scan.phases_worked}
            />
            {/* Responsive phase-tile grid. Cells use a min-width
                template so 22 short tiles flow into rows that fit the
                viewport instead of cramming 5 wide cells into 800 px
                of card space. */}
            <div className="grid grid-cols-[repeat(auto-fill,minmax(140px,1fr))] gap-2">
              {PHASES.map((p) => {
                const visual = phaseVisual(p.id, {
                  current: scan.current_phase,
                  isRunning: scan.status === "running",
                  phaseStatus: scan.phase_status,
                  worked: scan.phases_worked,
                });
                return (
                  <div
                    key={p.id}
                    title={`${p.id}. ${p.name} — ${PHASE_STATUS_LABEL[visual.status]}`}
                    className={cn(
                      "flex items-baseline gap-1.5 rounded-md border border-border bg-muted/20 px-2 py-1.5 text-[11px]",
                      visual.status === "active" &&
                        "border-amber-400/50 text-amber-700 dark:text-amber-300",
                      visual.status === "completed" &&
                        "border-emerald-500/40 text-emerald-700 dark:text-emerald-300",
                      visual.status === "blocked" &&
                        "border-rose-500/40 text-rose-700 dark:text-rose-300",
                      visual.status === "not_applicable" &&
                        "border-sky-500/30 text-sky-700/80 dark:text-sky-300/70",
                    )}
                  >
                    <span className="mono shrink-0 text-muted-foreground">
                      {p.id}
                    </span>
                    <span className="truncate" title={p.name}>
                      {p.name}
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">{t("scanDetail.riskOverview")}</CardTitle>
            <CardDescription>
              {(scan.vulns ?? []).length} findings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <RiskBreakdown vulns={scan.vulns ?? []} />
          </CardContent>
        </Card>

        {!!scan.sub_scan_total && (
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-sm">{t("scanDetail.wildcardCoverage")}</CardTitle>
              <CardDescription>
                {scan.sub_scan_completed ?? 0} scanned ·{" "}
                {scan.sub_scan_running ?? 0} running ·{" "}
                {scan.sub_scan_remaining ?? 0} remaining
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SubdomainProgress
                completed={scan.sub_scan_completed ?? 0}
                running={scan.sub_scan_running ?? 0}
                remaining={scan.sub_scan_remaining ?? 0}
                total={scan.sub_scan_total ?? 0}
              />
            </CardContent>
          </Card>
        )}
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            {t("scanDetail.tab.findings")}
          </TabsTrigger>
          <TabsTrigger value="events">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            {t("scanDetail.tab.events")}
          </TabsTrigger>
          <TabsTrigger value="tokens">
            <Activity className="mr-1.5 h-3.5 w-3.5" />
            {t("scanDetail.tab.tokens")}
          </TabsTrigger>
          {!!scan.sub_scan_total && (
            <TabsTrigger value="subdomains">
              <ListChecks className="mr-1.5 h-3.5 w-3.5" />
              {t("scanDetail.tab.subdomains")}
            </TabsTrigger>
          )}
          <TabsTrigger value="config">
            <ListChecks className="mr-1.5 h-3.5 w-3.5" />
            {t("scanDetail.tab.config")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-2">
          <FindingsTab vulns={scan.vulns ?? []} scanId={scan.id} />
        </TabsContent>
        <TabsContent value="events">
          <EventsTab
            events={mergedEvents}
            scanId={scan.id}
            instanceId={eventInstanceId}
            status={status}
            target={scan.target}
            canLoadEarlier={canLoadEarlier}
            remainingOlder={remainingOlder}
            loadingOlder={loadingOlder}
            onLoadEarlier={loadEarlierEvents}
          />
        </TabsContent>
        <TabsContent value="tokens">
          <TokenUsageTab scanId={scan.id} running={status === "running" || status === "paused"} />
        </TabsContent>
        {!!scan.sub_scan_total && (
          <TabsContent value="subdomains">
            <SubdomainsTab subScans={scan.sub_scans ?? []} />
          </TabsContent>
        )}
        <TabsContent value="config">
          <ConfigTab scan={scan} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function currentPhaseLabel(p?: number): string {
  if (!p) return "—";
  const found = PHASES.find((x) => x.id === p);
  return found ? `${p}. ${found.name}` : `Phase ${p}`;
}

function SubdomainProgress({
  completed,
  running,
  remaining,
  total,
}: {
  completed: number;
  running: number;
  remaining: number;
  total: number;
}) {
  const denominator = Math.max(total, 1);
  const completedPct = (completed / denominator) * 100;
  const runningPct = (running / denominator) * 100;
  const remainingPct = Math.max(0, 100 - completedPct - runningPct);
  return (
    <div className="space-y-3">
      <div className="flex h-2 overflow-hidden rounded-sm bg-muted">
        <div className="bg-success" style={{ width: `${completedPct}%` }} />
        <div className="bg-warning" style={{ width: `${runningPct}%` }} />
        <div
          className="bg-muted-foreground/25"
          style={{ width: `${remainingPct}%` }}
        />
      </div>
      <div className="grid gap-2 text-xs sm:grid-cols-4">
        <ProgressStat label="Total" value={total} />
        <ProgressStat label="Scanned" value={completed} />
        <ProgressStat label="Running" value={running} />
        <ProgressStat label="Remaining" value={remaining} />
      </div>
    </div>
  );
}

function ProgressStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mono mt-1 text-lg text-foreground">{value}</div>
    </div>
  );
}

function RiskBreakdown({ vulns }: { vulns: VulnSummary[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const v of vulns) {
      c[normalizeSeverity(v.severity)] += 1;
    }
    return c;
  }, [vulns]);
  const total = vulns.length || 1;
  const order: Array<keyof typeof counts> = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];
  return (
    <div className="space-y-3">
      <div className="flex h-12 items-end gap-1">
        {order.map((sev) => {
          const n = counts[sev as string];
          if (!n) return null;
          const pct = Math.max(4, Math.round((n / total) * 100));
          return (
            <div
              key={sev}
              className={cn(
                "h-full rounded-sm",
                sev === "critical" && "bg-red-500/70",
                sev === "high" && "bg-orange-500/70",
                sev === "medium" && "bg-amber-400/70",
                sev === "low" && "bg-blue-400/70",
                sev === "info" && "bg-neutral-500/60",
              )}
              style={{ width: `${pct}%` }}
              title={`${sev}: ${n}`}
            />
          );
        })}
        {vulns.length === 0 && (
          <div className="h-full w-full rounded-sm border border-dashed border-border" />
        )}
      </div>
      {/* Severity legend. Horizontal-scroll on very narrow widths so the
          five labels never overlap; wide enough to read at all sizes. */}
      <div className="-mx-1 flex gap-1.5 overflow-x-auto px-1 pb-1 text-[11px]">
        {order.map((sev) => (
          <div
            key={sev}
            className="flex min-w-[60px] flex-1 flex-col rounded-md border border-border bg-muted/20 px-2 py-1.5"
          >
            <span className="truncate uppercase tracking-wide text-muted-foreground">
              {sev}
            </span>
            <span className="mono text-base leading-tight text-foreground">
              {counts[sev as string]}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SubdomainsTab({ subScans }: { subScans: SubScanSummary[] }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);

  const total = subScans.length;
  // Clamp the current page when the list shrinks/grows (it grows live during a
  // wildcard scan) so we never strand the user on an empty page.
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  const safePage = Math.min(Math.max(1, page), totalPages);
  useEffect(() => {
    if (safePage !== page) setPage(safePage);
  }, [safePage, page]);

  const paged = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return subScans.slice(start, start + pageSize);
  }, [subScans, safePage, pageSize]);

  if (subScans.length === 0) {
    return (
      <EmptyState
        title="No subdomains recorded yet"
        description="Discovered subdomains will appear here as the wildcard scan progresses."
      />
    );
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <Th>Subdomain</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Tokens</Th>
                <Th>Started</Th>
              </tr>
            </thead>
            <tbody>
              {paged.map((sub) => (
                <tr
                  key={sub.id || sub.target}
                  className="border-b border-border/60 last:border-0"
                >
                  <Td>
                    <div className="mono text-sm text-foreground">
                      {sub.target}
                    </div>
                    <div className="mono text-xs text-muted-foreground">
                      {sub.id}
                    </div>
                  </Td>
                  <Td>
                    <ScanStatusPill status={sub.status} />
                  </Td>
                  <Td className="mono text-xs">{sub.vuln_count ?? 0}</Td>
                  <Td className="mono text-xs text-muted-foreground">
                    {sub.total_tokens ? sub.total_tokens.toLocaleString() : "—"}
                  </Td>
                  <Td className="text-muted-foreground">
                    {sub.started_at ? timeAgo(sub.started_at) : "—"}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pagination
          totalItems={total}
          page={safePage}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </CardContent>
    </Card>
  );
}

function Th({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <th className={cn("px-4 py-3 text-left font-medium", className)}>
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <td className={cn("px-4 py-3 align-middle", className)}>{children}</td>
  );
}

function findingKey(scanId: string, finding: VulnSummary): string {
  // source_scan_id disambiguates IDs reused by wildcard child scans. The
  // displayed scan is the safe fallback for responses from older records.
  return JSON.stringify([finding.source_scan_id || scanId, finding.id]);
}

function findingSourceScanId(scanId: string, finding: VulnSummary): string {
  return finding.source_scan_id || scanId;
}

function FindingsTab({
  vulns,
  scanId,
}: {
  vulns: VulnSummary[];
  scanId: string;
}) {
  const del = useDeleteVuln();
  const [selected, setSelected] = useState<VulnSummary | null>(null);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(() => new Set());
  const sorted = useMemo(
    () =>
      [...vulns].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity),
      ),
    [vulns],
  );
  const findingsByKey = useMemo(
    () => new Map(sorted.map((finding) => [findingKey(scanId, finding), finding])),
    [scanId, sorted],
  );

  const allSelected = sorted.length > 0 && selectedKeys.size === sorted.length;

  useEffect(() => {
    const allKeys = new Set(sorted.map((finding) => findingKey(scanId, finding)));
    setSelectedKeys((current) => {
      const next = new Set([...current].filter((key) => allKeys.has(key)));
      return next.size === current.size ? current : next;
    });
  }, [scanId, sorted]);

  function toggleSelect(key: string, checked: boolean) {
    setSelectedKeys((current) => {
      const next = new Set(current);
      if (checked) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  function selectAll() {
    setSelectedKeys(new Set(sorted.map((finding) => findingKey(scanId, finding))));
  }
  function clearSelection() {
    setSelectedKeys(new Set());
  }

  async function deleteVulns(keys: string[]) {
    const selectedFindings = keys
      .map((key) => findingsByKey.get(key))
      .filter((finding): finding is VulnSummary => Boolean(finding));
    const unique = new Map<string, { scanId: string; vulnId: string }>();
    for (const finding of selectedFindings) {
      const sourceScanId = findingSourceScanId(scanId, finding);
      unique.set(
        JSON.stringify([sourceScanId, finding.id]),
        { scanId: sourceScanId, vulnId: finding.id },
      );
    }
    if (!unique.size) return;
    const label =
      unique.size === 1
        ? "Permanently delete this finding?"
        : `Permanently delete ${unique.size} selected findings?`;
    if (!window.confirm(label)) return;
    for (const identity of unique.values()) {
      await del.mutateAsync(identity);
    }
    setSelectedKeys((current) => {
      const next = new Set(current);
      for (const key of keys) next.delete(key);
      return next;
    });
  }

  if (sorted.length === 0)
    return (
      <EmptyState
        title="No findings yet"
        description="Vulnerabilities will appear here as the engagement progresses."
      />
    );

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={allSelected ? clearSelection : selectAll}
        >
          {allSelected ? "Clear selection" : "Select all"}
        </Button>
        <span className="text-xs text-muted-foreground">
          {selectedKeys.size} selected
        </span>
        <BulkActionMenu
          disabled={selectedKeys.size === 0 || del.isPending}
          selectedCount={selectedKeys.size}
          onDelete={() => void deleteVulns([...selectedKeys])}
        />
      </div>
      <div className="space-y-2">
        {sorted.map((f) => {
          const key = findingKey(scanId, f);
          return (
            <Card
              key={key}
              id={`finding-${encodeURIComponent(key)}`}
              className={cn(
                "overflow-hidden",
                selectedKeys.has(key) && "ring-1 ring-primary/30",
              )}
            >
              <div className="flex items-start gap-2 p-2 pl-4">
                <input
                  type="checkbox"
                  checked={selectedKeys.has(key)}
                  aria-label={`Select ${f.title}`}
                  onChange={(e) => toggleSelect(key, e.currentTarget.checked)}
                  className="mt-3 h-4 w-4 shrink-0 rounded border-border bg-input accent-primary"
                />
                <button
                  type="button"
                  className="group block w-full flex-1 text-left transition-colors hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded"
                  onClick={() => setSelected(f)}
                  aria-label={`Open finding details for ${f.title}`}
                >
                  <CardContent className="flex flex-col gap-3 p-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0 space-y-1 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <h3 className="font-medium text-foreground">{f.title}</h3>
                        {f.cve && (
                          <Badge variant="outline" className="mono">
                            {f.cve}
                          </Badge>
                        )}
                        {f.cwe_id && (
                          <Badge
                            variant="outline"
                            className="mono text-emerald-600 dark:text-emerald-400 border-emerald-400/30"
                          >
                            {f.cwe_id}
                          </Badge>
                        )}
                        {f.owasp && (
                          <Badge
                            variant="outline"
                            className="mono text-amber-700 dark:text-amber-400 border-amber-400/30"
                          >
                            {f.owasp}
                          </Badge>
                        )}
                        <VerificationBadge verified={f.verified} tags={f.tags} />
                      </div>
                      {f.description && (
                        <p className="text-sm leading-relaxed text-muted-foreground line-clamp-3">
                          {f.description}
                        </p>
                      )}
                      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                        {f.target && <span className="mono">{f.target}</span>}
                        {f.endpoint && <span className="mono">{f.endpoint}</span>}
                        {f.method && <span className="mono">{f.method}</span>}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      {f.cvss != null && f.cvss > 0 && (
                        <Badge variant="outline" className="mono">
                          CVSS {f.cvss.toFixed(1)}
                        </Badge>
                      )}
                      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
                        Details <ArrowRight className="h-3.5 w-3.5" />
                      </span>
                    </div>
                  </CardContent>
                </button>
                <FindingRowMenu
                  finding={f}
                  scanId={scanId}
                  deleting={del.isPending}
                  onDelete={() => void deleteVulns([key])}
                />
              </div>
            </Card>
          );
        })}
      </div>
      <FindingDetailsDialog
        finding={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </>
  );
}

function BulkActionMenu({
  disabled,
  selectedCount,
  onDelete,
}: {
  disabled: boolean;
  selectedCount: number;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button size="sm" variant="secondary" disabled={disabled}>
          Actions
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="start" className={menuContentClass}>
          <DropdownMenu.Label className="px-2 py-1.5 text-xs text-muted-foreground">
            {selectedCount} selected
          </DropdownMenu.Label>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            className={cn(menuItemClass, "text-red-600 focus:text-red-700 dark:text-red-400 dark:focus:text-red-300")}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete selected
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function FindingRowMenu({
  finding,
  scanId,
  deleting,
  onDelete,
}: {
  finding: VulnSummary;
  scanId: string;
  deleting: boolean;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Actions for ${finding.title}`}
          className="mt-1 shrink-0"
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Item asChild className={menuItemClass}>
            <Link to={`/scans/${scanId}`}>
              <ExternalLink className="h-3.5 w-3.5" />
              Open scan
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            disabled={deleting}
            className={cn(
              menuItemClass,
              "text-red-600 focus:text-red-700 dark:text-red-400 dark:focus:text-red-300 data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
            )}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete finding
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function FindingDetailsDialog({
  finding,
  onOpenChange,
}: {
  finding: VulnSummary | null;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={!!finding} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] w-[calc(100vw-2rem)] min-w-0 max-w-3xl overflow-x-hidden overflow-y-auto">
        {finding && (
          <div className="min-w-0 max-w-full space-y-4">
            <DialogHeader className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 pr-8">
                <SeverityBadge severity={finding.severity} />
                {finding.cve && (
                  <Badge variant="outline" className="mono">
                    {finding.cve}
                  </Badge>
                )}
                {finding.cvss != null && finding.cvss > 0 && (
                  <Badge variant="outline" className="mono">
                    CVSS {finding.cvss.toFixed(1)}
                  </Badge>
                )}
                {finding.cwe_id && (
                  <Badge
                    variant="outline"
                    className="mono text-emerald-600 dark:text-emerald-400 border-emerald-400/30"
                  >
                    {finding.cwe_id}
                  </Badge>
                )}
                {finding.owasp && (
                  <Badge
                    variant="outline"
                    className="mono text-amber-700 dark:text-amber-400 border-amber-400/30"
                  >
                    {finding.owasp}
                  </Badge>
                )}
                <VerificationBadge verified={finding.verified} tags={finding.tags} />
              </div>
              <DialogTitle className="min-w-0 pr-8 text-lg [overflow-wrap:anywhere]">
                {finding.title}
              </DialogTitle>
              <DialogDescription>
                Detailed vulnerability record from this scan.
              </DialogDescription>
            </DialogHeader>

            <div className="grid min-w-0 max-w-full gap-3 rounded-md border border-border bg-muted/20 p-3 text-sm sm:grid-cols-2">
              <DetailRow label="Target" value={finding.target} mono />
              <DetailRow label="Endpoint" value={finding.endpoint} mono />
              <DetailRow label="Method" value={finding.method} mono />
              <DetailRow label="CVSS vector" value={finding.cvss_vector} mono />
              <DetailRow label="CWE" value={finding.cwe_id} mono />
              <DetailRow label="OWASP" value={finding.owasp} mono />
              <DetailRow label="Finding ID" value={finding.id} mono />
              <DetailRow
                label="Verification"
                value={finding.verification_method}
              />
            </div>

            <Separator />

            <div className="min-w-0 max-w-full space-y-4">
              <DetailSection title="Description" value={finding.description} />
              <DetailSection title="Impact" value={finding.impact} />
              <DetailSection
                title="Technical analysis"
                value={finding.technical_analysis}
              />
              <DetailSection
                title="Proof of concept"
                value={finding.poc_description}
              />
              {finding.poc_script && (
                <DetailSection
                  title="PoC script"
                  value={finding.poc_script}
                  code
                />
              )}
              {finding.exploitation_proof && (
                <DetailSection
                  title="Exploitation proof"
                  value={finding.exploitation_proof}
                  code
                />
              )}
              <DetailSection title="Remediation" value={finding.remediation} />
              {finding.fix && (
                <DetailSection title="Suggested fix" value={finding.fix} code />
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          "mt-1 min-w-0 max-w-full text-foreground [overflow-wrap:anywhere]",
          mono && "mono text-xs",
        )}
      >
        {value || "—"}
      </div>
    </div>
  );
}

function DetailSection({
  title,
  value,
  code,
}: {
  title: string;
  value?: string;
  code?: boolean;
}) {
  if (!value) return null;
  return (
    <section className="min-w-0 max-w-full space-y-2">
      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {title}
      </h4>
      {code ? (
        <pre className="max-h-64 min-w-0 max-w-full overflow-auto whitespace-pre-wrap rounded-md border border-border bg-muted p-3 text-xs leading-relaxed text-foreground [overflow-wrap:anywhere]">
          <code>{value}</code>
        </pre>
      ) : (
        <Markdown source={value} />
      )}
    </section>
  );
}

function EventsTab({
  events,
  scanId,
  instanceId,
  status,
  target,
  canLoadEarlier,
  remainingOlder,
  loadingOlder,
  onLoadEarlier,
}: {
  events: FeedEvent[];
  scanId: string;
  instanceId: string;
  status: string;
  target: string;
  canLoadEarlier: boolean;
  remainingOlder: number;
  loadingOlder: boolean;
  onLoadEarlier: () => void;
}) {
  const [filter, setFilter] = useState<FeedFilter>("all");
  return (
    <div className="space-y-3">
      {canLoadEarlier && (
        <div className="flex items-center justify-center">
          <Button
            variant="outline"
            size="sm"
            onClick={onLoadEarlier}
            disabled={loadingOlder}
          >
            {loadingOlder
              ? "Loading earlier events…"
              : `Load earlier events (${remainingOlder.toLocaleString()} older)`}
          </Button>
        </div>
      )}
      <LiveFeed
        events={events}
        filter={filter}
        onFilterChange={setFilter}
        exportFilePrefix={`xalgorix-${target || scanId}-events`}
        exportScope={scanId}
        emptyTitle="No events yet"
        emptyDescription="Once the scan starts producing output it will stream here."
      />
      {status === "running" && (
        <ScanGuidanceComposer instanceId={instanceId} />
      )}
    </div>
  );
}

const GUIDANCE_SUGGESTIONS = [
  "Focus next on authentication and session handling.",
  "Prioritize IDOR and broken access control checks.",
  "Verify the strongest finding with reproducible evidence.",
  "Summarize progress, then continue with the highest-risk gap.",
];

function ScanGuidanceComposer({ instanceId }: { instanceId: string }) {
  const { t } = useI18n();
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [feedback, setFeedback] = useState<{
    kind: "success" | "error";
    text: string;
  } | null>(null);

  const trimmed = message.trim();

  async function sendGuidance() {
    if (!trimmed || sending) return;
    setSending(true);
    setFeedback(null);
    try {
      const result = await api.chat(trimmed, instanceId);
      setMessage("");
      setFeedback({
        kind: "success",
        text: result.response || "Guidance queued for the next agent iteration.",
      });
    } catch (err) {
      setFeedback({
        kind: "error",
        text: err instanceof Error ? err.message : "Could not send guidance.",
      });
    } finally {
      setSending(false);
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">{t("scanDetail.guideScan")}</CardTitle>
        <CardDescription>
          Send a priority or correction to this agent. It will pick it up on
          its next iteration without interrupting the scan.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2" aria-label="Guidance suggestions">
          {GUIDANCE_SUGGESTIONS.map((suggestion) => (
            <Button
              key={suggestion}
              type="button"
              size="sm"
              variant="outline"
              className="h-auto whitespace-normal py-1.5 text-left text-xs"
              onClick={() => {
                setMessage(suggestion);
                setFeedback(null);
              }}
              disabled={sending}
            >
              {suggestion}
            </Button>
          ))}
        </div>
        <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-end">
          <Textarea
            value={message}
            onChange={(event) => {
              setMessage(event.target.value);
              setFeedback(null);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void sendGuidance();
              }
            }}
            placeholder="Example: Re-check the admin API with the second account before moving on."
            aria-label="Message to the running scan agent"
            rows={3}
            maxLength={4000}
            disabled={sending}
          />
          <Button
            type="button"
            onClick={() => void sendGuidance()}
            disabled={!trimmed || sending}
            className="shrink-0 sm:w-auto"
          >
            {sending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
            Send
          </Button>
        </div>
        <div className="flex items-center justify-between gap-3 text-[11px] text-muted-foreground">
          <span
            aria-live="polite"
            className={cn(
              feedback?.kind === "success" && "text-emerald-600 dark:text-emerald-400",
              feedback?.kind === "error" && "text-red-600 dark:text-red-400",
            )}
          >
            {feedback?.text || "Enter to send · Shift+Enter for a new line"}
          </span>
          <span className="mono shrink-0">{message.length}/4000</span>
        </div>
      </CardContent>
    </Card>
  );
}

function ConfigTab({
  scan,
}: {
  scan: NonNullable<ReturnType<typeof useScan>["data"]>;
}) {
  const items: Array<{ k: string; v: ReactNode }> = [
    { k: "Scan mode", v: scan.scan_mode || "—" },
    {
      k: "Recon access",
      v: scan.recon_mode === "passive" ? "passive only" : "active allowed",
    },
    {
      k: "Testing access",
      v: scan.scan_intensity === "passive" ? "passive only" : "active allowed",
    },
    {
      k: "Severity filter",
      v: (scan.severity_filter ?? []).join(", ") || "all",
    },
    { k: "Phases", v: (scan.phases ?? []).join(", ") || "all" },
    { k: "Iterations", v: <span className="mono">{scan.iterations}</span> },
    { k: "Tool calls", v: <span className="mono">{scan.tool_calls}</span> },
    {
      k: "Tokens",
      v: (
        <span className="mono">{scan.total_tokens?.toLocaleString() ?? 0}</span>
      ),
    },
    { k: "Stop reason", v: scan.stop_reason || "—" },
    { k: "Started", v: formatTime(scan.started_at) },
    { k: "Finished", v: scan.finished_at ? formatTime(scan.finished_at) : "—" },
    {
      k: "Discord webhook",
      v:
        scan.discord_webhook_configured || scan.discord_webhook
          ? "configured"
          : "none",
    },
  ];
  return (
    <Card>
      <CardContent className="p-0">
        <dl className="divide-y divide-border/60">
          {items.map((it) => (
            <div
              key={it.k}
              className="grid grid-cols-3 gap-2 px-4 py-3 text-sm"
            >
              <dt className="text-muted-foreground">{it.k}</dt>
              <dd className="col-span-2 text-foreground">{it.v}</dd>
            </div>
          ))}
          {scan.instruction && (
            <div className="grid grid-cols-3 gap-2 px-4 py-3 text-sm">
              <dt className="text-muted-foreground flex items-center gap-1">
                <Sparkles className="h-3 w-3" /> Instruction
              </dt>
              <dd className="col-span-2 whitespace-pre-wrap text-foreground/90">
                {scan.instruction}
              </dd>
            </div>
          )}
        </dl>
      </CardContent>
    </Card>
  );
}

function ScanDetailSkeleton() {
  return (
    <>
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-10 w-2/3" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-40 lg:col-span-2" />
        <Skeleton className="h-40" />
      </div>
      <Skeleton className="h-10 w-72" />
      <Skeleton className="h-96 w-full" />
    </>
  );
}
