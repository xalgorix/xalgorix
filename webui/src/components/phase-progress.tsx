import { cn } from "@/lib/utils";
// Canonical 22-phase methodology list, GENERATED from the Go registry
// (internal/methodology) via `go run ./tools/gen-webui-phases`. A Go test
// (internal/methodology TestWebuiPhaseListInSync) fails the build when this
// file drifts from the backend definitions — the phase IDs and names here
// are the same ones used by plan tasks, phase restrictions, scan records,
// reports and the phase-filter instructions.
import methodologyPhases from "@/methodology-phases.json";

// Xalgorix 22-phase methodology. The backend reports `current_phase`,
// `phase_status` (authoritative per-phase disposition) and `phases` as
// 1-based ids into this list, and the New Scan form lets the operator opt
// into any subset.
export const PHASES: { id: number; name: string }[] = methodologyPhases;

// Phase dispositions as reported by the backend `phase_status` map. These
// are DERIVED from engine evidence (completed plan tasks, hypothesis
// dispositions, recon dimensions, terminal lifecycle) — never from LLM
// prose or from "phase number N is past".
export type PhaseStatus =
  | "completed"
  | "active"
  | "pending"
  | "blocked"
  | "not_applicable"
  | "not_selected";

export function isPhaseStatus(value: string | undefined): value is PhaseStatus {
  return (
    value === "completed" ||
    value === "active" ||
    value === "pending" ||
    value === "blocked" ||
    value === "not_applicable" ||
    value === "not_selected"
  );
}

export const PHASE_STATUS_LABEL: Record<PhaseStatus, string> = {
  completed: "Completed",
  active: "Active",
  pending: "Pending",
  blocked: "Blocked",
  not_applicable: "Not applicable",
  not_selected: "Not selected",
};

type PhaseVisual = {
  className: string;
  status: PhaseStatus;
};

// phaseVisual computes the rendering state for one phase tile. When the
// backend provides an authoritative `phase_status` entry it is used
// directly. The legacy fallback (records written before phase_status
// existed) marks a phase completed ONLY when it appears in `phases_worked`
// — the engine's observed-work ledger — never merely because its number is
// below `current`. This is what stops the progress bar from painting every
// phase below the current one green.
export function phaseVisual(
  id: number,
  opts: {
    current?: number;
    isRunning?: boolean;
    phaseStatus?: Record<string, string>;
    worked?: number[];
  },
): PhaseVisual {
  const raw = opts.phaseStatus?.[String(id)];
  if (isPhaseStatus(raw)) {
    switch (raw) {
      case "completed":
        return { className: "bg-emerald-500/70", status: raw };
      case "active":
        return { className: "bg-amber-400 pulse-dot", status: raw };
      case "blocked":
        return { className: "bg-rose-500/60", status: raw };
      case "not_applicable":
        return { className: "bg-sky-500/30", status: raw };
      case "not_selected":
        return { className: "bg-muted/40", status: raw };
      default:
        return { className: "bg-muted", status: raw };
    }
  }
  // Legacy fallback: only WORKED phases count as executed coverage. A
  // phase below the current one that was never worked stays muted.
  if (opts.worked?.includes(id)) {
    return { className: "bg-emerald-500/70", status: "completed" };
  }
  if (opts.isRunning && opts.current === id) {
    return { className: "bg-amber-400 pulse-dot", status: "active" };
  }
  return { className: "bg-muted", status: "pending" };
}

export function PhaseProgress({
  current,
  selected,
  status,
  phaseStatus,
  worked,
  className,
}: {
  current?: number;
  selected?: number[];
  status?: string;
  phaseStatus?: Record<string, string>;
  worked?: number[];
  className?: string;
}) {
  const isRunning = (status || "").toLowerCase() === "running";
  const selectedSet = new Set(
    selected && selected.length ? selected : PHASES.map((p) => p.id),
  );
  return (
    <div
      className={cn("flex items-center gap-1", className)}
      role="progressbar"
      aria-valuemin={1}
      aria-valuemax={PHASES.length}
      aria-valuenow={current ?? undefined}
      aria-label="Scan phase progress"
    >
      {PHASES.map((p) => {
        const isSelected = selectedSet.has(p.id);
        const visual = phaseVisual(p.id, {
          current,
          isRunning,
          phaseStatus,
          worked,
        });
        const excludedByStatus = visual.status === "not_selected";
        return (
          <div
            key={p.id}
            title={`${p.id}. ${p.name}${
              isSelected || excludedByStatus ? "" : " (not selected)"
            } — ${PHASE_STATUS_LABEL[visual.status]}`}
            className={cn(
              "h-1.5 flex-1 rounded-sm transition-colors",
              !isSelected && !excludedByStatus && "bg-muted/40",
              isSelected && visual.status === "pending" && "bg-muted",
              isSelected && visual.className,
              !isSelected && excludedByStatus && "bg-muted/40",
            )}
          />
        );
      })}
    </div>
  );
}
