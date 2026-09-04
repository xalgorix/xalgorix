import { Link } from "react-router-dom";
import { Loader2, Menu, Plus, Search, StopCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConnectionStatus } from "@/components/connection-status";
import { LanguageSwitcher } from "@/components/language-switcher";
import { ThemeToggle } from "@/components/theme-toggle";
import { useStatus, useInstances, useStopAll } from "@/api/queries";
import { useCommandPalette } from "@/components/command-palette";
import { useI18n } from "@/i18n";

export function Topbar({
  onMenuToggle,
  menuOpen = false,
  menuControls,
}: {
  onMenuToggle?: () => void;
  menuOpen?: boolean;
  menuControls?: string;
}) {
  const { t } = useI18n();
  const { data: status } = useStatus();
  const { data: instances } = useInstances();
  const stopAll = useStopAll();
  const palette = useCommandPalette();

  const running =
    status?.running_instances ?? (status?.running ? 1 : 0);
  const activeInst = instances?.instances?.find(
    (i) => i.id === status?.instance_id,
  );

  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/80 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/60 sm:px-4">
      <button
        type="button"
        onClick={onMenuToggle}
        className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:text-foreground md:hidden"
        aria-label={t("topbar.toggleMenu")}
        aria-expanded={menuOpen}
        aria-controls={menuControls}
      >
        <Menu className="h-5 w-5" />
      </button>
      <button
        type="button"
        onClick={() => palette.setOpen(true)}
        className="group inline-flex h-8 min-w-0 flex-1 items-center gap-2 rounded-md border border-border bg-card px-2.5 text-xs text-muted-foreground hover:text-foreground transition-colors md:flex-none md:w-72 md:max-w-72"
        aria-label={t("topbar.openPalette")}
      >
        <Search className="h-3.5 w-3.5 shrink-0" />
        <span className="hidden sm:inline truncate">{t("topbar.searchLong")}</span>
        <span className="sm:hidden truncate">{t("topbar.searchShort")}</span>
        <kbd className="ml-auto hidden shrink-0 sm:inline rounded-sm border border-border bg-muted px-1 py-0.5 text-[10px] mono">
          Ctrl K
        </kbd>
      </button>

      {activeInst ? (
        <Link
          to={`/scans/${activeInst.id}`}
          className="hidden lg:flex min-w-0 items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1 text-xs text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 transition-colors"
        >
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500 pulse-dot" />
          <span className="mono truncate max-w-[14ch] xl:max-w-[24ch]">
            {t("topbar.scanning")} {activeInst.name || activeInst.targets.split(",")[0]}
          </span>
        </Link>
      ) : (
        running > 0 && (
          <span className="hidden lg:inline-flex shrink-0 items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-2.5 py-1 text-xs text-amber-700 dark:text-amber-300">
            <Loader2 className="h-3 w-3 animate-spin" /> {running}{" "}
            {running > 1 ? t("topbar.activeScans") : t("topbar.activeScan")}
          </span>
        )
      )}

      <div className="ml-auto flex shrink-0 items-center gap-2">
        <ThemeToggle />
        <LanguageSwitcher />
        <ConnectionStatus />
        {running > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => stopAll.mutate()}
            disabled={stopAll.isPending}
            className="hidden sm:inline-flex shrink-0 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
          >
            <StopCircle className="h-3.5 w-3.5" />
            <span className="hidden md:inline">{t("topbar.stopAll")}</span>
          </Button>
        )}
        <Button asChild size="sm" className="shrink-0">
          <Link to="/scans/new">
            <Plus className="h-3.5 w-3.5" />{" "}
            <span className="hidden md:inline">{t("topbar.newScan")}</span>
          </Link>
        </Button>
      </div>
    </header>
  );
}
