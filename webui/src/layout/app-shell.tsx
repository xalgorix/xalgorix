import { useCallback, useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";
import { ConnectionBanner } from "@/components/connection-status";
import { LegacyImportBanner } from "@/components/legacy-import-banner";
import { CommandPalette } from "@/components/command-palette";
import { useWSStore } from "@/store/ws";
import { useI18n } from "@/i18n";

const MOBILE_NAV_ID = "mobile-nav";

export function AppShell() {
  const { t } = useI18n();
  const connect = useWSStore((s) => s.connect);
  const disconnect = useWSStore((s) => s.disconnect);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  // Close mobile sidebar on navigation
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  // The drawer only exists below `md`. If the viewport grows past the
  // breakpoint while it is open, the panel is hidden by `md:hidden` but the
  // dialog stays mounted, which would leave focus trapped inside an invisible
  // element. Close it as soon as the desktop sidebar takes over.
  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 768px)");
    const sync = () => {
      if (desktop.matches) setSidebarOpen(false);
    };
    sync();
    desktop.addEventListener("change", sync);
    return () => desktop.removeEventListener("change", sync);
  }, []);

  const handleSidebarToggle = useCallback(() => setSidebarOpen((o) => !o), []);
  const handleSidebarClose = useCallback(() => setSidebarOpen(false), []);

  // No bg-background on the shell: body paints it, so the decorative radar
  // motif behind the shell stays visible through transparent regions.
  return (
    <div className="flex h-screen overflow-hidden text-foreground">
      {/* Desktop sidebar */}
      <div className="hidden md:block">
        <Sidebar />
      </div>

      {/* Mobile sidebar drawer. Built on the Radix dialog primitive so it gets
          focus trapping, Escape-to-close and `aria-modal` semantics rather than
          re-implementing them on a bare div. */}
      <DialogPrimitive.Root open={sidebarOpen} onOpenChange={setSidebarOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden" />
          <DialogPrimitive.Content
            id={MOBILE_NAV_ID}
            aria-describedby={undefined}
            className="drawer-in fixed inset-y-0 left-0 z-50 w-60 focus:outline-none md:hidden"
          >
            <DialogPrimitive.Title className="sr-only">
              {t("sidebar.navigation")}
            </DialogPrimitive.Title>
            <Sidebar onNavigate={handleSidebarClose} />
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <Topbar
          onMenuToggle={handleSidebarToggle}
          menuOpen={sidebarOpen}
          menuControls={MOBILE_NAV_ID}
        />
        <ConnectionBanner />
        <LegacyImportBanner />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-7xl px-4 py-4 sm:px-6 sm:py-6">
            <Outlet />
          </div>
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
