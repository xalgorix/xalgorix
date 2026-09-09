// Xalgorix — Autonomous AI Pentesting Engine
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanheaders"
	"github.com/xalgord/xalgorix/v4/internal/tui"
	"github.com/xalgord/xalgorix/v4/internal/web"
)

// version is the build-time version string. CI/release flow should
// override it with -ldflags so the released binary reports the actual tag:
//
//	go build -ldflags "-X main.version=$(git describe --tags --dirty)" ./cmd/xalgorix
//
// The hardcoded fallback is only used when developers `go run` the package
// without ldflags. It is a `var` (not `const`) precisely so ldflags can
// rewrite it.
var version = "4.6.75"

const defaultWebPort = 9137

func main() {
	// Top-level crash recovery — catches panics that escape all other handlers.
	// Critical for service mode where stderr may not be visible.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			crashMsg := fmt.Sprintf(
				"[FATAL CRASH] %v\nHeap: %d MB | Sys: %d MB | Goroutines: %d\n\nStack:\n%s",
				r, m.HeapAlloc/1024/1024, m.Sys/1024/1024, runtime.NumGoroutine(), string(stack),
			)

			// Log to stderr
			fmt.Fprintf(os.Stderr, "\n%s\n", crashMsg)

			// Also log to a file so it survives systemd journal rotation
			if f, err := os.OpenFile("/tmp/xalgorix-crash.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
				_, _ = fmt.Fprintf(f, "\n=== CRASH @ %s ===\n%s\n", time.Now().Format(time.RFC3339), crashMsg)
				f.Close()
			}

			os.Exit(2)
		}
	}()

	args := parseArgs()

	// Handle start command
	if args.start {
		handleStart()
		os.Exit(0)
	}

	// Handle stop command
	if args.stop {
		handleStop()
		os.Exit(0)
	}

	// Handle restart command
	if args.restart {
		handleRestart()
		os.Exit(0)
	}

	// Handle deferred restart-when-idle command
	if args.restartIdle {
		handleRestartWhenIdle()
		os.Exit(0)
	}

	// Handle uninstall command
	if args.uninstall {
		handleUninstall()
		os.Exit(0)
	}

	if args.version {
		fmt.Printf("xalgorix v%s\n", version)
		os.Exit(0)
	}

	// Setup runs before the normal startup path. runSetup also synchronizes the
	// singleton config because a transitive package initializer may have loaded
	// it before main entered.
	if args.setup {
		launchWeb, err := runSetup(os.Stdin, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
			os.Exit(1)
		}
		if !launchWeb {
			return
		}
		args.webUI = true
	}

	// Auto-update check on every start (skip if --update flag is used since that handles it)
	if !args.update {
		autoUpdate()
	}

	if args.update {
		fmt.Println("Updating xalgorix to latest version...")

		// Fetch latest release info from GitHub
		latestVer, downloadURL := fetchLatestRelease()
		if latestVer == "" {
			fmt.Fprintf(os.Stderr, "❌ Failed to fetch latest version from GitHub\n")
			fmt.Fprintf(os.Stderr, "   This is usually caused by GitHub API rate limiting (60 req/hour for unauthenticated users).\n")
			fmt.Fprintf(os.Stderr, "   Try again in a few minutes, or update manually:\n")
			fmt.Fprintf(os.Stderr, "   wget -O $(which xalgorix) https://github.com/xalgorix/xalgorix/releases/latest/download/xalgorix-linux-amd64\n")
			os.Exit(1)
		}

		if latestVer == version {
			fmt.Printf("✅ Already on latest version v%s\n", version)
			os.Exit(0)
		}

		fmt.Printf("Latest version: v%s\n", latestVer)

		// Determine install path
		installPath := resolveInstallPath()

		// Primary: download pre-built binary from GitHub release
		if downloadURL != "" {
			fmt.Printf("Downloading binary from GitHub release...\n")
			if err := installBinary(downloadURL, installPath); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Binary download failed: %v\n", err)
				fmt.Println("Falling back to go install...")
				goto goInstallFallback
			}
			fmt.Println("✅ Updated successfully!")
			verCmd := exec.Command(installPath, "--version")
			verCmd.Stdout = os.Stdout
			_ = verCmd.Run()
			os.Exit(0)
		}

	goInstallFallback:
		// Fallback: use go install with explicit version
		fmt.Printf("Installing v%s via go install...\n", latestVer)
		cmd := exec.Command("go", "install", "-v", "-ldflags", "-X main.version="+latestVer, "github.com/xalgord/xalgorix/v4/cmd/xalgorix@v"+latestVer)
		// GOPRIVATE makes the toolchain skip the public proxy and checksum DB
		// for our module path; GOSUMDB=off avoids hitting sum.golang.org for
		// this private module. (GONOSUMCHECK / GONOSUMDB are not real env vars.)
		cmd.Env = append(os.Environ(),
			"GOPROXY=direct",
			"GOPRIVATE=github.com/xalgord/*",
			"GOSUMDB=off",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Update failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nManual install:\n")
			fmt.Fprintf(os.Stderr, "  GOPROXY=direct GOPRIVATE=github.com/xalgord/* GOSUMDB=off go install -v github.com/xalgord/xalgorix/v4/cmd/xalgorix@v%s\n", latestVer)
			os.Exit(1)
		}

		// go install puts the binary in $GOPATH/bin — copy it to the actual
		// install path if they differ (e.g. /usr/local/bin vs ~/go/bin).
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = filepath.Join(os.Getenv("HOME"), "go")
		}
		goBinPath := filepath.Join(goPath, "bin", "xalgorix")
		if goBinPath != installPath {
			if _, err := os.Stat(goBinPath); err == nil {
				// On Linux, you can't overwrite a running binary ("text file busy").
				// Remove the old binary first, then move the new one in place.
				_ = os.Remove(installPath) // ignore error if not exists
				mvCmd := exec.Command("mv", goBinPath, installPath)
				if mvErr := mvCmd.Run(); mvErr != nil {
					// Fall back to sudo
					cpCmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("rm -f %s && mv %s %s", installPath, goBinPath, installPath))
					if sudoErr := cpCmd.Run(); sudoErr != nil {
						fmt.Fprintf(os.Stderr, "⚠️  Could not copy binary to %s: %v\n", installPath, sudoErr)
						fmt.Fprintf(os.Stderr, "   New binary is at: %s\n", goBinPath)
					}
				}
				_ = os.Chmod(installPath, 0755) //nolint:gosec // G302: installed binary must be executable
			}
		}

		fmt.Println("✅ Updated successfully!")
		verCmd := exec.Command(installPath, "--version")
		verCmd.Stdout = os.Stdout
		_ = verCmd.Run()
		os.Exit(0)
	}

	cfg := config.Get()
	resources.ProtectCurrentProcess()

	// -------------------------------------------------------------------------
	// Proxy initialisation — must run before any outbound HTTP requests.
	// Reads XALGORIX_USE_PROXY, XALGORIX_PROXY_URL, XALGORIX_PROXY_FILE and
	// XALGORIX_PROXY_ROTATION from the already-loaded config.
	// When USE_PROXY is false (the default) this is a no-op and all existing
	// behavior is preserved.
	// -------------------------------------------------------------------------
	if err := proxy.Init(
		cfg.UseProxy,
		cfg.ProxyURL,
		cfg.ProxyFile,
		cfg.ProxyRotation,
		30*time.Second,
	); err != nil {
		fmt.Fprintf(os.Stderr, "[proxy] init warning: %v\n", err)
		// Non-fatal: continue without proxy rather than crashing.
	}
	if proxy.Enabled() {
		fmt.Fprintf(os.Stderr, "[proxy] proxy routing active\n")
	}

	// Set web package version from main — single source of truth
	web.Version = version

	if args.model != "" {
		cfg.LLM = args.model
	}
	if args.bind != "" {
		cfg.BindAddr = args.bind
	}
	if len(args.headers) > 0 {
		cfg.ScanHeaders = scanheaders.Merge(args.headers, cfg.ScanHeaders)
	}

	// Web UI mode — no target or API config required at launch
	if args.webUI {
		port := args.port
		if port == 0 {
			port = defaultWebPort
		}

		fmt.Print(tui.Banner)
		fmt.Println()
		fmt.Printf("\n  Xalgorix Web UI starting on port %d...\n", port)
		printServiceAccessInfo(cfg, port)
		fmt.Println()

		// Opt-in profiling: starts a loopback pprof listener only when
		// XALGORIX_PPROF_ADDR is set (disabled by default). See pprof.go.
		web.StartDebugServerFromEnv()

		srv := web.NewServer(cfg, port)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// A code-first scan (--code-scan review|provision) makes the source the
	// subject, so --target is not required — but --source (or
	// XALGORIX_SOURCE_REPO) must supply the codebase.
	codeScan := strings.ToLower(strings.TrimSpace(args.codeScan))
	if args.source != "" {
		cfg.SourceRepo = args.source
	}
	if codeScan != "" && strings.TrimSpace(cfg.SourceRepo) == "" {
		fmt.Fprintf(os.Stderr, "Error: --code-scan requires --source <git URL or local path>\n\n")
		os.Exit(1)
	}

	// CLI/TUI mode — a live target is required unless this is a code-first scan.
	if len(args.targets) == 0 && codeScan == "" {
		fmt.Fprintf(os.Stderr, "Error: at least one --target is required (or use --code-scan with --source, or --web for Web UI)\n\n")
		printUsage()
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %s\n\n", err)
		fmt.Fprintln(os.Stderr, "Run the interactive setup wizard:")
		fmt.Fprintln(os.Stderr, "  xalgorix --setup")
		os.Exit(1)
	}

	// Default to CLI mode (no TUI)
	tui.RunCLI(cfg, args.targets, args.instruction, codeScan)
}

type cliArgs struct {
	targets     []string
	instruction string
	headers     []string
	model       string
	source      string // --source: git URL or local path for code-first scans
	codeScan    string // --code-scan: "review" or "provision"
	bind        string
	version     bool
	update      bool
	setup       bool
	webUI       bool
	port        int
	start       bool
	stop        bool
	restart     bool
	restartIdle bool
	uninstall   bool
}

func parseArgs() cliArgs {
	var args cliArgs

	osArgs := os.Args[1:]
	for i := 0; i < len(osArgs); i++ {
		switch osArgs[i] {
		case "--target", "-t":
			if i+1 < len(osArgs) {
				i++
				args.targets = append(args.targets, osArgs[i])
			}
		case "--instruction", "-i":
			if i+1 < len(osArgs) {
				i++
				args.instruction = osArgs[i]
			}
		case "--header", "-H":
			if i+1 < len(osArgs) {
				i++
				args.headers = append(args.headers, osArgs[i])
			}
		case "--source", "-s":
			if i+1 < len(osArgs) {
				i++
				args.source = osArgs[i]
			}
		case "--code-scan":
			if i+1 < len(osArgs) {
				i++
				args.codeScan = osArgs[i]
			}
		case "--model", "-m":
			if i+1 < len(osArgs) {
				i++
				args.model = osArgs[i]
			}
		case "--port", "-p":
			if i+1 < len(osArgs) {
				i++
				if p, err := strconv.Atoi(osArgs[i]); err == nil {
					args.port = p
				} else {
					fmt.Fprintf(os.Stderr, "Invalid --port value %q: %v\n", osArgs[i], err)
					os.Exit(1)
				}
			}
		case "--web", "-w":
			args.webUI = true
		case "--bind":
			if i+1 < len(osArgs) {
				i++
				args.bind = osArgs[i]
			}
		case "--update", "-up":
			args.update = true
		case "--setup":
			args.setup = true
		case "--version", "-v":
			args.version = true
		case "--start":
			args.start = true
		case "--stop":
			args.stop = true
		case "--restart":
			args.restart = true
		case "--restart-when-idle", "--restart-idle":
			args.restartIdle = true
		case "--uninstall":
			args.uninstall = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(osArgs[i], "--target=") {
				args.targets = append(args.targets, strings.TrimPrefix(osArgs[i], "--target="))
			} else if strings.HasPrefix(osArgs[i], "--instruction=") {
				args.instruction = strings.TrimPrefix(osArgs[i], "--instruction=")
			} else if strings.HasPrefix(osArgs[i], "--header=") {
				args.headers = append(args.headers, strings.TrimPrefix(osArgs[i], "--header="))
			} else if strings.HasPrefix(osArgs[i], "--source=") {
				args.source = strings.TrimPrefix(osArgs[i], "--source=")
			} else if strings.HasPrefix(osArgs[i], "--code-scan=") {
				args.codeScan = strings.TrimPrefix(osArgs[i], "--code-scan=")
			} else if strings.HasPrefix(osArgs[i], "--model=") {
				args.model = strings.TrimPrefix(osArgs[i], "--model=")
			} else if strings.HasPrefix(osArgs[i], "--port=") {
				_, _ = fmt.Sscanf(strings.TrimPrefix(osArgs[i], "--port="), "%d", &args.port)
			} else if strings.HasPrefix(osArgs[i], "--bind=") {
				args.bind = strings.TrimPrefix(osArgs[i], "--bind=")
			}
		}
	}

	return args
}

func printUsage() {
	fmt.Print(tui.Banner)
	fmt.Println()
	fmt.Println()
	fmt.Println("  Autonomous AI Pentesting Engine")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  xalgorix --setup                Interactive first-time setup")
	fmt.Printf("  xalgorix --web                  Start the Web UI (default port %d)\n", defaultWebPort)
	fmt.Println("  xalgorix --target <url> [flags]  Run a scan in CLI mode")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("      --setup               Configure provider, model, and API key interactively")
	fmt.Println("  -w, --web                 Launch the Web UI dashboard")
	fmt.Printf("  -p, --port <port>         Web UI port (default: %d)\n", defaultWebPort)
	fmt.Println("      --bind <addr>         Bind address (default: 127.0.0.1).")
	fmt.Println("                            Use 0.0.0.0 to expose externally (REQUIRES auth).")
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  --start                   Install and start as systemd service")
	fmt.Println("  --stop                    Stop the service")
	fmt.Println("  --restart                 Restart the service")
	fmt.Println("  --restart-when-idle       Restart once all scans finish and no tools run")
	fmt.Println("  --uninstall               Remove from system")
	fmt.Println()
	fmt.Println("CLI Flags:")
	fmt.Println("  -t, --target <url>        Target URL, IP, or local path (repeatable)")
	fmt.Println("  -i, --instruction <text>  Custom instructions for the agent")
	fmt.Println("  -H, --header <Name: value>  Identifying header on all target traffic (repeatable)")
	fmt.Println("  -s, --source <repo|path>  Codebase to scan (git URL or local path)")
	fmt.Println("      --code-scan <mode>    Code-first scan: 'review' (SAST, no target)")
	fmt.Println("                            or 'provision' (build+run source, then DAST)")
	fmt.Println("  -m, --model <name>        LLM model (overrides XALGORIX_LLM)")
	fmt.Println("  -v, --version             Show version")
	fmt.Println("  -up, --update             Update to latest version")
	fmt.Println("  --start                  Start as background service")
	fmt.Println("  --stop                   Stop running service")
	fmt.Println("  --uninstall              Uninstall from system")
	fmt.Println("  -h, --help                Show help")
	fmt.Println()
	fmt.Println("Proxy:")
	fmt.Println("  XALGORIX_USE_PROXY=true          Enable proxy routing")
	fmt.Println("  XALGORIX_PROXY_URL=ip:port        Single proxy (HTTP/SOCKS5)")
	fmt.Println("  XALGORIX_PROXY_FILE=proxies.txt   Proxy list with rotation")
	fmt.Println("  XALGORIX_PROXY_ROTATION=roundrobin  Rotation: roundrobin or random")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  xalgorix --setup")
	fmt.Println("  xalgorix --web")
	fmt.Println("  xalgorix --web --port 8080")
	fmt.Println("  xalgorix --target https://example.com")
	fmt.Println("  xalgorix --target https://example.com --instruction \"Focus on auth\"")
	fmt.Println("  xalgorix --source ./my-app --code-scan review")
	fmt.Println("  xalgorix --source https://github.com/org/app.git --code-scan provision")
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  xalgorix --start      Start Web UI in background")
	fmt.Println("  xalgorix --stop       Stop running Web UI")
	fmt.Println("  xalgorix --uninstall  Remove xalgorix from system")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  XALGORIX_LLM              Frontier model ID (e.g. openai/gpt-5.6)")
	fmt.Println("  XALGORIX_API_KEY           API key")
	fmt.Println("  XALGORIX_API_BASE          API base URL")
	fmt.Println("  XALGORIX_MAX_ITERATIONS    Max iterations (0 = unlimited)")
	fmt.Println("  XALGORIX_SCAN_HEADERS      Identifying header(s) for target traffic; ';' or newline separated")
	fmt.Println("  XALGORIX_SCAN_HEADERS_FILE File of headers, one 'Name: value' per line")
	fmt.Println()
}

// handleStart installs and starts xalgorix as a systemd service
func handleStart() {
	// Determine install path — use the same resolver as --update
	installPath := resolveInstallPath()

	// Check if binary exists
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		fmt.Printf("❌ Xalgorix not found at %s\n", installPath)
		fmt.Println("   Install with: xalgorix --update")
		os.Exit(1)
	}

	// Kill any existing xalgorix processes first (ignore if none running)
	_ = exec.Command("pkill", "-f", "xalgorix.*--web").Run()
	time.Sleep(1 * time.Second)

	// Also kill anything using the default web port (ignore if port is free)
	_ = exec.Command("fuser", "-k", fmt.Sprintf("%d/tcp", defaultWebPort)).Run()
	time.Sleep(1 * time.Second)

	// If systemd isn't the init system (common in WSL, Docker, and other
	// minimal environments), skip the unit-file dance entirely and run in the
	// background — otherwise `systemctl daemon-reload/start` fail and the whole
	// command aborts with no service running.
	if !systemdAvailable() {
		fmt.Println("ℹ️  systemd not detected on this host — starting in background mode instead.")
		startBackground()
		return
	}

	// Create systemd service file
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	// The active workspace root is now owned by config.resolveDataDir
	// (XALGORIX_DATA_DIR / ~/.xalgorix/data) per Task 3.6 / R6.4. The
	// systemd unit no longer derives a $CWD-style "workspace" path; its
	// WorkingDirectory is just $HOME so relative paths in operator-supplied
	// env vars resolve predictably.
	serviceContent := serviceUnitContent(home, installPath)
	// Try to write service file (requires sudo)
	servicePath := "/etc/systemd/system/xalgorix.service"
	// systemd unit files are conventionally world-readable (0644) and
	// contain no secrets; secrets come from the referenced env file.
	err := os.WriteFile(servicePath, []byte(serviceContent), 0644) //nolint:gosec // G306: systemd unit file is conventionally 0644

	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "tee", servicePath)
		cmd.Stdin = strings.NewReader(serviceContent)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to create service file (need sudo): %v\n", err)
			fmt.Println("   Trying to start in background mode...")
			startBackground()
			return
		}
	}

	// Reload systemd and enable service
	var cmd *exec.Cmd
	cmd = exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: systemctl daemon-reload failed: %v", err)
	}

	cmd = exec.Command("systemctl", "enable", "xalgorix")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Failed to enable service: %v\n", err)
	}

	// Start the service
	cmd = exec.Command("systemctl", "start", "xalgorix")
	if err := cmd.Run(); err != nil {
		// systemd is present but couldn't start the unit (e.g. it's degraded
		// or we lack privileges). Don't leave the operator with nothing —
		// fall back to a background process.
		fmt.Fprintf(os.Stderr, "⚠️  systemctl start failed (%v) — falling back to background mode.\n", err)
		startBackground()
		return
	}

	fmt.Println("✅ Xalgorix installed and started as systemd service!")
	printServiceAccessInfo(config.Get(), defaultWebPort)
	fmt.Println("   Logs:   journalctl -u xalgorix -f")
	fmt.Println("   Status: systemctl status xalgorix")
}

func serviceUnitContent(home, installPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Xalgorix - Autonomous AI Pentesting Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
Environment="PATH=%s/go/bin:%s/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="GOPATH=%s/go"
EnvironmentFile=%s/.xalgorix.env
ExecStart=%s --web
Restart=always
RestartSec=10
OOMScoreAdjust=-500
OOMPolicy=continue

[Install]
WantedBy=multi-user.target
`, home, home, home, home, home, installPath)
}

// systemdAvailable reports whether systemd is the running init system.
// `/run/systemd/system` exists only when the host was booted with systemd as
// PID 1 — the canonical check systemd itself documents (sd_booted(3)). On WSL
// without systemd, in most containers, and on non-systemd distros this is
// absent, so callers should fall back to background mode instead of shelling
// out to a `systemctl` that will fail.
func systemdAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return true
	}
	return false
}

func startBackground() {
	logFile, err := os.OpenFile("/tmp/xalgorix.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	// Use the same resolver as --update / --start
	installPath := resolveInstallPath()

	// Start via bash to source env file
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	// Task 3.6 / R6.4: don't re-derive a workspace from $CWD or invent a
	// new ~/xalgorix-workspace tree. The active Data_Dir is owned by
	// config.resolveDataDir; we just run from $HOME so relative paths the
	// operator supplies via env vars resolve predictably.
	startCmd := exec.Command("/bin/bash", "-c", "source "+homeDir+"/.xalgorix.env && "+installPath+" --web")
	startCmd.Stdout = logFile
	startCmd.Stderr = logFile
	startCmd.Dir = homeDir
	startCmd.Env = os.Environ()

	if err := startCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix started in background!")
	printServiceAccessInfo(config.Get(), defaultWebPort)
	fmt.Println("   Logs:   tail -f /tmp/xalgorix.log")
	fmt.Printf("   PID:    %d\n", startCmd.Process.Pid)
}

// handleStop stops the xalgorix service
func handleStop() {
	// Try to send stop notification to Discord first
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/api/stop-notify", defaultWebPort))
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Small delay to let notification send
	time.Sleep(500 * time.Millisecond)

	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "stop", "xalgorix")
	err := cmd.Run()

	if err != nil {
		// Fallback: pkill (exclude the current --stop process)
		cmd = exec.Command("pkill", "-f", "xalgorix.*--web")
		_ = cmd.Run()
	}

	fmt.Println("✅ Xalgorix stopped!")
}

// handleRestart restarts the xalgorix service
func handleRestart() {
	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "restart", "xalgorix")
	err := cmd.Run()

	if err != nil {
		// Fallback: stop then start
		handleStop()
		startBackground()
		return
	}

	fmt.Println("✅ Xalgorix restarted!")
	printServiceAccessInfo(config.Get(), defaultWebPort)
}

// handleRestartWhenIdle asks a running xalgorix --web process to restart once
// it is idle (all scans finished, no tools running) by sending it SIGUSR1.
// The actual restart is performed by the server's restart-when-idle watcher.
func handleRestartWhenIdle() {
	// pkill -f matches against the full command line. The current process is
	// "xalgorix --restart-when-idle" (no "--web"), so it never signals itself.
	const pattern = "xalgorix.*--web"
	signalCmds := [][]string{
		{"pkill", "--signal", "USR1", "-f", pattern},
		{"sudo", "pkill", "--signal", "USR1", "-f", pattern},
	}
	var signaled bool
	for _, c := range signalCmds {
		if err := exec.Command(c[0], c[1:]...).Run(); err == nil {
			signaled = true
			break
		}
	}
	if !signaled {
		fmt.Fprintln(os.Stderr, "❌ No running xalgorix --web process found to signal (or insufficient permissions).")
		fmt.Fprintln(os.Stderr, "   Start the service first with: xalgorix --start")
		os.Exit(1)
	}
	fmt.Println("✅ Graceful restart scheduled.")
	fmt.Println("   Xalgorix will restart automatically once all running scans finish")
	fmt.Println("   and no tools are active. Watch progress with:")
	fmt.Println("     journalctl -u xalgorix -f      (systemd)")
	fmt.Println("     tail -f /tmp/xalgorix.log      (background mode)")
}

func printServiceAccessInfo(cfg *config.Config, port int) {
	for _, line := range serviceAccessLines(cfg, port) {
		fmt.Println(line)
	}
}

func serviceAccessLines(cfg *config.Config, port int) []string {
	bindAddr := "127.0.0.1"
	if cfg != nil && strings.TrimSpace(cfg.BindAddr) != "" {
		bindAddr = strings.TrimSpace(cfg.BindAddr)
	}

	if isLoopbackBind(bindAddr) {
		return []string{
			fmt.Sprintf("   Web UI: http://localhost:%d (loopback only)", port),
			"   External access: set XALGORIX_BIND=0.0.0.0 plus XALGORIX_USERNAME and XALGORIX_PASSWORD in ~/.xalgorix.env, then restart.",
		}
	}

	host := bindAddr
	if bindAddr == "0.0.0.0" || bindAddr == "::" || bindAddr == "[::]" {
		host = "<server-ip>"
	} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	lines := []string{
		fmt.Sprintf("   Web UI: http://%s:%d (network-exposed)", host, port),
	}
	if !dashboardAuthConfigured(cfg) {
		lines = append(lines, "   Warning: external bind requires XALGORIX_USERNAME and XALGORIX_PASSWORD or XALGORIX_PASSWORD_HASH; the server will refuse to start without auth.")
	}
	lines = append(lines, fmt.Sprintf("   If remote clients still cannot connect, open TCP port %d in the host firewall or cloud security group.", port))
	return lines
}

func isLoopbackBind(bindAddr string) bool {
	switch strings.ToLower(strings.TrimSpace(bindAddr)) {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	default:
		return false
	}
}

func dashboardAuthConfigured(cfg *config.Config) bool {
	return cfg != nil && cfg.Username != "" && (cfg.Password != "" || cfg.PasswordHash != "")
}

// handleUninstall removes xalgorix from the system
func handleUninstall() {
	fmt.Println("🗑️  Uninstalling Xalgorix...")

	// Stop the service first
	cmd := exec.Command("pkill", "-f", "xalgorix")
	_ = cmd.Run()

	// Determine install path — use the same resolver as --update
	installPath := resolveInstallPath()

	// Remove binary
	if _, err := os.Stat(installPath); err == nil {
		rmCmd := exec.Command("rm", installPath)
		rmCmd.Stdout = os.Stdout
		rmCmd.Stderr = os.Stderr
		if err := rmCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to remove binary: %v\n", err)
		} else {
			fmt.Printf("✅ Removed %s\n", installPath)
		}
	}

	// Ask about data removal
	fmt.Println()
	fmt.Println("📁 Data directories (not removed automatically):")
	fmt.Println("   ~/.xalgorix/         - Configuration, skills, and scan data")
	fmt.Println()
	fmt.Println("To remove data manually:")
	fmt.Println("   rm -rf ~/.xalgorix")

	fmt.Println()
	fmt.Println("✅ Uninstall complete!")
}

// autoUpdateInterval is how often a CLI invocation may hit the GitHub API.
// Without a TTL every `xalgorix --target ...` invocation blocks for up to
// 15s waiting on GitHub — annoying for users and rate-limit-prone.
const autoUpdateInterval = 6 * time.Hour

// autoUpdateCheckPath returns the timestamp marker for the last successful
// update check. Using ~/.xalgorix/last_update_check so it survives across
// invocations and lives next to the rest of our local state.
func autoUpdateCheckPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	dir := filepath.Join(home, ".xalgorix")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "last_update_check")
}

// autoUpdateThrottled returns true when the last update check happened
// within autoUpdateInterval. Failures to read/write the marker are
// non-fatal — the worst case is one extra GitHub fetch.
func autoUpdateThrottled() bool {
	info, err := os.Stat(autoUpdateCheckPath())
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < autoUpdateInterval
}

func touchAutoUpdateMarker() {
	now := time.Now()
	path := autoUpdateCheckPath()
	if f, err := os.Create(path); err == nil {
		f.Close()
	}
	_ = os.Chtimes(path, now, now)
}

// autoUpdate checks GitHub for a newer release and self-updates if found.
func autoUpdate() {
	// Opt-out for immutable/managed deployments (containers, packaged installs).
	// In a container the binary must NOT rewrite itself — updates come from
	// pulling a new image tag — so the Docker image sets XALGORIX_NO_AUTO_UPDATE=1.
	if v := strings.TrimSpace(os.Getenv("XALGORIX_NO_AUTO_UPDATE")); v == "1" || strings.EqualFold(v, "true") {
		return
	}
	if autoUpdateThrottled() {
		return
	}
	latestVer, downloadURL := fetchLatestRelease()
	// Mark the check as performed even on failure so a flaky GitHub doesn't
	// produce a blocking call on every invocation.
	touchAutoUpdateMarker()
	if latestVer == "" || latestVer == version {
		return
	}

	if !isNewer(latestVer, version) {
		return
	}

	fmt.Printf("\n🔄 New version available: v%s → v%s\n", version, latestVer)

	installPath := resolveInstallPath()

	// Try binary download first (fastest, avoids Go module issues)
	if downloadURL != "" {
		fmt.Println("   Downloading update...")
		if err := installBinary(downloadURL, installPath); err != nil {
			fmt.Printf("   ⚠️  Download failed: %v (run 'xalgorix --update' manually)\n", err)
			return
		}
	} else {
		// Fallback to go install
		fmt.Println("   Installing update via go install...")
		cmd := exec.Command("go", "install", "-v", "-ldflags", "-X main.version="+latestVer, "github.com/xalgord/xalgorix/v4/cmd/xalgorix@v"+latestVer)
		cmd.Env = append(os.Environ(),
			"GOPROXY=direct",
			"GOPRIVATE=github.com/xalgord/*",
			"GOSUMDB=off",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("   ⚠️  Auto-update failed: %v (run 'xalgorix --update' manually)\n", err)
			return
		}

		// go install puts the binary in $GOPATH/bin — copy to actual install path
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = filepath.Join(os.Getenv("HOME"), "go")
		}
		goBinPath := filepath.Join(goPath, "bin", "xalgorix")
		if goBinPath != installPath {
			if _, statErr := os.Stat(goBinPath); statErr == nil {
				_ = os.Remove(installPath)
				mvCmd := exec.Command("mv", goBinPath, installPath)
				if mvErr := mvCmd.Run(); mvErr != nil {
					cpCmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("rm -f %s && mv %s %s", installPath, goBinPath, installPath))
					if sudoErr := cpCmd.Run(); sudoErr != nil {
						fmt.Fprintf(os.Stderr, "   ⚠️  Could not copy binary to %s: %v\n", installPath, sudoErr)
						fmt.Fprintf(os.Stderr, "      New binary is at: %s\n", goBinPath)
					}
				}
				_ = os.Chmod(installPath, 0755) //nolint:gosec // G302: installed binary must be executable
			}
		}
	}

	fmt.Printf("   ✅ Updated to v%s! Restarting...\n\n", latestVer)

	// Re-exec with same args
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("   ⚠️  Restart failed: %v (please restart manually)\n", err)
		os.Exit(0)
	}
	execPath, _ = filepath.EvalSymlinks(execPath)
	execErr := execRestart(execPath, os.Args, os.Environ())
	if execErr != nil {
		fmt.Printf("   ⚠️  Restart failed: %v (please restart manually)\n", execErr)
	}
	os.Exit(0)
}

// isNewer returns true if a is newer than b (semver comparison).
func isNewer(a, b string) bool {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	for i := 0; i < len(partsA) && i < len(partsB); i++ {
		numA, _ := strconv.Atoi(partsA[i])
		numB, _ := strconv.Atoi(partsB[i])
		if numA > numB {
			return true
		}
		if numA < numB {
			return false
		}
	}
	return len(partsA) > len(partsB)
}

// execRestart re-executes the current process with the same arguments.
func execRestart(path string, argv, env []string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command(path, argv[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
		return nil
	}
	return execSyscall(path, argv, env)
}

// fetchLatestRelease queries GitHub for the latest release version and binary download URL.
func fetchLatestRelease() (version string, downloadURL string) {
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", "https://api.github.com/repos/xalgorix/xalgorix/releases/latest", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "xalgorix/"+version)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Update check failed (network): %v", err)
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		log.Printf("GitHub API rate limited (HTTP %d), trying tags fallback...", resp.StatusCode)
		return fetchLatestTag(client)
	}

	if resp.StatusCode != 200 {
		log.Printf("GitHub releases API returned HTTP %d", resp.StatusCode)
		return fetchLatestTag(client)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", ""
	}

	ver := strings.TrimPrefix(release.TagName, "v")
	if ver == "" {
		return "", ""
	}

	wantName := fmt.Sprintf("xalgorix-%s-%s", runtime.GOOS, runtime.GOARCH)
	for _, asset := range release.Assets {
		if asset.Name == wantName || asset.Name == "xalgorix" {
			return ver, asset.BrowserDownloadURL
		}
	}

	return ver, ""
}

// fetchLatestTag uses the git tags API as a fallback when releases API is rate-limited.
func fetchLatestTag(client *http.Client) (string, string) {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/xalgorix/xalgorix/tags?per_page=1", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "xalgorix/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", ""
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil || len(tags) == 0 {
		return "", ""
	}

	ver := strings.TrimPrefix(tags[0].Name, "v")
	if ver == "" {
		return "", ""
	}

	wantName := fmt.Sprintf("xalgorix-%s-%s", runtime.GOOS, runtime.GOARCH)
	downloadURL := fmt.Sprintf("https://github.com/xalgorix/xalgorix/releases/download/v%s/%s", ver, wantName)
	return ver, downloadURL
}

// resolveInstallPath determines where the xalgorix binary should be installed.
func resolveInstallPath() string {
	if execPath, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
			return resolved
		}
		return execPath
	}
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	return filepath.Join(goPath, "bin", "xalgorix")
}

// installBinary downloads a binary from url and installs it to destPath.
func installBinary(url, destPath string) error {
	tmpPath := destPath + ".new"
	defer func() { _ = os.Remove(tmpPath) }()

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755) //nolint:gosec // G302: downloaded binary must be executable
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		return fmt.Errorf("download interrupted: %w", err)
	}

	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: could not remove old binary: %v, trying rename...", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		cmd := exec.Command("sudo", "mv", tmpPath, destPath)
		if sudoErr := cmd.Run(); sudoErr != nil {
			return fmt.Errorf("failed to install binary (tried mv and sudo mv): %w", err)
		}
	}

	_ = os.Chmod(destPath, 0755) //nolint:gosec // G302: installed binary must be executable
	return nil
}
