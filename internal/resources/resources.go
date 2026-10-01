// Package resources provides real-time system resource monitoring for
// dynamic scan admission control and runtime backpressure.
//
// It uses portable host metrics plus syscall.Statfs for disk space. All
// thresholds are configurable via environment variables.
package resources

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// ── Resource Levels ──

// Level represents the system's current resource pressure.
type Level int

const (
	LevelOK       Level = iota // All good — admit scans, execute tools freely
	LevelCaution               // Resources thinning — block new scans, existing continue
	LevelCritical              // Danger zone — throttle heavy tool execution
)

func (l Level) String() string {
	switch l {
	case LevelOK:
		return "OK"
	case LevelCaution:
		return "CAUTION"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ── System Stats ──

// SystemStats contains a snapshot of current system resources.
type SystemStats struct {
	CPUCores       int
	LoadAvg1m      float64
	MemTotalMB     int64
	MemAvailableMB int64
	DiskFreeMB     int64
	ProcessRSSMB   int64
	GoHeapAllocMB  int64
	GoHeapSysMB    int64
	Goroutines     int
}

// CapacitySnapshot describes the current adaptive capacity model used by the
// scan scheduler and subprocess launcher.
type CapacitySnapshot struct {
	ActiveToolLeases      int
	ActiveHeavyToolLeases int
	HeavyToolSlots        int
	LightToolSlots        int
	ToolMemLimitMB        int64
	ScanMemoryBudgetMB    int64
	HeavyToolCPULoad      float64
	GoMemoryLimitMB       int64
	Reason                string
}

// ToolLease represents reserved CPU/RAM headroom for one subprocess launch.
// Call Release exactly once after the process exits.
type ToolLease struct {
	id               uint64
	toolName         string
	heavy            bool
	memoryLimitBytes int64
	released         bool
}

// ── Thresholds (auto-scaled by init, overridable via env vars) ──
//
// IMPORTANT: Defaults are computed dynamically at startup based on actual
// system resources (CPU cores, total RAM). This ensures safe operation on
// both a 1-core/4GB VPS and a 12-core/24GB workstation without manual tuning.
//
// Override any value with its environment variable.
var (
	// CPU: percentage of cores that constitutes the threshold.
	// e.g., on 12 cores, 70% = load 8.4, 90% = load 10.8
	cpuCautionPct  = envFloat("XALGORIX_CPU_CAUTION_PCT", 70)
	cpuCriticalPct = envFloat("XALGORIX_CPU_CRITICAL_PCT", 90)

	// RAM: minimum free RAM in MB.
	// Auto-scaled in init() based on total system RAM.
	ramCautionMB  int64
	ramCriticalMB int64

	// Disk: minimum free disk in MB.
	diskCautionMB  = envInt64("XALGORIX_DISK_CAUTION_MB", 2048)  // 2 GB
	diskCriticalMB = envInt64("XALGORIX_DISK_CRITICAL_MB", 1024) // 1 GB

	// Optional operator-defined concurrent instance capacity. When set, this is
	// authoritative for scan admission; when unset, live RAM headroom computes
	// the capacity automatically. Tool execution remains resource-throttled in
	// either mode.
	manualMaxInstances = envOptionalInt("XALGORIX_MAX_INSTANCES")

	// Estimated load-average budget consumed by one heavy terminal tool.
	heavyToolCPULoad float64

	// Per-process memory limit for heavy tools (bytes).
	// Auto-scaled in init() based on total RAM. Set to 0 to disable.
	HeavyToolMemLimitBytes int64

	// Total RAM budget per running scan instance. This is the admission-control
	// unit used to decide how many scans can run concurrently.
	scanMemoryBudgetMB int64

	// Extra RAM budget per running scan for the Go process, browser state,
	// LLM history, buffers, and small helper tools around one heavy command.
	scanOverheadMB int64

	goMemoryLimitMB int64

	resourceMu            sync.Mutex
	nextLeaseID           uint64
	activeToolLeases      int
	activeHeavyToolLeases int
)

const (
	toolLeasePollInterval = 5 * time.Second
	toolLeaseLogInterval  = 30 * time.Second
)

func init() {
	cores := runtime.NumCPU()
	totalMB, _ := readMemInfo()

	// XALGORIX_SCAN_CPU_LOAD was a per-scan CPU budget input for the legacy
	// admission model that gated new scans on CPU load. Admission is now
	// RAM-only; if an operator still has the env var set we log a one-time
	// deprecation notice so they know it's a no-op.
	if _, ok := os.LookupEnv("XALGORIX_SCAN_CPU_LOAD"); ok {
		log.Printf("[RESOURCES] XALGORIX_SCAN_CPU_LOAD is deprecated and ignored; scan admission is now RAM-only. Use XALGORIX_HEAVY_TOOL_CPU_LOAD to tune per-tool CPU throttling.")
	}

	heavyToolCPULoad = envFloatDefault("XALGORIX_HEAVY_TOOL_CPU_LOAD", autoHeavyToolCPULoad(cores))
	scanOverheadMB = envInt64Default("XALGORIX_SCAN_OVERHEAD_MB", autoScanOverheadMB(totalMB))
	scanMemoryBudgetMB = envInt64Default("XALGORIX_SCAN_MEMORY_BUDGET_MB", autoScanMemoryBudgetMB(totalMB, cores))

	// ── RAM thresholds ──
	// Caution: 25% of total RAM (4GB VPS → 1024MB, 24GB → 6144MB)
	// Critical: 12% of total RAM (4GB VPS → 512MB, 24GB → 2880MB)
	autoCaution := totalMB / 4
	if autoCaution < 512 {
		autoCaution = 512
	}
	autoCritical := totalMB * 12 / 100
	if autoCritical < 256 {
		autoCritical = 256
	}
	ramCautionMB = envInt64("XALGORIX_RAM_CAUTION_MB", autoCaution)
	ramCriticalMB = envInt64("XALGORIX_RAM_CRITICAL_MB", autoCritical)

	if scanMemoryBudgetMB < 1024 {
		log.Printf("[RESOURCES] XALGORIX_SCAN_MEMORY_BUDGET_MB=%d too low, using 1024", scanMemoryBudgetMB)
		scanMemoryBudgetMB = 1024
	}
	if scanOverheadMB < 128 {
		log.Printf("[RESOURCES] XALGORIX_SCAN_OVERHEAD_MB=%d too low, using 128", scanOverheadMB)
		scanOverheadMB = 128
	}

	// ── Per-tool hard memory limit ──
	// Disabled by default. Many scanners are Go/Rust/Chromium binaries that
	// reserve virtual address space well above resident RAM; RLIMIT_AS/ulimit
	// causes false ENOMEM/SIGSEGV failures and hurts scan quality. Admission
	// control still uses a dynamic memory estimate, but hard limiting is only
	// applied when the operator explicitly configures it.
	var toolMemLimitMB int64
	if override, ok := envOptionalInt64("XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB"); ok {
		toolMemLimitMB = override
	}
	HeavyToolMemLimitBytes = toolMemLimitMB * 1024 * 1024

	configureGoRuntimeLimits(totalMB)

	manualCap := "none"
	if manualMaxInstances > 0 {
		manualCap = strconv.Itoa(manualMaxInstances)
	}
	log.Printf("[RESOURCES] Auto-scaled for %d cores, %d MB RAM: manual_instance_cap=%s, "+
		"ram_caution=%dMB, ram_critical=%dMB, tool_mem_limit=%s, scan_budget=%dMB, "+
		"heavy_tool_cpu_budget=%.2f, go_mem_limit=%dMB",
		cores, totalMB, manualCap, ramCautionMB, ramCriticalMB,
		toolMemoryLimitLabel(), perInstanceMemoryBudgetMB(),
		heavyToolCPULoad, goMemoryLimitMB)
}

// ── Public API ──

// GetStats returns a snapshot of current system resources.
func GetStats() SystemStats {
	stats := SystemStats{
		CPUCores: runtime.NumCPU(),
	}

	stats.LoadAvg1m = readLoadAvg()
	stats.MemTotalMB, stats.MemAvailableMB = readMemInfo()
	stats.DiskFreeMB = readDiskFree()
	stats.ProcessRSSMB = readProcessRSSMB()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	stats.GoHeapAllocMB = int64(mem.HeapAlloc / 1024 / 1024) //nolint:gosec // G115: MB-scaled heap size cannot overflow int64
	stats.GoHeapSysMB = int64(mem.HeapSys / 1024 / 1024)     //nolint:gosec // G115: MB-scaled heap size cannot overflow int64
	stats.Goroutines = runtime.NumGoroutine()

	return stats
}

// CurrentLevel evaluates the system's overall resource pressure.
// Returns the worst (highest) level across all resource dimensions.
func CurrentLevel() (Level, string) {
	stats := GetStats()
	return currentLevelForStats(stats)
}

func currentLevelForStats(stats SystemStats) (Level, string) {
	level := LevelOK
	var reasons []string

	// ── CPU check ──
	cpuCautionLoad := float64(stats.CPUCores) * cpuCautionPct / 100
	cpuCriticalLoad := float64(stats.CPUCores) * cpuCriticalPct / 100

	if stats.LoadAvg1m >= cpuCriticalLoad {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("CPU critical: load %.1f ≥ %.1f (%d%% of %d cores)",
			stats.LoadAvg1m, cpuCriticalLoad, int(cpuCriticalPct), stats.CPUCores))
	} else if stats.LoadAvg1m >= cpuCautionLoad {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("CPU high: load %.1f ≥ %.1f (%d%% of %d cores)",
			stats.LoadAvg1m, cpuCautionLoad, int(cpuCautionPct), stats.CPUCores))
	}

	// ── RAM check ──
	if stats.MemAvailableMB < ramCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("RAM critical: %d MB free < %d MB min",
			stats.MemAvailableMB, ramCriticalMB))
	} else if stats.MemAvailableMB < ramCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("RAM low: %d MB free < %d MB caution",
			stats.MemAvailableMB, ramCautionMB))
	}

	// ── Disk check ──
	if stats.DiskFreeMB < diskCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("Disk critical: %d MB free < %d MB min",
			stats.DiskFreeMB, diskCriticalMB))
	} else if stats.DiskFreeMB < diskCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("Disk low: %d MB free < %d MB caution",
			stats.DiskFreeMB, diskCautionMB))
	}

	if len(reasons) == 0 {
		return LevelOK, fmt.Sprintf("OK — CPU: %.1f/%d cores, RAM: %d MB free, Disk: %d MB free",
			stats.LoadAvg1m, stats.CPUCores, stats.MemAvailableMB, stats.DiskFreeMB)
	}
	return level, strings.Join(reasons, "; ")
}

// EffectiveMaxInstances computes how many scan slots current RAM headroom can
// support when no instances are already running. Callers that already own scan
// slots must use EffectiveMaxInstancesForRunning so those live instances are
// not counted once through runningCount and a second time through the reduced
// MemAvailable reading.
//
// CPU and disk are intentionally NOT slot inputs:
//
//   - CPU saturation throttles scans (kernel time-slices, scans complete
//     more slowly) but never crashes them. Gating new scans on CPU only
//     reduces total throughput. Per-tool CPU throttling lives in the
//     tool-lease layer (see tryAcquireToolLease) where it correctly
//     queues heavy subprocess launches without blocking scan admission.
//   - Disk consumption is bursty and bounded; scans don't reserve a fixed
//     budget up front. Disk only short-circuits to "refuse new scans"
//     when free space is critically low (the safety floor for log writes
//     and tool output) and is otherwise not a slot multiplier.
//
// Algorithm:
//   - If XALGORIX_MAX_INSTANCES is explicitly configured, use it as the total
//     instance capacity instead of the RAM-derived estimate.
//   - Otherwise compute RAM slots from available RAM and per-instance memory
//     budget.
//   - If free disk is below the critical threshold, admit nothing new in
//     either mode.
func EffectiveMaxInstances() (int, string) {
	stats := GetStats()
	return effectiveMaxInstancesForRunningStats(stats, 0, admissionReason(stats))
}

// EffectiveMaxInstancesForRunning returns the current total scan ceiling for
// a scheduler that already has runningCount admitted instances. The RAM model
// measures *remaining* headroom, so the existing instances must be added back
// before comparing the result with runningCount. The previous implementation
// compared runningCount directly with the remaining-headroom slot count; as
// scans consumed memory the reported "maximum" could shrink below the number
// already running (for example six running with "Max 5") and strand otherwise
// admissible work in pending forever.
func EffectiveMaxInstancesForRunning(runningCount int) (int, string) {
	stats := GetStats()
	return effectiveMaxInstancesForAdmissionStats(stats, runningCount, 0, admissionReason(stats))
}

// EffectiveMaxInstancesForAdmission is the scheduler-facing capacity model.
// unreflectedAdmissions is the number of just-started instances whose planned
// memory has not necessarily appeared in MemAvailable yet. Reserving one RAM
// slot for each prevents a burst of pending goroutines from all spending the
// same headroom snapshot before their agents and tools have allocated memory.
func EffectiveMaxInstancesForAdmission(
	runningCount int,
	unreflectedAdmissions int,
) (int, string) {
	stats := GetStats()
	return effectiveMaxInstancesForAdmissionStats(
		stats,
		runningCount,
		unreflectedAdmissions,
		admissionReason(stats),
	)
}

// admissionReason returns the human-readable rationale string for admission
// decisions. It is derived from currentLevelForStats but filtered to mention
// only the dimensions that actually gate admission (RAM and disk-critical) —
// CPU pressure is handled at the tool-lease layer, so surfacing it here
// would tell operators "CPU critical" while admission still proceeds.
func admissionReason(stats SystemStats) string {
	var reasons []string
	switch {
	case stats.MemAvailableMB < ramCriticalMB:
		reasons = append(reasons, fmt.Sprintf("RAM critical: %d MB free < %d MB min",
			stats.MemAvailableMB, ramCriticalMB))
	case stats.MemAvailableMB < ramCautionMB:
		reasons = append(reasons, fmt.Sprintf("RAM low: %d MB free < %d MB caution",
			stats.MemAvailableMB, ramCautionMB))
	}
	if stats.DiskFreeMB > 0 && stats.DiskFreeMB < diskCriticalMB {
		reasons = append(reasons, fmt.Sprintf("Disk critical: %d MB free < %d MB min",
			stats.DiskFreeMB, diskCriticalMB))
	}
	if len(reasons) == 0 {
		return fmt.Sprintf("OK — RAM: %d MB free, Disk: %d MB free",
			stats.MemAvailableMB, stats.DiskFreeMB)
	}
	return strings.Join(reasons, "; ")
}

func effectiveMaxInstancesForStats(stats SystemStats, reason string) (int, string) {
	return effectiveMaxInstancesForAdmissionStats(stats, 0, 0, reason)
}

func effectiveMaxInstancesForRunningStats(stats SystemStats, runningCount int, reason string) (int, string) {
	return effectiveMaxInstancesForAdmissionStats(stats, runningCount, 0, reason)
}

func effectiveMaxInstancesForAdmissionStats(
	stats SystemStats,
	runningCount int,
	unreflectedAdmissions int,
	reason string,
) (int, string) {
	if runningCount < 0 {
		runningCount = 0
	}
	if unreflectedAdmissions < 0 {
		unreflectedAdmissions = 0
	}
	if unreflectedAdmissions > runningCount {
		unreflectedAdmissions = runningCount
	}
	ramHeadroomSlots := memoryInstanceCapacity(stats)
	availableSlots := ramHeadroomSlots - unreflectedAdmissions
	if availableSlots < 0 {
		availableSlots = 0
	}
	effective := runningCount + availableSlots
	capacityMode := "adaptive"
	if manualMaxInstances > 0 {
		// Setting XALGORIX_MAX_INSTANCES is an explicit operator decision about
		// how many scan coordinators this host should admit. Do not silently
		// replace it with a smaller RAM estimate; the tool-lease layer still
		// throttles memory/CPU-heavy subprocesses under pressure.
		effective = manualMaxInstances
		capacityMode = "manual"
	}
	if !diskHasHeadroom(stats) {
		// Existing work may continue, but no new scan may be admitted while the
		// disk is below the hard safety floor.
		effective = runningCount
	}

	detail := fmt.Sprintf("%s; capacity_mode=%s, running=%d, ram_headroom_slots=%d, unreflected_admissions=%d, available_slots=%d, total_ceiling=%d, scan_budget=%dMB",
		reason, capacityMode, runningCount, ramHeadroomSlots, unreflectedAdmissions, availableSlots, effective, perInstanceMemoryBudgetMB())
	if manualMaxInstances > 0 {
		detail += fmt.Sprintf(", manual_capacity=%d", manualMaxInstances)
	}
	return effective, detail
}

func memoryInstanceCapacity(stats SystemStats) int {
	spare := stats.MemAvailableMB - ramCriticalMB
	if spare <= 0 {
		return 0
	}
	ramCap := int(spare / perInstanceMemoryBudgetMB())
	if ramCap < 1 {
		return 1
	}
	return ramCap
}

// diskHasHeadroom reports whether free disk is above the critical floor.
// This is a yes/no admission gate — disk does NOT contribute to slot count.
// Scans don't reserve disk up front; they write logs, tool output, and
// reports as they go. The critical floor exists so a scan can't run on a
// system that's about to fail to write its own results.
func diskHasHeadroom(stats SystemStats) bool {
	if stats.DiskFreeMB <= 0 {
		// statfs failed or filesystem reports zero; don't block on a
		// missing reading.
		return true
	}
	return stats.DiskFreeMB >= diskCriticalMB
}

func perInstanceMemoryBudgetMB() int64 {
	toolLimitMB := HeavyToolMemLimitBytes / (1024 * 1024)
	budget := scanMemoryBudgetMB
	minBudget := toolLimitMB + scanOverheadMB
	if minBudget > budget {
		budget = minBudget
	}
	if budget < 1024 {
		return 1024
	}
	return budget
}

func autoHeavyToolMemLimitMB(totalMB int64) int64 {
	// Base limit scales with host memory but is capped. The scan-budget cap
	// below is what keeps the default admission model around 2GB per instance.
	limit := totalMB / 4
	if limit > 4096 {
		limit = 4096
	}
	if limit < 256 {
		limit = 256
	}

	budgetedLimit := scanMemoryBudgetMB - scanOverheadMB
	if budgetedLimit >= 256 && limit > budgetedLimit {
		limit = budgetedLimit
	}
	return limit
}

func autoHeavyToolCPULoad(cores int) float64 {
	if cores <= 1 {
		return 0.85
	}
	if cores == 2 {
		return 0.90
	}
	return 1.0
}

func autoScanOverheadMB(totalMB int64) int64 {
	overhead := totalMB / 16
	if overhead < 256 {
		overhead = 256
	}
	if overhead > 512 {
		overhead = 512
	}
	return overhead
}

func autoScanMemoryBudgetMB(totalMB int64, cores int) int64 {
	if totalMB <= 0 {
		return 1024
	}
	targetSlots := cores
	if targetSlots < 1 {
		targetSlots = 1
	}
	if targetSlots > 6 {
		targetSlots = 6
	}
	usable := totalMB - hostReserveMB(totalMB)
	if usable < 1024 {
		usable = 1024
	}
	budget := usable / int64(targetSlots)
	if budget < 768 {
		budget = 768
	}
	if budget > 2048 {
		budget = 2048
	}
	return budget
}

func autoGoMemoryLimitMB(totalMB int64) int64 {
	if totalMB <= 0 {
		return 0
	}
	limit := totalMB * 45 / 100
	if limit < 512 {
		limit = 512
	}
	maxLimit := totalMB - hostReserveMB(totalMB)
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	if limit > 4096 {
		limit = 4096
	}
	return limit
}

func hostReserveMB(totalMB int64) int64 {
	reserve := totalMB * 20 / 100
	if reserve < 512 {
		reserve = 512
	}
	if reserve > 2048 {
		reserve = 2048
	}
	return reserve
}

func configureGoRuntimeLimits(totalMB int64) {
	override, hasOverride := envOptionalInt64("XALGORIX_GO_MEM_LIMIT_MB")
	if !hasOverride {
		if _, hasGoMemLimit := os.LookupEnv("GOMEMLIMIT"); hasGoMemLimit {
			log.Printf("[RESOURCES] GOMEMLIMIT is already set; leaving Go runtime memory limit unchanged")
			return
		}
		override = autoGoMemoryLimitMB(totalMB)
	}
	if override > 0 {
		debug.SetMemoryLimit(override * 1024 * 1024)
		goMemoryLimitMB = override
	}
	if _, hasGOGC := os.LookupEnv("GOGC"); !hasGOGC {
		if totalMB > 0 && totalMB <= 4096 {
			debug.SetGCPercent(75)
		} else {
			debug.SetGCPercent(100)
		}
	}
}

// CanAdmitScan decides whether a new scan instance should be started.
// Layer 1: admission control. Uses EffectiveMaxInstances for a live,
// resource-aware concurrency ceiling instead of a fixed number.
func CanAdmitScan(runningCount int) (bool, string) {
	return CanAdmitScanWithReservations(runningCount, 0)
}

// CanAdmitScanWithReservations applies the live capacity model while reserving
// RAM for instances admitted recently enough that their memory may not yet be
// reflected in the operating system's MemAvailable reading.
func CanAdmitScanWithReservations(runningCount int, unreflectedAdmissions int) (bool, string) {
	effMax, reason := EffectiveMaxInstancesForAdmission(runningCount, unreflectedAdmissions)

	if effMax <= 0 {
		return false, fmt.Sprintf("dynamic limit: resources unavailable (%s)", reason)
	}

	if runningCount >= effMax {
		return false, fmt.Sprintf("dynamic limit: %d/%d instances (%s)",
			runningCount, effMax, reason)
	}

	return true, fmt.Sprintf("%d/%d instances — %s", runningCount, effMax, reason)
}

// CanExecTool decides whether a tool can be executed right now.
// Layer 2: pre-exec throttle. The decision uses both live pressure and active
// tool leases, so CPU-heavy commands cannot stampede when a scan fleet starts.
func CanExecTool(isHeavy bool) (bool, string) {
	stats := GetStats()
	level, reason := currentLevelForStats(stats)
	resourceMu.Lock()
	activeTotal := activeToolLeases
	activeHeavy := activeHeavyToolLeases
	resourceMu.Unlock()
	capacity := toolCapacityForStats(stats, level, reason, activeTotal, activeHeavy)
	return toolSlotAdmission(isHeavy, capacity, activeTotal, activeHeavy)
}

func toolMemoryLimitLabel() string {
	if HeavyToolMemLimitBytes <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("%dMB", HeavyToolMemLimitBytes/(1024*1024))
}

// AcquireToolLease reserves live CPU/RAM headroom for one subprocess. The
// caller must release the lease after the process exits.
func AcquireToolLease(isHeavy bool, maxWait time.Duration, toolName string) (*ToolLease, bool) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if maxWait > 0 {
		ctx, cancel = context.WithTimeout(ctx, maxWait)
		defer cancel()
	}
	lease, err := acquireToolLeaseWithContext(ctx, isHeavy, toolName, toolLeasePollInterval, maxWait)
	return lease, err == nil
}

// ErrToolLeaseWaitTimeout is wrapped into the error returned by the lease
// acquire functions when launch capacity could not be obtained within the
// bounded lease-wait window. Callers use errors.Is on it to distinguish a
// saturated or wedged launch queue from a canceled scan.
var ErrToolLeaseWaitTimeout = errors.New("tool lease wait timeout")

// DefaultToolLeaseMaxWait bounds how long one subprocess launch may sit in
// the tool lease queue before it is returned as a typed throttle failure.
//
// The predecessor semantics ("block until capacity is available") made the
// wait unbounded: a wedged lease holder or a stuck resource-pressure level
// froze EVERY subsequent terminal_execute/python_action/browser_action
// call. Commands queued pre-launch are outside the per-command timeout
// (that starts only after launch), so even trivial commands sat until the
// agent-level hard-timeout force-return — observed burning 65 minutes per
// attempt, repeatedly, for hours. Ten minutes is far above normal fleet
// queueing while guaranteeing a fast, typed failure the agent can act on.
const DefaultToolLeaseMaxWait = 10 * time.Minute

// AcquireToolLeaseContext reserves live CPU/RAM headroom for one subprocess.
// It blocks until capacity is available, the caller's context is canceled,
// or DefaultToolLeaseMaxWait elapses (in which case the returned error wraps
// ErrToolLeaseWaitTimeout). It never refuses purely because the system
// stayed busy for a shorter period — ten minutes of sustained saturation is
// treated as a launch-path failure, not a reason to queue forever.
func AcquireToolLeaseContext(ctx context.Context, isHeavy bool, toolName string) (*ToolLease, error) {
	return AcquireToolLeaseContextMaxWait(ctx, isHeavy, toolName, DefaultToolLeaseMaxWait)
}

// AcquireToolLeaseContextMaxWait is AcquireToolLeaseContext with an explicit
// lease-wait bound. A maxWait <= 0 selects DefaultToolLeaseMaxWait.
func AcquireToolLeaseContextMaxWait(ctx context.Context, isHeavy bool, toolName string, maxWait time.Duration) (*ToolLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxWait <= 0 {
		maxWait = DefaultToolLeaseMaxWait
	}
	return acquireToolLeaseWithContext(ctx, isHeavy, toolName, toolLeasePollInterval, maxWait)
}

func acquireToolLeaseWithContext(ctx context.Context, isHeavy bool, toolName string, pollInterval time.Duration, maxWait time.Duration) (*ToolLease, error) {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	toolLabel := ToolLogLabel(toolName)
	waited := false
	startedWaiting := time.Now()
	lastLog := startedWaiting
	var lastReason string
	var deadline time.Time
	if maxWait > 0 {
		deadline = startedWaiting.Add(maxWait)
	}

	for {
		lease, reason := tryAcquireToolLease(isHeavy, toolLabel)
		if lease != nil {
			if waited {
				log.Printf("[RESOURCES] Resources recovered; proceeding with %s", toolLabel)
			}
			return lease, nil
		}
		lastReason = reason

		// Bounded lease wait (circuit-breaker backstop): return a typed
		// failure instead of queueing forever when the launch path cannot
		// free capacity within the allowed window.
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, fmt.Errorf("gave up waiting for launch capacity for %s after %s — %s: %w",
				toolLabel, time.Since(startedWaiting).Round(time.Second), lastReason, ErrToolLeaseWaitTimeout)
		}

		if !waited {
			log.Printf("[THROTTLE] Queueing %s until resources recover — %s", toolLabel, reason)
			waited = true
			lastLog = time.Now()
		} else if time.Since(lastLog) >= toolLeaseLogInterval {
			log.Printf("[THROTTLE] Still waiting to exec %s after %s — %s",
				toolLabel, time.Since(startedWaiting).Round(time.Second), lastReason)
			lastLog = time.Now()
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("canceled while waiting to launch %s after %s: %w (last resource state: %s)",
				toolLabel, time.Since(startedWaiting).Round(time.Second), ctx.Err(), lastReason)
		case <-time.After(pollInterval):
		}
	}
}

// ToolLogLabel returns a short, non-sensitive label for resource-manager logs.
// Callers may pass full shell commands; this intentionally logs only the tool
// name so URLs, tokens, headers, and payloads do not end up in journald.
func ToolLogLabel(toolName string) string {
	fields := strings.Fields(strings.TrimSpace(toolName))
	for i := 0; i < len(fields); i++ {
		part := strings.Trim(fields[i], `"'`)
		if part == "" {
			continue
		}
		if strings.Contains(part, "=") && !strings.Contains(part, "/") && !strings.HasPrefix(part, "-") {
			continue
		}
		switch part {
		case "sudo", "env", "command", "time", "timeout", "nice", "nohup":
			continue
		case "bash", "sh", "zsh":
			return "shell"
		}
		if slash := strings.LastIndex(part, "/"); slash >= 0 {
			part = part[slash+1:]
		}
		if part == "" {
			continue
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '+' {
				continue
			}
			return "tool"
		}
		return part
	}
	return "tool"
}

func tryAcquireToolLease(isHeavy bool, toolLabel string) (*ToolLease, string) {
	stats := GetStats()
	level, levelReason := currentLevelForStats(stats)

	resourceMu.Lock()
	defer resourceMu.Unlock()

	capacity := toolCapacityForStats(stats, level, levelReason, activeToolLeases, activeHeavyToolLeases)
	if ok, reason := toolSlotAdmission(isHeavy, capacity, activeToolLeases, activeHeavyToolLeases); !ok {
		return nil, reason
	}

	projectedTotal := activeToolLeases + 1
	projectedHeavy := activeHeavyToolLeases
	if isHeavy {
		projectedHeavy++
	}
	limitMB := toolMemoryLimitMBForStats(stats, isHeavy, projectedTotal, projectedHeavy, level)
	if isHeavy && HeavyToolMemLimitBytes > 0 && limitMB < minimumHeavyToolMemMB() {
		return nil, fmt.Sprintf("not enough RAM for heavy tool: dynamic limit %dMB below minimum %dMB (%s)",
			limitMB, minimumHeavyToolMemMB(), capacity.Reason)
	}

	nextLeaseID++
	activeToolLeases++
	if isHeavy {
		activeHeavyToolLeases++
	}
	lease := &ToolLease{
		id:               nextLeaseID,
		toolName:         toolLabel,
		heavy:            isHeavy,
		memoryLimitBytes: limitMB * 1024 * 1024,
	}
	log.Printf("[RESOURCES] Lease %d acquired for %s: heavy=%v active_tools=%d active_heavy=%d mem_limit=%dMB slots=%d/%d",
		lease.id, toolLabel, isHeavy, activeToolLeases, activeHeavyToolLeases, limitMB,
		capacity.HeavyToolSlots, capacity.LightToolSlots)
	return lease, capacity.Reason
}

func toolSlotAdmission(isHeavy bool, capacity toolCapacity, activeTotal, activeHeavy int) (bool, string) {
	if isHeavy && activeHeavy >= capacity.HeavyToolSlots {
		return false, fmt.Sprintf("heavy tool slots full: %d/%d (%s)",
			activeHeavy, capacity.HeavyToolSlots, capacity.Reason)
	}
	if activeTotal >= capacity.LightToolSlots {
		return false, fmt.Sprintf("tool slots full: %d/%d (%s)",
			activeTotal, capacity.LightToolSlots, capacity.Reason)
	}
	return true, capacity.Reason
}

// Release frees the CPU/RAM reservation held by this tool lease.
func (l *ToolLease) Release() {
	if l == nil {
		return
	}
	resourceMu.Lock()
	defer resourceMu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if activeToolLeases > 0 {
		activeToolLeases--
	}
	if l.heavy && activeHeavyToolLeases > 0 {
		activeHeavyToolLeases--
	}
	log.Printf("[RESOURCES] Lease %d released for %s: active_tools=%d active_heavy=%d",
		l.id, l.toolName, activeToolLeases, activeHeavyToolLeases)
}

// MemoryLimitBytes returns the per-process memory ceiling selected for this
// lease. A zero value means memory limiting is disabled by configuration.
func (l *ToolLease) MemoryLimitBytes() int64 {
	if l == nil {
		return CurrentToolMemoryLimitBytes(true)
	}
	return l.memoryLimitBytes
}

// CurrentToolMemoryLimitBytes returns a best-effort memory limit for callers
// that cannot hold an explicit lease.
func CurrentToolMemoryLimitBytes(isHeavy bool) int64 {
	stats := GetStats()
	level, _ := currentLevelForStats(stats)
	resourceMu.Lock()
	projectedTotal := activeToolLeases + 1
	projectedHeavy := activeHeavyToolLeases
	if isHeavy {
		projectedHeavy++
	}
	resourceMu.Unlock()
	return toolMemoryLimitMBForStats(stats, isHeavy, projectedTotal, projectedHeavy, level) * 1024 * 1024
}

// Capacity returns the current resource model, including active tool leases.
func Capacity() CapacitySnapshot {
	stats := GetStats()
	level, reason := currentLevelForStats(stats)
	resourceMu.Lock()
	activeTotal := activeToolLeases
	activeHeavy := activeHeavyToolLeases
	resourceMu.Unlock()
	capacity := toolCapacityForStats(stats, level, reason, activeTotal, activeHeavy)
	return CapacitySnapshot{
		ActiveToolLeases:      activeTotal,
		ActiveHeavyToolLeases: activeHeavy,
		HeavyToolSlots:        capacity.HeavyToolSlots,
		LightToolSlots:        capacity.LightToolSlots,
		ToolMemLimitMB:        toolMemoryLimitMBForStats(stats, true, activeTotal+1, activeHeavy+1, level),
		ScanMemoryBudgetMB:    perInstanceMemoryBudgetMB(),
		HeavyToolCPULoad:      heavyToolCPULoad,
		GoMemoryLimitMB:       goMemoryLimitMB,
		Reason:                capacity.Reason,
	}
}

type toolCapacity struct {
	HeavyToolSlots int
	LightToolSlots int
	Reason         string
}

func toolCapacityForStats(stats SystemStats, level Level, reason string, activeTotal, activeHeavy int) toolCapacity {
	spareMB := stats.MemAvailableMB - ramCriticalMB
	if spareMB <= 0 {
		return toolCapacity{Reason: reason}
	}

	heavyMemUnitMB := toolMemoryEstimateMB(stats, true)
	memSlots := int(spareMB / heavyMemUnitMB)
	if memSlots < 1 && spareMB > 0 {
		memSlots = 1
	}

	cpuHeavySlots := heavyToolCPUCapacity(stats)
	parallelCap := heavyToolParallelCap(stats.CPUCores)
	heavySlots := minInt(memSlots, minInt(cpuHeavySlots, parallelCap))

	lightMemUnitMB := toolMemoryEstimateMB(stats, false)
	lightMemSlots := int(spareMB / lightMemUnitMB)
	if lightMemSlots < 1 && spareMB > 0 {
		lightMemSlots = 1
	}
	lightSlots := minInt(lightMemSlots, lightToolCPUCapacity(stats))
	if lightSlots < heavySlots {
		lightSlots = heavySlots
	}

	detail := fmt.Sprintf("%s; tool_slots: heavy=%d/%d light=%d/%d, active_tools=%d, active_heavy=%d, heavy_mem_est=%dMB, light_mem_est=%dMB, cpu_budget=%.2f, hard_mem_limit=%s",
		reason, activeHeavy, heavySlots, activeTotal, lightSlots, activeTotal, activeHeavy,
		heavyMemUnitMB, lightMemUnitMB, heavyToolCPULoad, toolMemoryLimitLabel())
	return toolCapacity{HeavyToolSlots: heavySlots, LightToolSlots: lightSlots, Reason: detail}
}

func toolMemoryEstimateMB(stats SystemStats, isHeavy bool) int64 {
	heavyEstimate := autoHeavyToolMemLimitMB(stats.MemTotalMB)
	if heavyEstimate < 1 {
		heavyEstimate = 1
	}
	if isHeavy {
		return heavyEstimate
	}
	cores := int64(maxInt(1, stats.CPUCores))
	lightEstimate := heavyEstimate / cores
	if lightEstimate < 1 {
		return 1
	}
	return lightEstimate
}

func toolMemoryLimitMBForStats(stats SystemStats, isHeavy bool, projectedTotal, projectedHeavy int, level Level) int64 {
	if HeavyToolMemLimitBytes <= 0 {
		return 0
	}
	maxLimitMB := HeavyToolMemLimitBytes / (1024 * 1024)
	if maxLimitMB <= 0 {
		return 0
	}
	spareMB := stats.MemAvailableMB - ramCriticalMB
	if spareMB <= 0 {
		return minimumHeavyToolMemMB()
	}

	divisor := projectedHeavy
	if !isHeavy {
		divisor = projectedTotal
	}
	if divisor < 1 {
		divisor = 1
	}
	dynamicLimit := spareMB / int64(divisor)
	if level == LevelCaution {
		dynamicLimit = dynamicLimit * 3 / 4
	}
	if dynamicLimit > maxLimitMB {
		dynamicLimit = maxLimitMB
	}
	minLimit := minimumHeavyToolMemMB()
	if !isHeavy {
		minLimit = 128
	}
	if dynamicLimit < minLimit {
		dynamicLimit = minLimit
	}
	return dynamicLimit
}

func heavyToolCPUCapacity(stats SystemStats) int {
	budget := heavyToolCPULoad
	if budget <= 0 {
		budget = autoHeavyToolCPULoad(stats.CPUCores)
	}
	cores := maxInt(1, stats.CPUCores)
	loadPerCore := stats.LoadAvg1m / float64(cores)
	if loadPerCore < 1 {
		loadPerCore = 1
	}
	capacity := int(math.Floor(float64(cores) / (budget * loadPerCore)))
	if capacity < 1 {
		return 1
	}
	return capacity
}

func lightToolCPUCapacity(stats SystemStats) int {
	cores := maxInt(1, stats.CPUCores)
	loadPerCore := stats.LoadAvg1m / float64(cores)
	if loadPerCore < 1 {
		loadPerCore = 1
	}
	capacity := int(math.Ceil(float64(cores*cores) / loadPerCore))
	if capacity < 1 {
		return 1
	}
	return capacity
}

func heavyToolParallelCap(cores int) int {
	if cores <= 1 {
		return 1
	}
	if cores == 2 {
		return 2
	}
	return maxInt(2, cores-1)
}

func minimumHeavyToolMemMB() int64 {
	return 256
}

// WaitForResources blocks until resources are available, or until maxWait is
// exceeded. It keeps the old API for non-lease callers by acquiring and
// immediately releasing a short lease.
func WaitForResources(isHeavy bool, maxWait time.Duration, toolName string) bool {
	lease, ok := AcquireToolLease(isHeavy, maxWait, toolName)
	if lease != nil {
		lease.Release()
	}
	return ok
}

// MaxInstances returns the optional manual cap. A zero value means no static
// cap is configured and the live resource ceiling is used directly.
func MaxInstances() int {
	return manualMaxInstances
}

// LiveMaxInstances returns the current effective ceiling (dynamic, based on live resources).
func LiveMaxInstances() int {
	n, _ := EffectiveMaxInstances()
	return n
}

// ProtectCurrentProcess lowers the OOM-killer score for the xalgorix parent
// process. Child scan tools are assigned a higher score when they launch, so
// under memory pressure the kernel should kill a tool before the web service.
func ProtectCurrentProcess() {
	if runtime.GOOS != "linux" {
		return
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-500"), 0644); err != nil { //nolint:gosec // G306: procfs ignores the file mode
		if !os.IsPermission(err) {
			log.Printf("[RESOURCES] Cannot protect xalgorix from OOM killer: %v", err)
		}
		return
	}
	log.Printf("[RESOURCES] xalgorix OOM score set to -500")
}

// ── Portable host metrics ──

// readLoadAvg reads the host's 1-minute load average.
func readLoadAvg() float64 {
	stats, err := load.Avg()
	if err != nil {
		log.Printf("[RESOURCES] Cannot read load average: %v", err)
		return 0
	}
	return stats.Load1
}

// readMemInfo reads total and available physical memory. gopsutil maps this to
// procfs on Linux and the native VM statistics APIs on macOS.
func readMemInfo() (totalMB, availableMB int64) {
	stats, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("[RESOURCES] Cannot read memory statistics: %v", err)
		return 0, 0
	}
	return int64(stats.Total / (1024 * 1024)), int64(stats.Available / (1024 * 1024)) //nolint:gosec // G115: MB-scaled memory sizes fit int64
}

func readProcessRSSMB() int64 {
	current, err := process.NewProcess(int32(os.Getpid())) //nolint:gosec // G115: OS process IDs fit int32
	if err != nil {
		return 0
	}
	stats, err := current.MemoryInfo()
	if err != nil {
		return 0
	}
	return int64(stats.RSS / (1024 * 1024)) //nolint:gosec // G115: MB-scaled RSS fits int64
}

// readDiskFree returns free disk space (in MB) for the root filesystem.
func readDiskFree() int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		log.Printf("[RESOURCES] Cannot statfs /: %v", err)
		return 0
	}
	// Available blocks * block size → bytes → MB. Compute in uint64 to
	// match the statfs field types, then convert the MB-scaled result
	// (which always fits int64) once.
	freeMB := stat.Bavail * uint64(stat.Bsize) / (1024 * 1024) //nolint:gosec // G115: filesystem block size is small and non-negative
	return int64(freeMB)                                       //nolint:gosec // G115: MB-scaled free space fits int64
}

// ── Env var helpers ──

func envFloat(key string, defaultVal float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		log.Printf("[RESOURCES] Invalid %s=%q, using default %.1f", key, s, defaultVal)
		return defaultVal
	}
	return v
}

func envFloatDefault(key string, defaultVal float64) float64 {
	return envFloat(key, defaultVal)
}

func envInt64(key string, defaultVal int64) int64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		log.Printf("[RESOURCES] Invalid %s=%q, using default %d", key, s, defaultVal)
		return defaultVal
	}
	return v
}

func envInt64Default(key string, defaultVal int64) int64 {
	return envInt64(key, defaultVal)
}

func envOptionalInt64(key string) (int64, bool) {
	s, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(s) == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v < 0 {
		log.Printf("[RESOURCES] Invalid %s=%q, ignoring override", key, s)
		return 0, false
	}
	return v, true
}

func envOptionalInt(key string) int {
	s, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(s) == "" {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v < 1 {
		log.Printf("[RESOURCES] Invalid %s=%q, ignoring manual cap", key, s)
		return 0
	}
	return v
}

// max returns the larger of two Levels.
func maxLevel(a, b Level) Level {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
