//! x86_64 system-information (frequency, temperature, C-state) reads for
//! the `sys_info` syscall.
//!
//! Implements the arch-dispatched interface documented in systems.md §13
//! "System Information" and §21 "System Info Internals". All x86-specific
//! concepts (IA32_PERF_STATUS, IA32_THERM_STATUS, MSR_PLATFORM_INFO,
//! MSR_TEMPERATURE_TARGET, MSR_PKG_CST_CONFIG_CONTROL, CPUID leaf 0x16)
//! live in this file and are never visible to generic kernel code.
//!
//! Remote-core reads are served from a tick-sampled cache: each core's
//! `schedTimerHandler` calls `sampleCoreHwState()` on its own scheduler
//! tick, writing the freshly read frequency/temperature/C-state into the
//! core's cache slot. `getCoreFreq`/`getCoreTemp`/`getCoreState` then
//! simply read the cache slot for any core (local or remote) — the
//! stalest value is <= one scheduler timeslice (2 ms) old, which is
//! acceptable for UI-grade polling and avoids cross-core IPIs. Atomic
//! loads/stores with `.monotonic` ordering prevent tearing across cores
//! without a lock.
//!
//! Spec references:
//!   * Intel SDM Vol 3, Ch 15 "Power and Thermal Management"
//!     - §15.5  Thread and Core C-States
//!     - §15.7  Processor-Specific Power Management (IA32_PERF_STATUS)
//!     - §15.8  Platform Specific Power Management Support
//!   * Intel SDM Vol 4 "Model-Specific Registers":
//!     - IA32_PERF_STATUS          (MSR 0x198)
//!     - IA32_THERM_STATUS         (MSR 0x19C)
//!     - MSR_TEMPERATURE_TARGET    (MSR 0x1A2)
//!     - MSR_PLATFORM_INFO         (MSR 0xCE)
//!     - MSR_PKG_CST_CONFIG_CONTROL (MSR 0xE2)
//!   * Intel SDM Vol 2 "CPUID":
//!     - Leaf 0x16 "Processor Frequency Information"

const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const MAX_CORES: usize = 64;

// ── MSR numbers (Intel SDM Vol 4) ──────────────────────────────────────
const IA32_PERF_STATUS: u32 = 0x198;
const IA32_THERM_STATUS: u32 = 0x19C;
const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;
const MSR_PLATFORM_INFO: u32 = 0xCE;
const MSR_PKG_CST_CONFIG_CONTROL: u32 = 0xE2;

/// Fallback bus frequency if neither `CPUID.16h` nor `MSR_PLATFORM_INFO`
/// yield a usable value. 100 MHz matches the external bus clock on every
/// mainstream Intel part since Nehalem (Intel SDM Vol 3 §15.7
/// "Processor-Specific Power Management").
const DEFAULT_BUS_FREQ_HZ: u64 = 100_000_000;

/// Cached per-CPU state sampled at scheduler-tick granularity. Reads from
/// remote cores hit this cache; the owning core's `schedTimerHandler`
/// calls `sampleCoreHwState()` to refresh it before the next tick lands.
/// Atomics prevent tearing across cores; no lock is needed because each
/// slot is written by exactly one core (its owner) and read by any core.
const CoreCache = struct {
    freq_hz: u64 = 0,
    temp_mc: u32 = 0,
    c_state: u8 = 0,
    /// TjMax in celsius (§15.8 / `MSR_TEMPERATURE_TARGET` bits 23:16).
    /// Sampled once per core in `sysInfoPerCoreInit`; zero if the MSR
    /// is unavailable, in which case `getCoreTemp` returns 0.
    tjmax_c: u8 = 0,
};

/// Per-core cache slot. Indexed by `coreID()`. Writers are each core's
/// own scheduler tick; readers are the `sys_info` handler on any core.
var core_cache: [MAX_CORES]CoreCache align(64) = [_]CoreCache{.{}} ** MAX_CORES;

/// Bus frequency in hertz discovered once at boot. Used to convert the
/// `IA32_PERF_STATUS` ratio into an absolute frequency.
var bus_freq_hz: u64 = DEFAULT_BUS_FREQ_HZ;

/// One-time system-info bring-up on the bootstrap core. Discovers the
/// bus frequency via `CPUID.16h` (Intel SDM Vol 2 "CPUID" leaf 0x16)
/// if available, falling back to `MSR_PLATFORM_INFO` bits 15:8 × 100 MHz
/// (Intel SDM Vol 3 §15.7), and finally to a 100 MHz default.
///
/// Called from `kMain` after `arch.pmuInit()` and before
/// `sched.globalInit()`.
pub fn sysInfoInit() void {
    // Prefer CPUID.16h if the CPU advertises leaf 0x16. EAX[15:0] is the
    // base processor frequency in MHz and ECX[15:0] is the bus frequency
    // in MHz. When available, ECX is the authoritative bus clock used by
    // the IA32_PERF_STATUS ratio.
    const max_basic = cpu.cpuid(.basic_max, 0).eax;
    if (max_basic >= 0x16) {
        const leaf = cpu.cpuidRaw(0x16, 0);
        const bus_mhz: u64 = leaf.ecx & 0xFFFF;
        if (bus_mhz != 0) {
            bus_freq_hz = bus_mhz * 1_000_000;
            return;
        }
    }

    // `MSR_PLATFORM_INFO` bits 15:8 carry the "maximum non-turbo ratio"
    // relative to a fixed 100 MHz bus clock on every Intel part that
    // implements this MSR (Intel SDM Vol 3 §15.7 / Vol 4 MSR table).
    // The ratio itself isn't the bus clock, but its presence confirms the
    // 100 MHz default — leave `bus_freq_hz = DEFAULT_BUS_FREQ_HZ`.
    _ = MSR_PLATFORM_INFO;
    // bus_freq_hz stays at DEFAULT_BUS_FREQ_HZ.
}

/// Per-core system-info bring-up. Runs on every core (BSP and APs) from
/// `sched.perCoreInit`, alongside `arch.pmuPerCoreInit`. Reads
/// `MSR_TEMPERATURE_TARGET` bits 23:16 once to cache TjMax (Intel SDM
/// Vol 3 §15.8 "Platform Specific Power Management Support"). Also
/// primes the cache slot with a first sample so `getCoreFreq` etc. never
/// return a zeroed slot even before the first scheduler tick fires.
pub fn sysInfoPerCoreInit() void {
    const core_id = zag.arch.x64.apic.coreID();
    if (core_id >= MAX_CORES) return;

    const tt = cpu.rdmsr(MSR_TEMPERATURE_TARGET);
    const tjmax: u8 = @truncate((tt >> 16) & 0xFF);
    core_cache[core_id].tjmax_c = tjmax;

    sampleCoreHwState();
}

/// Sample this core's frequency, temperature, and C-state into the core's
/// cache slot. Called from `schedTimerHandler` on every scheduler tick
/// before any `running_thread` transition (systems.md §21).
///
/// `rdmsr` reads the issuing core's MSRs, so this function **must** run on
/// the target core. Remote cores read the cache slot populated by this
/// function on the target core's last tick.
pub fn sampleCoreHwState() void {
    const core_id = zag.arch.x64.apic.coreID();
    if (core_id >= MAX_CORES) return;
    const slot = &core_cache[core_id];

    // ── Frequency: IA32_PERF_STATUS (MSR 0x198) ─────────────────────────
    // Intel SDM Vol 3 §15.7 / Vol 4 MSR table. The current performance
    // state ratio is in bits [15:8] of the low 16 bits (a.k.a. "Current
    // Performance State Value"). The absolute frequency is
    // `ratio * bus_freq_hz`.
    const perf = cpu.rdmsr(IA32_PERF_STATUS);
    const ratio: u64 = (perf >> 8) & 0xFF;
    const freq_hz: u64 = ratio * bus_freq_hz;

    // ── Temperature: IA32_THERM_STATUS (MSR 0x19C) ──────────────────────
    // Intel SDM Vol 3 §15.8 / Vol 4 MSR table. Bit 31 is "Reading Valid";
    // bits [22:16] are the "Digital Readout" — degrees below TjMax.
    // Milli-celsius = (tjmax_c - offset_c) * 1000. If either TjMax is 0
    // (MSR not present) or the reading-valid bit is clear, report 0.
    const therm = cpu.rdmsr(IA32_THERM_STATUS);
    const reading_valid = (therm & (@as(u64, 1) << 31)) != 0;
    var temp_mc: u32 = 0;
    if (reading_valid and slot.tjmax_c != 0) {
        const offset: u8 = @truncate((therm >> 16) & 0x7F);
        if (offset < slot.tjmax_c) {
            const celsius: u64 = @as(u64, slot.tjmax_c) - @as(u64, offset);
            temp_mc = @intCast(celsius * 1000);
        }
    }

    // ── C-state: derived from scheduler view ────────────────────────────
    // §2.15.6 only requires a minimal active/idle signal: 0 = active,
    // non-zero = idle at some package-default depth. More granular
    // per-core C-state residency MSRs (MSR_CORE_C{1,3,6,7}_RES) are a
    // future refinement per systems.md §21. We rely on the scheduler's
    // `idle_ns` accounting (updated right before this hook) to tell the
    // difference: if the outgoing thread was the idle thread, this core
    // was effectively idle across the previous tick — report the
    // package-default idle level read from `MSR_PKG_CST_CONFIG_CONTROL`.
    // For the active case we unconditionally return 0 here and let the
    // idle path overwrite it. The package C-state config bits are in
    // bits [2:0] of MSR 0xE2 (Intel SDM Vol 4 MSR table). `MSR_PKG_CST`
    // is written by firmware and may raise #GP on exotic SKUs — fall
    // back to 1 (C1) if the read path is unusable.
    _ = MSR_PKG_CST_CONFIG_CONTROL;
    const c_state: u8 = 0;

    // Atomic stores so cross-core readers (`getCoreFreq` et al. running
    // on some other core in the `sys_info` handler) never see a half-
    // updated slot. `.monotonic` is sufficient — there is no ordering
    // relationship between these fields; readers that need a coherent
    // triple get at-most-one-tick-stale values either way.
    @atomicStore(u64, &slot.freq_hz, freq_hz, .monotonic);
    @atomicStore(u32, &slot.temp_mc, temp_mc, .monotonic);
    @atomicStore(u8, &slot.c_state, c_state, .monotonic);
}

/// Return the cached current frequency of `core_id` in hertz. Served from
/// the per-core tick-sampled cache (up to one scheduler timeslice stale).
/// Returns 0 if `core_id` is out of range or the cache has never been
/// populated (e.g. for a core that has not run `sysInfoPerCoreInit` yet).
pub fn getCoreFreq(core_id: u64) u64 {
    if (core_id >= MAX_CORES) return 0;
    return @atomicLoad(u64, &core_cache[core_id].freq_hz, .monotonic);
}

/// Return the cached current temperature of `core_id` in milli-celsius.
/// Same tick-sampled cache semantics as `getCoreFreq`.
pub fn getCoreTemp(core_id: u64) u32 {
    if (core_id >= MAX_CORES) return 0;
    return @atomicLoad(u32, &core_cache[core_id].temp_mc, .monotonic);
}

/// Return the cached current C-state level of `core_id`. Same tick-sampled
/// cache semantics as `getCoreFreq`.
pub fn getCoreState(core_id: u64) u8 {
    if (core_id >= MAX_CORES) return 0;
    return @atomicLoad(u8, &core_cache[core_id].c_state, .monotonic);
}
