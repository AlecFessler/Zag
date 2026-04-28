//! aarch64 PMUv3 backend.
//!
//! Implements the arch-dispatched PMU interface documented in systems.md
//! §arch-interface / §pmu using the ARMv8 PMUv3 architectural register
//! interface. Counts in EL0 only (USR counting) so per-thread sampling sees
//! only the thread's own work, matching the x64 backend's `PERFEVTSEL_USR`.
//!
//! Spec references (all "ARM Architecture Reference Manual for A-profile",
//! ARM DDI 0487 K.a):
//!   * D7.3    Performance Monitors Extension (PMUv3) overview
//!   * D13.3.3 PMCR_EL0 — Performance Monitors Control Register
//!   * D13.3.4 PMCNTENSET_EL0 / PMCNTENCLR_EL0
//!   * D13.3.12 PMEVCNTR<n>_EL0 — event counter (0..30)
//!   * D13.3.13 PMEVTYPER<n>_EL0 — event type (0..30)
//!   * D13.3.14 PMCCNTR_EL0 — cycle counter
//!   * D13.3.17 PMOVSCLR_EL0 / PMOVSSET_EL0
//!   * D13.3.19 PMUSERENR_EL0 — EL0 access enables
//!   * D13.3.21 PMINTENSET_EL1 / PMINTENCLR_EL1 — overflow interrupt enable
//!   * D13.2.62 ID_AA64DFR0_EL1 — PMU feature ID; `PMUVer` bits [11:8].
//!   * D23.3 "Common event numbers" (architectural events; A76 implements
//!     these plus µarch-specific events).
//!
//! Host platform: Raspberry Pi 5 (Cortex-A76) under KVM. KVM only exposes
//! the PMUv3 register interface to the guest when QEMU is launched with
//! `-cpu host,pmu=on` (or an equivalent KVM_ARM_VCPU_PMU_V3 attribute);
//! without that flag, guest PMU MRS/MSR trap to an injected undefined
//! instruction. The kernel test runners always pass `pmu=on`; if that flag
//! is dropped the guest panics on the first `probe()` access, which is the
//! intended loud failure mode rather than a silent zero-counter report.

const zag = @import("zag");

const pmu_sched = zag.syscall.pmu;
const port = zag.sched.port;
const sched = zag.sched.scheduler;

const ArchCpuContext = zag.arch.aarch64.interrupts.ArchCpuContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PmuCounterConfig = pmu_sched.PmuCounterConfig;
const PmuEvent = pmu_sched.PmuEvent;
const PmuInfo = pmu_sched.PmuInfo;
const PmuSample = pmu_sched.PmuSample;

/// Per-arch alias for the generic compile-time ceiling. See
/// `zag.syscall.pmu.MAX_COUNTERS` for the rationale.
pub const MAX_COUNTERS: u8 = pmu_sched.MAX_COUNTERS;

/// GIC INTID used by the PMU overflow interrupt on aarch64.
/// ARM ARM DDI 0487 K.a §D13.3.1: PMU overflow connects as a
const default_config: PmuCounterConfig = .{
    .event = .cycles,
    .has_threshold = false,
    .overflow_threshold = 0,
};

/// Per-thread arch PMU state. Layout identical in spirit to the x64
/// backend's `PmuState`: count + configs + saved values.
pub const PmuState = extern struct {
    _gen_lock: GenLock = .{},
    num_counters: u8 = 0,
    _pad: [7]u8 = .{0} ** 7,
    configs: [MAX_COUNTERS]PmuCounterConfig = .{default_config} ** MAX_COUNTERS,
    values: [MAX_COUNTERS]u64 = .{0} ** MAX_COUNTERS,
};

// ── ARMv8 common architectural event numbers (DDI 0487 §D23.3) ──────────
// These are the "common event numbers" mandated by the architecture; A76
// implements every one of them (Arm Cortex-A76 TRM Table 11-1).
const EVENT_INST_RETIRED: u16 = 0x08;
const EVENT_CPU_CYCLES: u16 = 0x11;
const EVENT_BUS_CYCLES: u16 = 0x1D;
const EVENT_BR_RETIRED: u16 = 0x21;
const EVENT_BR_MIS_PRED_RETIRED: u16 = 0x22;
const EVENT_STALL_FRONTEND: u16 = 0x23;
const EVENT_STALL_BACKEND: u16 = 0x24;
const EVENT_LL_CACHE: u16 = 0x32;
const EVENT_LL_CACHE_MISS: u16 = 0x33;

/// Mapping from our cross-arch `PmuEvent` enum to ARMv8 event numbers.
/// `null` = not mapped (unsupported on aarch64).
fn eventNumber(e: PmuEvent) ?u16 {
    return switch (e) {
        .cycles => EVENT_CPU_CYCLES,
        .instructions => EVENT_INST_RETIRED,
        // LL_CACHE* are "common architectural" events D23.3 — A76 implements
        // them as L3/SCU events (Cortex-A76 TRM Table 11-1). On a part that
        // did not implement them, PMCEID0_EL0 would clear the bit and the
        // probe below would not advertise `.cache_references` / `.cache_misses`.
        .cache_references => EVENT_LL_CACHE,
        .cache_misses => EVENT_LL_CACHE_MISS,
        .branch_instructions => EVENT_BR_RETIRED,
        .branch_misses => EVENT_BR_MIS_PRED_RETIRED,
        .bus_cycles => EVENT_BUS_CYCLES,
        .stalled_cycles_frontend => EVENT_STALL_FRONTEND,
        .stalled_cycles_backend => EVENT_STALL_BACKEND,
        else => null,
    };
}

// ── State ───────────────────────────────────────────────────────────────

var cached_info: PmuInfo = .{
    .num_counters = 0,
    .overflow_support = false,
    .supported_events = 0,
};

/// Event counter bit-width. ARMv8.0/8.2 PMUv3 always uses 32-bit event
/// counters; FEAT_PMUv3p5 (PMUVer >= 6) can opt into 64-bit via PMCR_EL0.LP
/// but Cortex-A76 is PMUv3 only, so we stay with 32.
const counter_bitwidth: u8 = 32;

// ── MRS/MSR helpers ─────────────────────────────────────────────────────

inline fn readPMCR() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], pmcr_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn readID_AA64DFR0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], id_aa64dfr0_el1"
        : [v] "=r" (v),
    );
    return v;
}

inline fn readPMCEID0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], pmceid0_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn readPMCEID1() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], pmceid1_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn writePMINTENCLR(mask: u64) void {
    asm volatile ("msr pmintenclr_el1, %[v]"
        :
        : [v] "r" (mask),
    );
}

inline fn writePMINTENSET(mask: u64) void {
    asm volatile ("msr pmintenset_el1, %[v]"
        :
        : [v] "r" (mask),
    );
}

inline fn readPMOVSCLR() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], pmovsclr_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn writePMCNTENSET(mask: u64) void {
    asm volatile ("msr pmcntenset_el0, %[v]"
        :
        : [v] "r" (mask),
    );
}

inline fn writePMCNTENCLR(mask: u64) void {
    asm volatile ("msr pmcntenclr_el0, %[v]"
        :
        : [v] "r" (mask),
    );
}

inline fn writePMOVSCLR(mask: u64) void {
    asm volatile ("msr pmovsclr_el0, %[v]"
        :
        : [v] "r" (mask),
    );
}

inline fn writePMSELR(sel: u64) void {
    asm volatile ("msr pmselr_el0, %[v]"
        :
        : [v] "r" (sel),
    );
    asm volatile ("isb");
}

inline fn writePMXEVTYPER(v: u64) void {
    asm volatile ("msr pmxevtyper_el0, %[v]"
        :
        : [v] "r" (v),
    );
}

inline fn writePMXEVCNTR(v: u64) void {
    asm volatile ("msr pmxevcntr_el0, %[v]"
        :
        : [v] "r" (v),
    );
}

inline fn readPMXEVCNTR() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], pmxevcntr_el0"
        : [v] "=r" (v),
    );
    return v;
}

// ── Probe / init ────────────────────────────────────────────────────────

/// Returns true if PMUv3 is visible at EL1 and at least one counter is
/// advertised by PMCR_EL0.N.
fn probe() bool {
    // ID_AA64DFR0_EL1.PMUVer (bits [11:8]): 0 = not impl, 0xF = "impl but
    // not PMUv3" (IMPDEF only — treat as not supported). Anything in
    // 0x1..0xE is PMUv3 of some minor revision.
    const dfr0 = readID_AA64DFR0();
    const pmuver: u8 = @truncate((dfr0 >> 8) & 0xF);
    if (pmuver == 0 or pmuver == 0xF) return false;

    // PMCR_EL0.N (bits [15:11]) = number of event counters implemented.
    const pmcr = readPMCR();
    const n: u8 = @truncate((pmcr >> 11) & 0x1F);
    if (n == 0) return false;

    return true;
}

pub fn pmuInit() void {
    if (!probe()) {
        cached_info = .{
            .num_counters = 0,
            .overflow_support = false,
            .supported_events = 0,
        };
        return;
    }

    const pmcr = readPMCR();
    const n: u8 = @truncate((pmcr >> 11) & 0x1F);
    const counters = @min(n, MAX_COUNTERS);

    // Build supported-events mask from PMCEID0_EL0 + PMCEID1_EL0 (events
    // 0..63 and 64..127 respectively). Each bit = "this event number is
    // implemented".
    const ceid0 = readPMCEID0();
    const ceid1 = readPMCEID1();

    var mask: u64 = 0;
    inline for (@typeInfo(PmuEvent).@"enum".fields) |field| {
        const variant: PmuEvent = @enumFromInt(field.value);
        if (eventNumber(variant)) |evnum| {
            const impl: bool = if (evnum < 64) blk: {
                const shift: u6 = @intCast(evnum);
                break :blk ((ceid0 >> shift) & 1) == 1;
            } else if (evnum < 128) blk: {
                const shift: u6 = @intCast(evnum - 64);
                break :blk ((ceid1 >> shift) & 1) == 1;
            } else false;
            if (impl) {
                const bit_idx: u6 = @intCast(field.value);
                mask |= @as(u64, 1) << bit_idx;
            }
        }
    }

    cached_info = .{
        .num_counters = counters,
        // Overflow-driven sampling is supported. Per ARM ARM DDI 0487 K.a
        // §D13.3.1 "Generating overflow interrupt requests", the PMU
        // connects to the GIC as a level-sensitive PPI with ID 23 on
        // GICv3-compatible implementations (QEMU `virt`, Cortex-A72/A76
        // all honour this recommendation). The GIC driver enables and
        // configures PPI 23 per-core in `initRedistributor`, and
        // `exceptions.dispatchIrq` routes INTID 23 to `pmiHandler` below.
        .overflow_support = true,
        .supported_events = mask,
    };
}

pub fn pmuGetInfo() PmuInfo {
    return cached_info;
}

pub fn pmuStart(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn pmuStop(state: *PmuState) void {
    if (cached_info.num_counters == 0) {
        state.num_counters = 0;
        return;
    }
    const all_mask: u64 = counterMask(cached_info.num_counters);
    writePMCNTENCLR(all_mask);
    // Mask the PMU overflow PPI for every counter we may have armed.
    // D13.3.21 PMINTENCLR_EL1: bit n = 1 disables the overflow-interrupt
    // contribution of PMEVCNTR<n>. Required for level-sensitive PPI 23
    // so a residual overflow bit can't re-assert the line on the next
    // thread before it gets a chance to reprogram the PMU.
    writePMINTENCLR(all_mask);
    clearAllOverflowStatus(state.num_counters);
    state.num_counters = 0;
}

pub fn pmuConfigureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        state.values[i] = preloadValue(configs[i]);
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn pmuClearState(state: *PmuState) void {
    state.num_counters = 0;
    var i: usize = 0;
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn pmuSave(state: *PmuState) void {
    if (state.num_counters == 0) return;
    if (cached_info.num_counters == 0) return;

    const enabled_mask: u64 = counterMask(state.num_counters);
    writePMCNTENCLR(enabled_mask);
    // Mask the PMU PPI so a pending overflow that fires after the
    // context switch is not delivered against the incoming thread's
    // PMU state. pmuRestore re-arms PMINTENSET for the counters that
    // the restored thread had configured with has_threshold = true.
    writePMINTENCLR(enabled_mask);

    var i: u8 = 0;
    while (i < state.num_counters) {
        writePMSELR(i);
        state.values[i] = readPMXEVCNTR();
        i += 1;
    }
}

pub fn pmuRestore(state: *PmuState) void {
    if (state.num_counters == 0) return;
    if (cached_info.num_counters == 0) return;

    var enable_mask: u64 = 0;
    var intr_mask: u64 = 0;
    var i: u8 = 0;
    while (i < state.num_counters) {
        const cfg = state.configs[i];
        const evnum = eventNumber(cfg.event) orelse {
            i += 1;
            continue;
        };
        writePMSELR(i);
        writePMXEVTYPER(evtyperWord(evnum));
        writePMXEVCNTR(state.values[i]);
        const sh: u6 = @intCast(i);
        enable_mask |= @as(u64, 1) << sh;
        if (cfg.has_threshold) intr_mask |= @as(u64, 1) << sh;
        i += 1;
    }
    if (enable_mask != 0) writePMCNTENSET(enable_mask);
    // D13.3.21 PMINTENSET_EL1: re-arm the PMU overflow PPI only on
    // counters the restored thread asked to sample (has_threshold). The
    // matching mask was cleared in pmuSave so this is a pure re-arm.
    if (intr_mask != 0) writePMINTENSET(intr_mask);
}

pub fn pmuRead(state: *PmuState, sample: *PmuSample) void {
    var i: usize = 0;
    while (i < sample.counters.len) {
        sample.counters[i] = 0;
        i += 1;
    }
    i = 0;
    while (i < state.num_counters) {
        sample.counters[i] = state.values[i];
        i += 1;
    }
}

// ── Internals ───────────────────────────────────────────────────────────

/// Build a bitmask with the low `n` bits set. `n` must be in 0..63.
fn counterMask(n: u8) u64 {
    if (n == 0) return 0;
    if (n >= 64) return ~@as(u64, 0);
    const sh: u6 = @intCast(n);
    return (@as(u64, 1) << sh) - 1;
}

fn programCounters(state: *PmuState, configs: []const PmuCounterConfig) void {
    const n: u8 = @intCast(configs.len);

    if (cached_info.num_counters == 0) {
        // Stub path: keep `state` coherent so pmu_read/pmu_stop semantics
        // remain consistent, but never touch hardware. (Unreachable in
        // practice because the generic syscall layer rejects calls when
        // `num_counters == 0`.)
        state.num_counters = n;
        var i: u8 = 0;
        while (i < n) {
            state.configs[i] = configs[i];
            state.values[i] = 0;
            i += 1;
        }
        return;
    }

    // Disable all slots we are about to touch before reprogramming, and
    // mask any pending overflow interrupts on them to avoid a stale PMI
    // firing against the new configuration (D13.3.21 PMINTENCLR_EL1).
    const touch_mask = counterMask(n);
    writePMCNTENCLR(touch_mask);
    writePMINTENCLR(touch_mask);

    state.num_counters = n;
    var enable_mask: u64 = 0;
    var intr_mask: u64 = 0;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        const evnum = eventNumber(configs[i].event) orelse {
            state.values[i] = 0;
            i += 1;
            continue;
        };
        writePMSELR(i);
        writePMXEVTYPER(evtyperWord(evnum));
        const preload = preloadValue(configs[i]);
        writePMXEVCNTR(preload);
        state.values[i] = preload;
        const sh: u6 = @intCast(i);
        enable_mask |= @as(u64, 1) << sh;
        // Only arm the PMU overflow interrupt for counters that request
        // threshold-based sampling. Free-running counters stay off the
        // PMI so their wrap-arounds don't generate fault messages.
        if (configs[i].has_threshold) intr_mask |= @as(u64, 1) << sh;
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }

    if (enable_mask != 0) writePMCNTENSET(enable_mask);
    if (intr_mask != 0) writePMINTENSET(intr_mask);
}

/// Build a PMEVTYPER<n>_EL0 value for `evnum` with EL0-only counting.
/// DDI 0487 §D13.3.13:
///   [15:0]  evtCount — architectural event number
///   [31]    P  — exclude EL1 (1 = don't count)
///   [30]    U  — exclude EL0 (1 = don't count)
/// We want per-thread user-mode counting, so P=1 (exclude kernel) and U=0
/// (include EL0). This matches the x64 backend's `PERFEVTSEL_USR` policy.
fn evtyperWord(evnum: u16) u64 {
    const P: u64 = 1 << 31;
    return (@as(u64, evnum) & 0xFFFF) | P;
}

/// Compute the preload value so the counter overflows after
/// `overflow_threshold` events. Event counters are `counter_bitwidth`
/// bits wide; preloading with `span - threshold` makes the next overflow
/// arrive after exactly `threshold` events.
fn preloadValue(cfg: PmuCounterConfig) u64 {
    if (!cfg.has_threshold) return 0;
    if (counter_bitwidth == 0 or counter_bitwidth >= 64) return 0;
    const threshold = cfg.overflow_threshold;
    const bw_shift: u6 = @intCast(counter_bitwidth);
    const span: u64 = @as(u64, 1) << bw_shift;
    const clamped = if (threshold >= span) span - 1 else threshold;
    return span - clamped;
}

fn clearAllOverflowStatus(num_counters: u8) void {
    if (num_counters == 0) return;
    if (cached_info.num_counters == 0) return;
    const mask: u64 = counterMask(num_counters);
    writePMOVSCLR(mask);
}

/// PMU overflow PPI (INTID 23) handler. Invoked from
/// `kernel/arch/aarch64/exceptions.zig dispatchIrq`.
///
/// Mirrors the Intel/AMD PMI contract: snapshot the overflow status and
/// live counter values, mask the source (so the level-sensitive PPI 23
/// line deasserts before we ERET back to userspace), deliver a
/// `.pmu_overflow` fault to the process's fault handler, and yield.
///
/// Spec references:
///   * ARM ARM DDI 0487 K.a §D13.3  Behavior on overflow
///   * ARM ARM DDI 0487 K.a §D13.3.1 Generating overflow interrupt requests
///     — PMU overflow connects as GICv3 PPI 23, level-sensitive.
///   * ARM ARM DDI 0487 K.a §D13.3.17 PMOVSCLR_EL0 — clearing a bit
///     deasserts that counter's contribution to the PMU overflow request.
///   * ARM ARM DDI 0487 K.a §D13.3.21 PMINTENCLR_EL1 — masking removes
///     the counter's contribution to PMUIRQ without losing PMOVSSET state.
pub fn pmiHandler(ctx: *ArchCpuContext) void {
    _ = ctx;
    const ec = sched.currentEc() orelse {
        // No EC context (can happen during early boot transitions).
        // Just scrub any pending overflow bits so the PPI deasserts.
        writePMINTENCLR(~@as(u64, 0));
        writePMOVSCLR(~@as(u64, 0));
        return;
    };
    // self-alive: PMI fires on the core running `ec`; its pmu_state
    // slot can't be freed under us during this handler.
    const state_ref = ec.pmu_state orelse {
        // No PMU state on this EC — another EC's overflow that was
        // latched before the context switch. Mask and clear so the
        // level-sensitive PPI line drops, then return.
        writePMINTENCLR(~@as(u64, 0));
        writePMOVSCLR(~@as(u64, 0));
        return;
    };
    const state_ptr = state_ref.ptr;

    // Stale-PMI filter: require at least one overflow bit that maps to
    // a counter owned by the current EC. Matches the Intel PMI
    // filter in `arch/x64/intel/pmu.zig`.
    if (state_ptr.num_counters == 0) {
        writePMINTENCLR(~@as(u64, 0));
        writePMOVSCLR(~@as(u64, 0));
        return;
    }
    const nbits: u6 = @intCast(state_ptr.num_counters);
    const owned_mask: u64 = (@as(u64, 1) << nbits) - 1;
    const status = readPMOVSCLR();
    if ((status & owned_mask) == 0) {
        // Overflow bit belongs to a different EC or a slot we no
        // longer own; just clear every bit to drop the PPI and return.
        writePMOVSCLR(status);
        return;
    }

    // Snapshot every counter's live value so the faulted EC's
    // userspace fault handler can observe the sample.
    var i: u8 = 0;
    while (i < state_ptr.num_counters) {
        writePMSELR(i);
        state_ptr.values[i] = readPMXEVCNTR();
        i += 1;
    }

    // Mask PMU overflow contributions for every owned counter, and
    // clear PMOVSCLR so the level-sensitive PPI 23 line deasserts
    // before we ERET. PMINTENSET is re-armed on the next pmuRestore
    // (or pmuStart) for counters that still have has_threshold = true.
    writePMINTENCLR(owned_mask);
    writePMOVSCLR(status);

    // Identify the first overflowing counter slot as the event sub-code
    // payload. Routes that bind pmu_overflow get the index of the
    // counter that fired; no-route fallback drops the event.
    var fired_idx: u64 = 0;
    var bit: u8 = 0;
    while (bit < state_ptr.num_counters) {
        const sh: u6 = @intCast(bit);
        if (((status >> sh) & 1) != 0) {
            fired_idx = bit;
            break;
        }
        bit += 1;
    }
    port.firePmuOverflow(ec, fired_idx);

    // Hand off to the scheduler so the route's bound port handler (or
    // the next ready EC, if no route was bound) can run. yield is
    // noreturn.
    sched.yield();
}
