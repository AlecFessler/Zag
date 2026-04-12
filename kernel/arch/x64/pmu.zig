//! x86_64 PMU implementation.
//!
//! Implements the arch-dispatched PMU interface documented in systems.md
//! §13 (Architecture Interface) and §20 (PMU Internals). All x86-specific
//! concepts (MSR numbers, IA32_PERFEVTSELx, IA32_PMCx, IA32_PERF_GLOBAL_CTRL,
//! CPUID leaf 0x0A architectural performance monitoring, LAPIC LVT
//! performance-counter entry, PMI vector wiring) live in this file and are
//! never visible to generic kernel code.
//!
//! Spec references:
//!   * Intel SDM Vol 3, Ch 18 "Performance Monitoring"
//!     - §18.2.1 Architectural Performance Monitoring Version 1 Facilities
//!     - §18.2.1.1 Architectural Performance Monitoring Events (table 18-1)
//!     - §18.2.1.2 Pre-defined Architectural Performance Events (table 18-2)
//!     - §18.2.2 CPUID leaf 0Ah (figures 18-6/18-7)
//!     - §18.2.3 Full-Width Writes to Performance Counter Registers
//!   * Intel SDM Vol 4 "Model-Specific Registers":
//!     - IA32_PMCx (MSR 0xC1 + x)
//!     - IA32_PERFEVTSELx (MSR 0x186 + x)
//!     - IA32_PERF_GLOBAL_CTRL (MSR 0x38F)
//!     - IA32_PERF_GLOBAL_STATUS (MSR 0x38E)
//!     - IA32_PERF_GLOBAL_OVF_CTRL (MSR 0x390)
//!   * AMD APM Vol 2, Ch 13 "Hardware Performance Monitoring" — AMD chips
//!     that implement the Intel architectural PMU via CPUID leaf 0x0A use
//!     the same MSR layout and event encodings; non-architectural AMD
//!     PerfCtr/PerfEvtSel MSRs are not covered by this implementation.

const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const pmu_sched = zag.syscall.pmu;
const sched = zag.sched.scheduler;

const PmuCounterConfig = pmu_sched.PmuCounterConfig;
const PmuEvent = pmu_sched.PmuEvent;
const PmuInfo = pmu_sched.PmuInfo;
const PmuSample = pmu_sched.PmuSample;

/// Per-arch alias for the generic compile-time ceiling. See
/// `zag.syscall.pmu.MAX_COUNTERS` for the rationale.
pub const MAX_COUNTERS: u8 = pmu_sched.MAX_COUNTERS;

// ── MSR numbers (Intel SDM Vol 4) ──────────────────────────────────────
const IA32_PMC_BASE: u32 = 0xC1;
const IA32_PERFEVTSEL_BASE: u32 = 0x186;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
const IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
const IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;

// ── IA32_PERFEVTSELx bit layout (Intel SDM Vol 3 §18.2.1.1, figure 18-1) ──
//   bits  0-7:  Event Select
//   bits  8-15: Unit Mask (UMASK)
//   bit   16:   USR — count events in CPL > 0 (ring 3)
//   bit   17:   OS  — count events in CPL = 0 (ring 0)
//   bit   18:   E (edge detect)
//   bit   19:   PC (pin control)
//   bit   20:   INT — enable APIC PMI on counter overflow
//   bit   21:   ANY
//   bit   22:   EN — enable the counter
//   bit   23:   INV
//   bits 24-31: CMASK
const PERFEVTSEL_USR: u64 = 1 << 16;
const PERFEVTSEL_OS: u64 = 1 << 17;
const PERFEVTSEL_INT: u64 = 1 << 20;
const PERFEVTSEL_EN: u64 = 1 << 22;

/// PMI vector. Registered in the shared `IntVecs` enum
/// (`kernel/arch/x64/interrupts.zig`) at 0xFB — below the scheduler/TLB
/// vectors (0xFD/0xFE) and above the external IRQ range (0x20..0x7F),
/// outside the syscall gate (0x80), so it collides with nothing already
/// allocated.
const PMI_VECTOR: u8 = @intFromEnum(interrupts.IntVecs.pmu);

/// Architectural event index (CPUID.0AH:EBX bits [6:0], 1 bit per
/// architectural event; bit set means event is NOT available).
/// Intel SDM Vol 3 §18.2.1.2 and Table 18-1.
const ARCH_EVENT_CORE_CYCLES: u8 = 0; // UnHalted Core Cycles
const ARCH_EVENT_INST_RETIRED: u8 = 1; // Instructions Retired
const ARCH_EVENT_REF_CYCLES: u8 = 2; // UnHalted Reference Cycles
const ARCH_EVENT_LLC_REF: u8 = 3; // LLC Reference
const ARCH_EVENT_LLC_MISS: u8 = 4; // LLC Misses
const ARCH_EVENT_BR_INST_RETIRED: u8 = 5; // Branch Instruction Retired
const ARCH_EVENT_BR_MISS_RETIRED: u8 = 6; // Branch Mispredict Retired

/// Hardware encoding for one architectural event: `(event_select, unit_mask)`.
/// See Intel SDM Vol 3 Table 18-2 "Predefined Architectural Performance
/// Events". Any `PmuEvent` variant whose `arch_idx` bit is missing from
/// `supported_events` is filtered out by the generic syscall layer before
/// we ever hit `eventEncoding`.
const EventEncoding = struct {
    event_select: u8,
    unit_mask: u8,
    /// Index into CPUID.0AH:EBX[6:0] "architectural events not available"
    /// bitmap. `null` means "this PmuEvent has no direct architectural
    /// counterpart and must be reported as unsupported".
    arch_idx: ?u8,
};

fn eventEncoding(e: PmuEvent) EventEncoding {
    return switch (e) {
        // CPU_CLK_UNHALTED.THREAD, event 0x3C, umask 0x00 (Intel table 18-2).
        .cycles => .{ .event_select = 0x3C, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_CORE_CYCLES },
        // INST_RETIRED.ANY_P, event 0xC0, umask 0x00.
        .instructions => .{ .event_select = 0xC0, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_INST_RETIRED },
        // LONGEST_LAT_CACHE.REFERENCE (a.k.a. LLC Reference), event 0x2E, umask 0x4F.
        .cache_references => .{ .event_select = 0x2E, .unit_mask = 0x4F, .arch_idx = ARCH_EVENT_LLC_REF },
        // LONGEST_LAT_CACHE.MISS (LLC Miss), event 0x2E, umask 0x41.
        .cache_misses => .{ .event_select = 0x2E, .unit_mask = 0x41, .arch_idx = ARCH_EVENT_LLC_MISS },
        // BR_INST_RETIRED.ALL_BRANCHES, event 0xC4, umask 0x00.
        .branch_instructions => .{ .event_select = 0xC4, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_BR_INST_RETIRED },
        // BR_MISP_RETIRED.ALL_BRANCHES, event 0xC5, umask 0x00.
        .branch_misses => .{ .event_select = 0xC5, .unit_mask = 0x00, .arch_idx = ARCH_EVENT_BR_MISS_RETIRED },
        // CPU_CLK_UNHALTED.REF_TSC, event 0x3C, umask 0x01. Bus cycles is
        // reported through the ref-cycles architectural event bit.
        .bus_cycles => .{ .event_select = 0x3C, .unit_mask = 0x01, .arch_idx = ARCH_EVENT_REF_CYCLES },
        // Front-end / back-end stall events are non-architectural on Intel
        // (they live under model-specific events like IDQ_UOPS_NOT_DELIVERED
        // and CYCLE_ACTIVITY.*). Report unsupported — the generic layer
        // rejects starts that reference them.
        .stalled_cycles_frontend, .stalled_cycles_backend => .{
            .event_select = 0x00,
            .unit_mask = 0x00,
            .arch_idx = null,
        },
        else => .{ .event_select = 0x00, .unit_mask = 0x00, .arch_idx = null },
    };
}

/// Per-thread arch state. One entry per configured counter. `num_counters`
/// is what the thread actually programmed via `pmu_start` / `pmu_reset`;
/// `configs[i]` describes counter `i`, and `values[i]` is its last saved
/// value (updated on every context switch away from the owning thread).
const default_config: PmuCounterConfig = .{
    .event = .cycles,
    .has_threshold = false,
    .overflow_threshold = 0,
};

pub const PmuState = extern struct {
    num_counters: u8 = 0,
    _pad: [7]u8 = .{0} ** 7,
    configs: [MAX_COUNTERS]PmuCounterConfig = .{default_config} ** MAX_COUNTERS,
    values: [MAX_COUNTERS]u64 = .{0} ** MAX_COUNTERS,
};

// ── cached PmuInfo populated by pmuInit ─────────────────────────────────
var cached_info: PmuInfo = .{
    .num_counters = 0,
    .supported_events = 0,
    .overflow_support = false,
};

/// Hardware counter bit width from CPUID.0AH:EAX[23:16]. Used to preload
/// counters so they overflow exactly at the configured threshold.
/// 0 means "PMU not present".
var counter_bitwidth: u8 = 0;

/// One-time PMU bring-up on the bootstrap core. Intel SDM Vol 3 §18.2.2
/// "CPUID leaf 0AH" describes the detection protocol. Called from `kMain`
/// between `arch.vmInit()` and `sched.globalInit()`.
///
/// This routine runs once on the BSP only: it does the global CPUID
/// detection, caches `PmuInfo`, and wires the PMI vector into the IDT /
/// interrupts dispatch table. Per-core LAPIC LVT programming happens in
/// `pmuPerCoreInit`, which is called from `sched.perCoreInit` on every
/// core (BSP and APs).
pub fn pmuInit() void {
    // CPUID.0AH.EAX[7:0] = version ID. 0 means architectural PMU absent.
    const max_basic = cpu.cpuid(.basic_max, 0).eax;
    if (max_basic < 0x0A) return;

    const leaf = cpu.cpuidRaw(0x0A, 0);
    const version: u8 = @truncate(leaf.eax & 0xFF);
    // Intel SDM Vol 3 §18.2.2: IA32_PERF_GLOBAL_CTRL / _STATUS / _OVF_CTRL
    // are only guaranteed present on architectural PMU version ≥ 2. Writing
    // them on a v1-only CPU raises #GP. Refuse to enable the PMU on v1.
    if (version < 2) return;

    const num_gp: u8 = @truncate((leaf.eax >> 8) & 0xFF);
    const width: u8 = @truncate((leaf.eax >> 16) & 0xFF);
    if (num_gp == 0 or width == 0) return;

    // CPUID.0AH.EAX[31:24] = length of EBX "events not available" bitmap
    // (§18.2.2). Bit i set in EBX means architectural event i is NOT
    // available on this CPU.
    const ebx_len: u8 = @truncate((leaf.eax >> 24) & 0xFF);
    const ebx_bits = leaf.ebx;

    counter_bitwidth = width;

    var supported_mask: u64 = 0;
    inline for (@typeInfo(PmuEvent).@"enum".fields) |field| {
        const variant: PmuEvent = @enumFromInt(field.value);
        const enc = eventEncoding(variant);
        if (enc.arch_idx) |idx| {
            // An architectural event is "supported" iff its bit is cleared
            // in EBX and the bitmap is long enough to include it.
            if (idx < ebx_len) {
                const shift: u5 = @intCast(idx);
                const missing = ((ebx_bits >> shift) & 1) == 1;
                if (!missing) {
                    const bit_idx: u6 = @intCast(field.value);
                    supported_mask |= @as(u64, 1) << bit_idx;
                }
            }
        }
    }

    // Clamp the reported counter count to the compile-time ceiling.
    const counters = @min(num_gp, MAX_COUNTERS);

    cached_info = .{
        .num_counters = counters,
        .supported_events = supported_mask,
        .overflow_support = true,
    };

    // Wire up the PMI handler: register the vector in the interrupts
    // dispatch table and open an interrupt gate pointing at the stub.
    interrupts.registerVector(PMI_VECTOR, pmuPmiHandler, .external);
    idt.openInterruptGate(
        PMI_VECTOR,
        interrupts.stubs[PMI_VECTOR],
        zag.arch.x64.gdt.KERNEL_CODE_OFFSET,
        .ring_0,
        .interrupt_gate,
    );

    // The BSP's LVT is programmed by its own pmuPerCoreInit() call from
    // sched.perCoreInit(); we do not program it here.
}

/// Per-core PMU bring-up. Runs on every core (BSP and APs) from
/// `sched.perCoreInit`. Programs the LAPIC LVT performance-counter entry
/// with the PMI vector so overflows on this core are delivered to
/// `pmuPmiHandler`. Intel SDM Vol 3 §10.5.1 "Local Vector Table" and
/// §18.6.3 "Generating an Interrupt on Overflow".
///
/// Cheap enough to run unconditionally: if `pmuInit` bailed out
/// (no PMU present or v1-only), `cached_info.num_counters == 0` and the
/// generic syscall layer rejects every `pmu_start`, so the LVT entry is
/// harmless even though counters can never overflow.
pub fn pmuPerCoreInit() void {
    if (cached_info.num_counters == 0) return;
    if (apic.x2_apic) {
        const lvt_val: u64 = PMI_VECTOR; // delivery mode = fixed (0), mask = 0
        cpu.wrmsr(
            @intFromEnum(apic.X2ApicMsr.local_vector_table_performance_monitor_register),
            lvt_val,
        );
    } else {
        apic.writeReg(.lvt_perf_monitoring_counters_reg, PMI_VECTOR);
    }
}

pub fn pmuGetInfo() PmuInfo {
    return cached_info;
}

pub fn pmuStart(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn pmuReset(state: *PmuState, configs: []const PmuCounterConfig) !void {
    // Clear any stale overflow bits from the previous run so the next PMI
    // reflects fresh counter state (Intel SDM Vol 3 §18.6.3).
    clearAllOverflowStatus(state.num_counters);
    programCounters(state, configs);
}

pub fn pmuStop(state: *PmuState) void {
    // Disable every counter globally before touching per-counter MSRs so
    // an in-flight PMI cannot fire while we're mid-reconfiguration.
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), 0);
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), 0);
        i += 1;
    }
    clearAllOverflowStatus(state.num_counters);
    state.num_counters = 0;
}

/// Stamp `state.configs` / `state.values` for a *non-running* target thread.
/// Does NOT touch any MSRs. Used by the generic PMU syscall layer for
/// external-profiler paths where the caller is not the target: when the
/// target is next scheduled, `pmuRestore` picks up the stamped configs and
/// preload values and programs hardware fresh at that point.
///
/// This mirrors the per-counter stamping done by `programCounters` but
/// skips every `wrmsr` — programming MSRs on the caller's core would trash
/// the caller's own PMU state and do nothing to the target's future core.
pub fn pmuConfigureState(state: *PmuState, configs: []const PmuCounterConfig) void {
    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        state.values[i] = preloadValue(configs[i]);
        i += 1;
    }
    // Zero any tail slots so a later pmuSave/pmuRestore doesn't pick up
    // stale values from a previous run with more counters.
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

/// Clear `state` for a *non-running* target thread without touching any
/// MSRs. Used by `pmu_stop` / `Thread.deinit` when the target thread is
/// not the caller — programming hardware is both meaningless (the target
/// isn't running on this core) and destructive (it would clobber whatever
/// PMU state the caller itself is using).
pub fn pmuClearState(state: *PmuState) void {
    state.num_counters = 0;
    // Leaving configs/values as-is is safe — num_counters = 0 means every
    // loop over them becomes a no-op. Zero values for defensiveness.
    var i: usize = 0;
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn pmuSave(state: *PmuState) void {
    // A thread with PMU state allocated but no counters configured (e.g.
    // between pmu_stop and the next pmu_start, or a remote profiler that
    // stamped then cleared) pays nothing on the hot context-switch path.
    if (state.num_counters == 0) return;
    // Disable all counters first (Intel SDM Vol 3 §18.6.1) so the read of
    // each PMCx reflects the thread's exact end-of-timeslice value, not
    // something that crept up between the read and the next instruction.
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var i: u8 = 0;
    while (i < state.num_counters) {
        state.values[i] = cpu.rdmsr(IA32_PMC_BASE + @as(u32, i));
        i += 1;
    }
}

pub fn pmuRestore(state: *PmuState) void {
    if (state.num_counters == 0) return;
    // Guarantee the global enable is clear before writing per-counter MSRs.
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    var enable_mask: u64 = 0;
    var i: u8 = 0;
    while (i < state.num_counters) {
        const cfg = state.configs[i];
        const enc = eventEncoding(cfg.event);
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), perfevtselWord(enc, cfg));
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), state.values[i]);
        const shift_i: u6 = @intCast(i);
        enable_mask |= @as(u64, 1) << shift_i;
        i += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, enable_mask);
}

pub fn pmuRead(state: *PmuState, sample: *PmuSample) void {
    // §2.14.11: pmu_read is only valid on .faulted / .suspended threads,
    // which means the outgoing save has already pushed fresh hardware values
    // into state.values. We therefore copy from the state — not from MSRs.
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

/// Shared implementation for `pmu_start` and `pmu_reset`: copy the configs
/// into `state`, program hardware, preload counters so each one overflows
/// exactly `overflow_threshold` events from now, and flip the global enable.
fn programCounters(state: *PmuState, configs: []const PmuCounterConfig) void {
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);

    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        const enc = eventEncoding(configs[i].event);
        cpu.wrmsr(IA32_PERFEVTSEL_BASE + @as(u32, i), perfevtselWord(enc, configs[i]));
        const preload = preloadValue(configs[i]);
        cpu.wrmsr(IA32_PMC_BASE + @as(u32, i), preload);
        state.values[i] = preload;
        i += 1;
    }
    // Zero any tail slots so a later pmuSave doesn't read stale hardware.
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }

    if (n == 0) return;

    var enable_mask: u64 = 0;
    var j: u8 = 0;
    while (j < n) {
        const sh: u6 = @intCast(j);
        enable_mask |= @as(u64, 1) << sh;
        j += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, enable_mask);
}

fn perfevtselWord(enc: EventEncoding, cfg: PmuCounterConfig) u64 {
    var w: u64 = 0;
    w |= @as(u64, enc.event_select);
    w |= @as(u64, enc.unit_mask) << 8;
    // Count in user mode (ring 3) only — kernel activity on the thread's
    // core would be attributed to whichever thread happens to be running
    // when e.g. a timer tick fires, which pollutes per-thread counts.
    // (Intel SDM Vol 3 §18.2.1.1.)
    w |= PERFEVTSEL_USR;
    w |= PERFEVTSEL_EN;
    if (cfg.has_threshold) w |= PERFEVTSEL_INT;
    return w;
}

/// Compute the counter-register preload value so the counter overflows
/// exactly `overflow_threshold` events from now. Intel SDM Vol 3 §18.6.3:
/// counters are `counter_bitwidth` bits wide; overflow fires when the
/// register wraps past `2**width`. Preload with `(2**width) - threshold`.
fn preloadValue(cfg: PmuCounterConfig) u64 {
    if (!cfg.has_threshold) return 0;
    const threshold = cfg.overflow_threshold;
    if (counter_bitwidth == 0 or counter_bitwidth >= 64) return 0;
    const bw_shift: u6 = @intCast(counter_bitwidth);
    const span: u64 = @as(u64, 1) << bw_shift;
    const clamped = if (threshold >= span) span - 1 else threshold;
    return span - clamped;
}

fn clearAllOverflowStatus(num_counters: u8) void {
    if (num_counters == 0) return;
    var mask: u64 = 0;
    var i: u8 = 0;
    while (i < num_counters) {
        const sh: u6 = @intCast(i);
        mask |= @as(u64, 1) << sh;
        i += 1;
    }
    cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, mask);
}

/// PMI handler. Runs on the core whose counter overflowed. The handler
/// path is documented in systems.md §20 "PMI Handler Flow"; in summary it
/// EOIs, saves counter values, disables the global PMU, and hands the
/// thread off to the fault delivery machinery with reason `pmu_overflow`.
fn pmuPmiHandler(ctx: *cpu.Context) void {
    // The PMI vector is registered as `.external` in `pmuInit`, so
    // `dispatchInterrupt` already issues `apic.endOfInterrupt()` after this
    // handler returns. Do NOT EOI here — a second EOI would pop an extra
    // ISR bit and could mis-acknowledge an unrelated lower-priority
    // pending interrupt. The delivery order is therefore:
    //     save + clear overflow status + disable global PMU → faultBlock →
    //     dispatchInterrupt's post-handler EOI → iret.
    //
    // Step 1: read which counters overflowed, then clear those status
    // bits. Per Intel SDM Vol 3 §18.2.3 the global status register is
    // write-1-to-clear via IA32_PERF_GLOBAL_OVF_CTRL.
    const status = cpu.rdmsr(IA32_PERF_GLOBAL_STATUS);
    cpu.wrmsr(IA32_PERF_GLOBAL_OVF_CTRL, status);

    // Step 2: stop all counters on this core so no second PMI can fire
    // between here and the fault delivery.
    cpu.wrmsr(IA32_PERF_GLOBAL_CTRL, 0);

    // Step 3: find the thread that owns the overflow. If it has no PMU
    // state (race: pmu_stop completed between overflow and PMI), we just
    // return to the interrupted context with counters already disabled.
    const thread = sched.currentThread() orelse return;
    const state_ptr = thread.pmu_state orelse return;

    // Step 3a: stale-PMI filter. A counter can overflow on thread T just
    // before pmuSave clears IA32_PERF_GLOBAL_CTRL; the LAPIC PMI pending
    // bit is set but the interrupt is masked and doesn't fire until the
    // core has context-switched to T'. If T' also has pmu_state, we'd
    // mis-attribute the overflow to T'. Require at least one overflow bit
    // to fall within the current thread's configured counter range — if
    // none do, treat this as stale, leave counters disabled, return.
    if (state_ptr.num_counters == 0) return;
    const nbits: u6 = @intCast(state_ptr.num_counters);
    // Counters occupy bits [0..nbits) of IA32_PERF_GLOBAL_STATUS.
    const owned_mask: u64 = (@as(u64, 1) << nbits) - 1;
    if ((status & owned_mask) == 0) return;

    // Step 4: snapshot the overflowed counter values into `state.values`
    // — same as `pmuSave`.
    var i: u8 = 0;
    while (i < state_ptr.num_counters) {
        state_ptr.values[i] = cpu.rdmsr(IA32_PMC_BASE + @as(u32, i));
        i += 1;
    }

    // Step 5: faultBlock delivers a fault message to the configured
    // handler. FaultMessage.fault_addr and regs.rip are both the RIP at
    // the time of overflow, which is the profiler's sample.
    const rip_at_pmi = ctx.rip;
    const delivered = thread.process.faultBlock(
        thread,
        .pmu_overflow,
        rip_at_pmi,
        rip_at_pmi,
        ctx,
    );

    if (!delivered) {
        // Step 6: no surviving handler — kill and halt. We must NOT return
        // from the PMI handler on this path: returning would unwind through
        // dispatchInterrupt and iret back to the killed thread's user RIP,
        // letting it run freely until the next scheduler tick. Mirror the
        // pattern in `exceptionHandler` (kernel/arch/x64/exceptions.zig) —
        // enable interrupts so the next scheduler tick can dispatch another
        // thread onto this core, and halt in place.
        thread.process.kill(.pmu_overflow);
        cpu.enableInterrupts();
        cpu.halt();
    }

    // Step 7: yield so the scheduler picks a different thread; this
    // thread is now .faulted and the PMI handler must not return to the
    // interrupted RIP.
    //
    // Enable interrupts BEFORE calling yield: yield sends a self-IPI to
    // trigger the context switch, but if IF=0 the IPI stays pending. The
    // PMI handler would then return through dispatchInterrupt (which EOIs)
    // and the stub's iret, letting the faulted thread briefly resume in
    // user mode before the IPI finally lands. Matching the exception
    // handler pattern in kernel/arch/x64/exceptions.zig, re-enabling
    // interrupts here lets the self-IPI preempt the kernel handler
    // immediately, so the thread never re-enters user space.
    cpu.enableInterrupts();
    sched.yield();
}

