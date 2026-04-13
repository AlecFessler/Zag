//! AMD PMU backend.
//!
//! Invoked through the vendor-dispatching façade in `kernel/arch/x64/pmu.zig`.
//! AMD does not implement Intel's architectural PMU (CPUID leaf 0x0A) on the
//! processors this kernel targets, so we program the AMD-specific PerfCtr /
//! PerfEvtSel MSRs directly.
//!
//! Spec references:
//!   * AMD APM Vol 2, Ch 13 "Hardware Performance Monitoring"
//!     - §13.2.1 Legacy PMC MSRs (0xC001_0000..0xC001_0007)
//!     - §13.2.2 Extended PMC MSRs (0xC001_0200..0xC001_020B, PerfCtrExtCore)
//!     - §13.2.3 PerfEvtSel register layout
//!   * AMD APM Vol 3 Appendix E, CPUID Fn8000_0001h ECX bit 23 (PerfCtrExtCore)
//!   * AMD APM Vol 2 §16.4 "Local APIC LVT PerfMon Entry" — same LAPIC LVT
//!     register as Intel; the PMI is delivered as a fixed-vector interrupt
//!     via the existing IDT wiring.
//!
//! Differences from Intel:
//!   * No IA32_PERF_GLOBAL_CTRL / _STATUS / _OVF_CTRL. Each counter is
//!     enabled independently by its own PerfEvtSel EN bit, and overflow
//!     detection is implicit — any PMI on this core is attributed to the
//!     currently running thread's PMU state (same stale-filter policy as
//!     Intel, just without a status MSR to sanity-check against).
//!   * Counters are 48 bits wide on all supported AMD families.
//!   * Event codes differ from Intel; we only encode the always-present
//!     core events (cycles, retired instructions, branches, mispredicts).

const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const pmu_facade = zag.arch.x64.pmu;
const pmu_sched = zag.syscall.pmu;
const sched = zag.sched.scheduler;

const PmuCounterConfig = pmu_sched.PmuCounterConfig;
const PmuEvent = pmu_sched.PmuEvent;
const PmuInfo = pmu_sched.PmuInfo;
const PmuSample = pmu_sched.PmuSample;
const PmuState = pmu_facade.PmuState;
const MAX_COUNTERS = pmu_facade.MAX_COUNTERS;

// ── Legacy PMC MSRs (AMD APM Vol 2 §13.2.1) ────────────────────────────
//   PerfEvtSel0..3 at 0xC001_0000..0xC001_0003
//   PerfCtr0..3    at 0xC001_0004..0xC001_0007
const LEGACY_PERFEVTSEL_BASE: u32 = 0xC001_0000;
const LEGACY_PERFCTR_BASE: u32 = 0xC001_0004;

// ── Extended PMC MSRs (AMD APM Vol 2 §13.2.2, PerfCtrExtCore) ─────────
//   Interleaved layout: PerfEvtSel0=0xC001_0200, PerfCtr0=0xC001_0201,
//   PerfEvtSel1=0xC001_0202, PerfCtr1=0xC001_0203, ...
//   Six counters total (indices 0..5).
const EXT_BASE: u32 = 0xC001_0200;

// ── PerfEvtSel bit layout (AMD APM Vol 2 §13.2.3) ──────────────────────
// Identical to Intel for the low 32 bits we use here:
//   bits  0-7:  Event Select [7:0]
//   bits  8-15: Unit Mask
//   bit   16:   USR
//   bit   17:   OS
//   bit   20:   INT (APIC interrupt on overflow)
//   bit   22:   EN
//   bits 32-35: Event Select [11:8] (AMD extension for 12-bit event codes)
const PERFEVTSEL_USR: u64 = 1 << 16;
const PERFEVTSEL_INT: u64 = 1 << 20;
const PERFEVTSEL_EN: u64 = 1 << 22;

const PMI_VECTOR: u8 = @intFromEnum(interrupts.IntVecs.pmu);

/// AMD counters are 48 bits wide across all supported families (K8+).
const AMD_COUNTER_BITS: u8 = 48;

/// Extended-core PMC layout: PerfEvtSel and PerfCtr are interleaved,
/// two MSRs per counter index.
var use_extended: bool = false;

var cached_info: PmuInfo = .{
    .num_counters = 0,
    .supported_events = 0,
    .overflow_support = false,
};

const EventEncoding = struct {
    /// Low 8 bits of the 12-bit event select. High 4 bits are zero for
    /// every event we currently encode.
    event_select: u8,
    unit_mask: u8,
    supported: bool,
};

fn eventEncoding(e: PmuEvent) EventEncoding {
    // Event codes are from AMD APM Vol 2 Appendix A "Core Performance Event
    // Reference" — common events across Zen 1/2/3/4/5 families. The cache
    // event approximations below (DC access / DC refill) don't match Intel's
    // LLC definitions exactly; they're the best general-purpose Zen analogs.
    return switch (e) {
        // CPU Clocks not Halted (event 0x76).
        .cycles => .{ .event_select = 0x76, .unit_mask = 0x00, .supported = true },
        // Retired Instructions (event 0xC0).
        .instructions => .{ .event_select = 0xC0, .unit_mask = 0x00, .supported = true },
        // Retired Branch Instructions (event 0xC2).
        .branch_instructions => .{ .event_select = 0xC2, .unit_mask = 0x00, .supported = true },
        // Retired Branch Instructions Mispredicted (event 0xC3).
        .branch_misses => .{ .event_select = 0xC3, .unit_mask = 0x00, .supported = true },
        // Data Cache Accesses (event 0x40) — L1 DC access rate. The closest
        // Zen analog to Intel's "LLC reference"; agents using this for
        // cross-vendor comparison should treat the number as a cache-access
        // proxy rather than a strict LLC metric.
        .cache_references => .{ .event_select = 0x40, .unit_mask = 0x00, .supported = true },
        // Data Cache Refills from L2 or System (event 0x43) — L1 DC miss
        // refill rate. Zen analog to "LLC miss"; same caveat.
        .cache_misses => .{ .event_select = 0x43, .unit_mask = 0x00, .supported = true },
        // Stall and bus-cycle events are family-specific. Report unsupported;
        // the generic syscall layer filters these out of any pmu_start.
        else => .{ .event_select = 0x00, .unit_mask = 0x00, .supported = false },
    };
}

fn perfevtselMsr(counter: u8) u32 {
    if (use_extended) return EXT_BASE + @as(u32, counter) * 2;
    return LEGACY_PERFEVTSEL_BASE + @as(u32, counter);
}

fn perfctrMsr(counter: u8) u32 {
    if (use_extended) return EXT_BASE + 1 + @as(u32, counter) * 2;
    return LEGACY_PERFCTR_BASE + @as(u32, counter);
}

pub fn probe() bool {
    // Vendor string is checked by the façade before this runs. Detect
    // extended-core PMCs via CPUID Fn8000_0001 ECX bit 23 (PerfCtrExtCore).
    const ext_max = cpu.cpuid(.ext_max, 0).eax;
    if (ext_max < 0x8000_0001) return false;
    return true;
}

pub fn init() void {
    const ext_features = cpu.cpuid(.ext_features, 0);
    const has_ext = (ext_features.ecx & (1 << 23)) != 0;

    use_extended = has_ext;
    const raw_counters: u8 = if (has_ext) 6 else 4;
    const counters = @min(raw_counters, MAX_COUNTERS);

    var supported_mask: u64 = 0;
    inline for (@typeInfo(PmuEvent).@"enum".fields) |field| {
        const variant: PmuEvent = @enumFromInt(field.value);
        if (eventEncoding(variant).supported) {
            const bit_idx: u6 = @intCast(field.value);
            supported_mask |= @as(u64, 1) << bit_idx;
        }
    }

    cached_info = .{
        .num_counters = counters,
        .supported_events = supported_mask,
        .overflow_support = true,
    };

    interrupts.registerVector(PMI_VECTOR, pmiHandler, .external);
    idt.openInterruptGate(
        PMI_VECTOR,
        interrupts.stubs[PMI_VECTOR],
        zag.arch.x64.gdt.KERNEL_CODE_OFFSET,
        .ring_0,
        .interrupt_gate,
    );
}

pub fn perCoreInit() void {
    if (cached_info.num_counters == 0) return;
    // LAPIC LVT PerfMon entry is architecturally identical on AMD and Intel;
    // reuse the same register. Fixed delivery, unmasked.
    if (apic.x2_apic) {
        const lvt_val: u64 = PMI_VECTOR;
        cpu.wrmsr(
            @intFromEnum(apic.X2ApicMsr.local_vector_table_performance_monitor_register),
            lvt_val,
        );
    } else {
        apic.writeReg(.lvt_perf_monitoring_counters_reg, PMI_VECTOR);
    }
}

pub fn getInfo() PmuInfo {
    return cached_info;
}

pub fn start(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn reset(state: *PmuState, configs: []const PmuCounterConfig) !void {
    programCounters(state, configs);
}

pub fn stop(state: *PmuState) void {
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(i), 0);
        cpu.wrmsr(perfctrMsr(i), 0);
        i += 1;
    }
    state.num_counters = 0;
}

pub fn configureState(state: *PmuState, configs: []const PmuCounterConfig) void {
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

pub fn clearState(state: *PmuState) void {
    state.num_counters = 0;
    var i: usize = 0;
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

pub fn save(state: *PmuState) void {
    if (state.num_counters == 0) return;
    // Disable each counter first so the readback reflects the exact
    // end-of-timeslice value. AMD has no global disable, so we clear
    // EN per counter.
    var i: u8 = 0;
    while (i < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(i), 0);
        i += 1;
    }
    i = 0;
    while (i < state.num_counters) {
        state.values[i] = cpu.rdmsr(perfctrMsr(i)) & COUNTER_MASK;
        i += 1;
    }
}

pub fn restore(state: *PmuState) void {
    if (state.num_counters == 0) return;
    var i: u8 = 0;
    while (i < state.num_counters) {
        const cfg = state.configs[i];
        const enc = eventEncoding(cfg.event);
        cpu.wrmsr(perfctrMsr(i), state.values[i]);
        cpu.wrmsr(perfevtselMsr(i), perfevtselWord(enc, cfg));
        i += 1;
    }
}

pub fn read(state: *PmuState, sample: *PmuSample) void {
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

const COUNTER_MASK: u64 = (@as(u64, 1) << AMD_COUNTER_BITS) - 1;

fn programCounters(state: *PmuState, configs: []const PmuCounterConfig) void {
    // Disable any previously configured counters first so no in-flight
    // PMI fires against half-reprogrammed state.
    var k: u8 = 0;
    while (k < state.num_counters) {
        cpu.wrmsr(perfevtselMsr(k), 0);
        k += 1;
    }

    const n: u8 = @intCast(configs.len);
    state.num_counters = n;
    var i: u8 = 0;
    while (i < n) {
        state.configs[i] = configs[i];
        const enc = eventEncoding(configs[i].event);
        const preload = preloadValue(configs[i]);
        cpu.wrmsr(perfctrMsr(i), preload);
        cpu.wrmsr(perfevtselMsr(i), perfevtselWord(enc, configs[i]));
        state.values[i] = preload;
        i += 1;
    }
    while (i < state.values.len) {
        state.values[i] = 0;
        i += 1;
    }
}

fn perfevtselWord(enc: EventEncoding, cfg: PmuCounterConfig) u64 {
    var w: u64 = 0;
    w |= @as(u64, enc.event_select);
    w |= @as(u64, enc.unit_mask) << 8;
    // Count in user mode (ring 3) only — kernel activity on the thread's
    // core would otherwise be attributed to whichever thread was running
    // when e.g. a timer tick fires.
    w |= PERFEVTSEL_USR;
    w |= PERFEVTSEL_EN;
    if (cfg.has_threshold) w |= PERFEVTSEL_INT;
    return w;
}

/// Preload so the counter overflows exactly `overflow_threshold` events
/// from now. AMD counters are 48 bits wide; overflow fires when the
/// register wraps past `2**48`. Preload with `(2**48) - threshold`.
fn preloadValue(cfg: PmuCounterConfig) u64 {
    if (!cfg.has_threshold) return 0;
    const threshold = cfg.overflow_threshold;
    const span: u64 = @as(u64, 1) << AMD_COUNTER_BITS;
    const clamped = if (threshold >= span) span - 1 else threshold;
    return span - clamped;
}

fn pmiHandler(ctx: *cpu.Context) void {
    // Registered as `.external`; `dispatchInterrupt` EOIs after we return.
    const thread = sched.currentThread() orelse return;
    const state_ptr = thread.pmu_state orelse return;
    if (state_ptr.num_counters == 0) return;

    // Stale-PMI filter: any counter whose current value has wrapped back
    // near its preload (i.e. is far below (2^48 - threshold_small)) is
    // treated as the overflowing one. Simpler policy: if at least one
    // counter's high bit cleared — meaning it overflowed past the 48-bit
    // boundary — attribute the PMI to this thread. Otherwise drop as stale.
    var overflowed = false;
    var i: u8 = 0;
    while (i < state_ptr.num_counters) {
        const raw = cpu.rdmsr(perfctrMsr(i)) & COUNTER_MASK;
        if (raw < state_ptr.values[i]) overflowed = true;
        state_ptr.values[i] = raw;
        // Disable this counter so it can't re-fire before we hand off to
        // the fault handler.
        cpu.wrmsr(perfevtselMsr(i), 0);
        i += 1;
    }
    if (!overflowed) return;

    const rip_at_pmi = ctx.rip;
    const delivered = thread.process.faultBlock(
        thread,
        .pmu_overflow,
        rip_at_pmi,
        rip_at_pmi,
        ctx,
    );

    if (!delivered) {
        thread.process.kill(.pmu_overflow);
    }

    cpu.enableInterrupts();
    sched.yield();
}
