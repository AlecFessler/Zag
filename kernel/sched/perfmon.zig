//! Per-EC PMU counter state. Lazy-allocated on first `perfmon_start`
//! against an EC; freed on `perfmon_stop` or implicitly on EC destroy.
//! See spec §[execution_context] perfmon_* syscalls.
//!
//! Not a handle-bearing object — referenced only from
//! `ExecutionContext.perfmon_state` as `?SlabRef(PerfmonState)`.
//! Slab-allocated so ECs that never call perfmon don't carry the
//! per-counter buffers as inline bloat.

const std = @import("std");
const zag = @import("zag");

const dispatch = zag.arch.dispatch;
const port = zag.sched.port;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PmuCounterConfig = zag.syscall.pmu.PmuCounterConfig;
const PmuEvent = zag.syscall.pmu.PmuEvent;
const PmuSample = zag.syscall.pmu.PmuSample;
const PmuState = dispatch.pmu.PmuState;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;

/// Maximum hardware PMU counters the state struct accommodates.
/// Common architectures expose 4-8 general-purpose counters; this
/// caps the inline arrays at a power-of-two reasonable for both.
pub const MAX_COUNTERS: u8 = 8;

/// Bit 8 of a `config_event` word is `has_threshold`. Spec §[execution_context].perfmon_start.
const CONFIG_HAS_THRESHOLD_BIT: u64 = 1 << 8;

/// Bits 0..7 of a `config_event` word hold the event index. Spec §[execution_context].perfmon_start.
const CONFIG_EVENT_MASK: u64 = 0xFF;

/// Reserved bits in a `config_event` word; any set bit returns E_INVAL. Spec test 06.
const CONFIG_RESERVED_MASK: u64 = ~(CONFIG_EVENT_MASK | CONFIG_HAS_THRESHOLD_BIT);

pub const PerfmonState = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Bitmap of which counters (bits 0..MAX_COUNTERS) are active.
    active_counters: u8 = 0,

    /// Per-counter event index (per `perfmon_info`'s
    /// `supported_events` bitmask). Valid only for active counters.
    counter_events: [MAX_COUNTERS]u8 = [_]u8{0} ** MAX_COUNTERS,

    /// Per-counter overflow threshold. Used only when the
    /// corresponding bit in `has_threshold` is set.
    counter_thresholds: [MAX_COUNTERS]u64 = [_]u64{0} ** MAX_COUNTERS,

    /// Bitmap of which counters have an overflow threshold configured
    /// (matches the `has_threshold` bit in the original config_event).
    has_threshold: u8 = 0,

    /// Arch PMU control state — MSR snapshots, hardware counter
    /// assignment, sub-counter event-select encodings. Carried inline
    /// because the kernel has no general-purpose heap; the only
    /// allocators for kernel objects are SecureSlabs.
    arch_state: PmuState = .{},
};

pub const Allocator = SecureSlab(PerfmonState, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── Internal API (no syscalls — perfmon syscalls live on EC) ─────────

/// Lazy-allocate a PerfmonState slot for an EC on first perfmon_start.
fn alloc() !*PerfmonState {
    const ref = try slab_instance.create();
    return ref.ptr;
}

/// Free on perfmon_stop or implicit on EC destroy. Idempotent against
/// a null `ec.perfmon_state`; the caller is expected to clear that
/// field after the call returns.
fn release(ps: *PerfmonState) void {
    // currentGen() snapshot is safe here: perfmon_start/read/stop are
    // serialized through the owning EC's `_gen_lock`, so no other path
    // can be racing a destroy of this slot.
    const gen = ps._gen_lock.currentGen();
    if (gen % 2 == 0) return;
    slab_instance.destroy(ps, gen) catch {};
}

/// Decode `[]const u64` perfmon_start configs into `PmuCounterConfig`s,
/// stamp `ps`, and program the hardware via `dispatch.pmu`.
/// Returns 0 on success or a negative spec error code.
/// Spec §[execution_context].perfmon_start.
fn programCounters(ps: *PerfmonState, configs: []const u64) i64 {
    const info = dispatch.pmu.pmuGetInfo();
    const n = configs.len / 2;
    if (n == 0 or n > info.num_counters or n > MAX_COUNTERS) return -1;

    var decoded: [MAX_COUNTERS]PmuCounterConfig = undefined;
    var active_mask: u8 = 0;
    var threshold_mask: u8 = 0;

    var i: usize = 0;
    while (i < n) {
        const word = configs[2 * i];
        const threshold = configs[2 * i + 1];

        if (word & CONFIG_RESERVED_MASK != 0) return -1;

        const event_idx: u8 = @intCast(word & CONFIG_EVENT_MASK);
        const has_threshold = (word & CONFIG_HAS_THRESHOLD_BIT) != 0;

        if (event_idx >= 64) return -1;
        const event_bit = @as(u64, 1) << @intCast(event_idx);
        if (info.supported_events & event_bit == 0) return -1;
        if (has_threshold and !info.overflow_support) return -1;

        const event_enum: PmuEvent = @enumFromInt(event_idx);
        decoded[i] = .{
            .event = event_enum,
            .has_threshold = has_threshold,
            .overflow_threshold = threshold,
        };

        const slot_bit: u8 = @as(u8, 1) << @intCast(i);
        active_mask |= slot_bit;
        if (has_threshold) threshold_mask |= slot_bit;
        ps.counter_events[i] = event_idx;
        ps.counter_thresholds[i] = threshold;

        i += 1;
    }

    // Zero out trailing slots so a smaller-N reprogramming doesn't
    // leave stale entries in the visible state.
    while (i < MAX_COUNTERS) {
        ps.counter_events[i] = 0;
        ps.counter_thresholds[i] = 0;
        i += 1;
    }

    ps.active_counters = active_mask;
    ps.has_threshold = threshold_mask;

    dispatch.pmu.pmuStart(&ps.arch_state, decoded[0..n]) catch return -1;
    return 0;
}

/// Read counter values + monotonic timestamp.
/// Spec §[execution_context].perfmon_read.
fn readCounters(ps: *PerfmonState, out_values: []u64, out_timestamp: *u64) i64 {
    var sample: PmuSample = .{ .counters = [_]u64{0} ** MAX_COUNTERS };
    dispatch.pmu.pmuRead(&ps.arch_state, &sample);

    const n = @min(out_values.len, ps.arch_state.num_counters);
    var i: usize = 0;
    while (i < n) {
        out_values[i] = sample.counters[i];
        i += 1;
    }
    while (i < out_values.len) {
        out_values[i] = 0;
        i += 1;
    }

    out_timestamp.* = dispatch.time.currentMonotonicNs();
    return 0;
}

/// Stop the hardware counters for `ps` and clear its visible state.
/// The slab slot itself is freed via `release`.
fn stopCounters(ps: *PerfmonState) void {
    dispatch.pmu.pmuStop(&ps.arch_state);
    ps.active_counters = 0;
    ps.has_threshold = 0;
    var i: usize = 0;
    while (i < MAX_COUNTERS) {
        ps.counter_events[i] = 0;
        ps.counter_thresholds[i] = 0;
        i += 1;
    }
}

/// Per-arch PMU ISR entry. Routes the overflow to the EC's
/// `event_routes[pmu_overflow]` via `port.firePmuOverflow`. Carries
/// the index of the first overflowing counter as the spec subcode.
/// Spec §[execution_context].perfmon_*.
pub fn handleOverflow(ec: *ExecutionContext, overflow_mask: u32) void {
    if (overflow_mask == 0) return;
    const counter_idx: u64 = @intCast(@ctz(overflow_mask));
    port.firePmuOverflow(ec, counter_idx);
}
