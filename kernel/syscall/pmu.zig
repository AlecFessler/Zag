//! Cross-arch PMU type definitions used by the `perfmon_*` syscall
//! surface and consumed by both `kernel/sched/perfmon.zig` and the
//! per-arch PMU backends through `kernel/arch/dispatch/pmu.zig`.
//!
//! Lives under `kernel/syscall/` because the contract these types
//! describe is the userspace-visible one defined by Spec
//! §[execution_context].perfmon_*. The arch backends and the
//! per-EC perfmon state both depend on this module rather than each
//! other so the dependency graph stays acyclic.

/// Maximum hardware PMU counters the kernel exposes. Intel/AMD generic
/// counters and ARMv8-A both top out near or below this; sizing it as a
/// power-of-two compile-time constant lets `PmuSample.counters` and the
/// per-EC `PerfmonState` arrays stay inline. Spec
/// §[execution_context].perfmon_info caps `num_counters` at 8 implicitly
/// via the bits-0-7 layout but the supported-event count is the binding
/// upper bound here.
pub const MAX_COUNTERS: u8 = 8;

/// Cross-arch PMU event identifier. Numeric values match the supported-
/// event bit indices reported by `perfmon_info` per Spec
/// §[execution_context].perfmon_info, which userspace also passes back
/// in the low byte of every `perfmon_start` config word.
pub const PmuEvent = enum(u8) {
    cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_cycles_frontend = 7,
    stalled_cycles_backend = 8,
};

/// One decoded `perfmon_start` counter config. The kernel-visible form
/// of the (config_event, config_threshold) pair documented in Spec
/// §[execution_context].perfmon_start.
///
/// `has_threshold` mirrors bit 8 of the config_event word; the arch
/// backend uses it to decide whether to enable PMI delivery and seed
/// the counter with a `(span - threshold)` preload so the next
/// overflow fires at the requested cumulative count.
pub const PmuCounterConfig = extern struct {
    event: PmuEvent,
    has_threshold: bool = false,
    _pad: [6]u8 = .{0} ** 6,
    overflow_threshold: u64 = 0,
};

/// Snapshot of the active counter values returned by `pmuRead` and
/// surfaced to userspace by `perfmon_read` per Spec
/// §[execution_context].perfmon_read. Slots beyond
/// `PmuState.num_counters` are zero.
pub const PmuSample = struct {
    counters: [MAX_COUNTERS]u64 = [_]u64{0} ** MAX_COUNTERS,
};

/// Hardware PMU capability descriptor returned by `pmuGetInfo`. Maps
/// directly onto the `perfmon_info` syscall return shape (Spec
/// §[execution_context].perfmon_info): `num_counters` and
/// `overflow_support` pack into the caps_word; `supported_events` is
/// the bitmask whose bit indices match `PmuEvent` enum values.
pub const PmuInfo = struct {
    num_counters: u8,
    supported_events: u64,
    overflow_support: bool,
};
