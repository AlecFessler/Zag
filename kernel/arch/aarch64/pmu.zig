//! aarch64 PMU stubs (unimplemented).
//!
//! Per systems.md §pmu "aarch64 Stub Policy": the stub exists so
//! `kernel/arch/dispatch.zig` comptime switches compile on aarch64 and so
//! the PMU syscalls return `E_INVAL` cleanly instead of `@compileError`-ing
//! the build. Because `pmuGetInfo` reports `num_counters = 0`, the generic
//! syscall layer rejects every `pmu_start` call at validation time, and the
//! allocation path plus all arch hardware entry points here are statically
//! unreachable.

const zag = @import("zag");

const pmu = zag.syscall.pmu;

/// Stub PMU state. Must be large enough for the slab allocator's intrusive
/// freelist node (24 bytes in Debug: magic + next + base pointer).
pub const PmuState = extern struct {
    _reserved: [4]u64 = .{ 0, 0, 0, 0 },
};

pub fn pmuInit() void {}

pub fn pmuPerCoreInit() void {}

pub fn pmuGetInfo() pmu.PmuInfo {
    return .{
        .num_counters = 0,
        .supported_events = 0,
        .overflow_support = false,
    };
}

pub fn pmuSave(state: *PmuState) void {
    _ = state;
    unreachable;
}

pub fn pmuRestore(state: *PmuState) void {
    _ = state;
    unreachable;
}

pub fn pmuStart(state: *PmuState, configs: []const pmu.PmuCounterConfig) !void {
    _ = state;
    _ = configs;
    unreachable;
}

pub fn pmuRead(state: *PmuState, sample: *pmu.PmuSample) void {
    _ = state;
    _ = sample;
    unreachable;
}

pub fn pmuReset(state: *PmuState, configs: []const pmu.PmuCounterConfig) !void {
    _ = state;
    _ = configs;
    unreachable;
}

pub fn pmuStop(state: *PmuState) void {
    _ = state;
    unreachable;
}

pub fn pmuConfigureState(state: *PmuState, configs: []const pmu.PmuCounterConfig) void {
    _ = state;
    _ = configs;
    unreachable;
}

pub fn pmuClearState(state: *PmuState) void {
    _ = state;
    unreachable;
}
