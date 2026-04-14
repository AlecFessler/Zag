const mode = @import("mode.zig");

pub const Kind = enum(u8) {
    trace_enter = 1,
    trace_exit = 2,
    trace_point = 3,
    /// PMU-overflow leaf sample: `ip` is the interrupted RIP/PC; `arg` = 0.
    sample = 4,
    /// Call-chain frame for the preceding `sample` record: `ip` is a
    /// return address walked from the frame-pointer chain; `arg` holds
    /// the 1-based depth (1 = caller of the leaf, 2 = caller's caller, ...).
    sample_frame = 5,
};

/// A single kprof record.
///
/// Layout is conditional on `-Dkernel_profile`:
///
/// * `trace`  — 64 bytes. Carries `tsc`, the usual scope fields, and
///   three free-running PMU counter snapshots (`cycles`,
///   `cache_misses`, `branch_misses`) so post-processing can compute
///   per-scope deltas without a second data stream. `_pad2` rounds
///   the struct up to the 64-byte cache line.
///
/// * `sample` / `none` — 32 bytes. Just the base fields; the three
///   counter fields don't exist in this variant so sample-mode emits
///   don't pay the space cost. Sample records still carry `ip`+`arg`,
///   which is all `parse_kprof` / `flamegraph.py` need.
pub const Record = if (mode.trace_enabled) extern struct {
    tsc: u64,
    kind: u8,
    cpu: u8,
    _pad: u16,
    id: u32,
    ip: u64,
    arg: u64,
    cycles: u64,
    cache_misses: u64,
    branch_misses: u64,
    _pad2: u64,
} else extern struct {
    tsc: u64,
    kind: u8,
    cpu: u8,
    _pad: u16,
    id: u32,
    ip: u64,
    arg: u64,
};

pub const RECORD_SIZE: usize = if (mode.trace_enabled) 64 else 32;

comptime {
    const std = @import("std");
    std.debug.assert(@sizeOf(Record) == RECORD_SIZE);
}
