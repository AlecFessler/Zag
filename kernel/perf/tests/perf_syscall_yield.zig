const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

/// Measures null syscall overhead via thread_yield().
/// This is the baseline floor for all syscall measurements.
pub fn main(_: u64) void {
    _ = bench.runBench(.{
        .name = "syscall_yield",
        .warmup = 1000,
        .iterations = 10000,
        .pmu_events = &.{ .cycles, .instructions, .cache_misses },
    }, yieldOnce);
    syscall.shutdown();
}

fn yieldOnce() void {
    syscall.thread_yield();
}
