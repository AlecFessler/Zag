const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

/// Measures clock_gettime() syscall overhead.
/// Comparison with syscall_yield shows the cost of the HPET register read.
pub fn main(_: u64) void {
    _ = bench.runBench(.{
        .name = "clock_gettime",
        .warmup = 1000,
        .iterations = 10000,
        .pmu_events = &.{ .cycles, .instructions, .cache_misses },
    }, clockOnce);
    syscall.shutdown();
}

fn clockOnce() void {
    _ = syscall.clock_gettime();
}
