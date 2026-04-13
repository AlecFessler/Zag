const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;
const t = lib.testing;

/// PMU self-operation benchmark. Measures `pmu_start` + `pmu_stop` as a
/// pair on the caller's own thread — the kernel's self path avoids the
/// remote state-check (kernel/syscall/pmu.zig:145-151, `is_self == true`)
/// and goes straight to `arch.pmuStart` for MSR programming.
///
/// Note: `pmu_stop` at kernel/syscall/pmu.zig:256-263 destroys the
/// pmu_state slot, so each iteration allocates, configures, and frees.
/// This is the "cold-start overhead" — the cost an in-process profiler
/// pays per start/stop cycle. The pure-MSR steady-state "reprogram while
/// already armed" path is not measurable via the public API because
/// `pmu_start` on self with existing state simply overwrites MSRs, and
/// `pmu_read` / `pmu_reset` require .faulted/.suspended state (pmu.zig:180).
///
/// pmu_info is measured separately in perf_syscall_micro.zig.
pub fn main(_: u64) void {
    const pmu = t.requirePmu("perf_pmu_self");
    cached_event = pmu.event;
    cached_self = @bitCast(syscall.thread_self());

    _ = bench.runBench(.{
        .name = "pmu_start_stop_self_cold",
        .warmup = 100,
        .iterations = 2000,
    }, benchStartStop);

    syscall.shutdown();
}

var cached_event: syscall.PmuEvent = .cycles;
var cached_self: u64 = 0;

fn benchStartStop() void {
    var cfg = syscall.PmuCounterConfig{
        .event = cached_event,
        .has_threshold = false,
        .overflow_threshold = 0,
    };
    _ = syscall.pmu_start(cached_self, @intFromPtr(&cfg), 1);
    _ = syscall.pmu_stop(cached_self);
}
