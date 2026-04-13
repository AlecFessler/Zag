const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

const ITERATIONS: u32 = 5000;

const Shared = struct {
    partner_ready: u64 = 0,
    timestamp: u64 = 0,
    partner_timestamp: u64 = 0,
    phase: u64 = 0,
    done: u64 = 0,
};

var shared: Shared = .{};

/// Measures context switch cost between two threads on the same core.
/// Thread A writes TSC, yields. Thread B reads A's timestamp and writes
/// its own, yields back. The delta is one yield-to-execute latency
/// (includes syscall entry, scheduler decision, and context switch).
pub fn main(_: u64) void {
    shared = .{};

    const rc = syscall.thread_create(&partnerEntry, 0, 4);
    if (rc < 0) {
        syscall.write("[PERF] ctx_switch SKIP thread_create failed\n");
        syscall.shutdown();
    }

    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    while (@atomicLoad(u64, &shared.partner_ready, .acquire) == 0) {
        syscall.thread_yield();
    }

    // Warmup
    var w: u32 = 0;
    while (w < 500) {
        syscall.thread_yield();
        w += 1;
    }

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] ctx_switch SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var i: u32 = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        @atomicStore(u64, &shared.timestamp, t0, .release);
        @atomicStore(u64, &shared.phase, 1, .release);
        syscall.thread_yield();

        const partner_ts = @atomicLoad(u64, &shared.partner_timestamp, .acquire);
        buf[i] = partner_ts -% t0;
        @atomicStore(u64, &shared.phase, 0, .release);
        i += 1;
    }

    @atomicStore(u64, &shared.done, 1, .release);
    syscall.thread_yield();

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report("ctx_switch", result);
    syscall.shutdown();
}

fn partnerEntry() void {
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    @atomicStore(u64, &shared.partner_ready, 1, .release);

    while (@atomicLoad(u64, &shared.done, .acquire) == 0) {
        if (@atomicLoad(u64, &shared.phase, .acquire) == 1) {
            @atomicStore(u64, &shared.partner_timestamp, bench.rdtscp(), .release);
        }
        syscall.thread_yield();
    }

    syscall.thread_exit();
}
