const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

const ITERATIONS: u32 = 5000;

const Shared = struct {
    futex_val: u64 = 0,
    wake_timestamp: u64 = 0,
    measured_delta: u64 = 0,
    waiter_ready: u64 = 0,
    waiter_done: u64 = 0,
    exit: u64 = 0,
};

var shared: Shared = .{};

/// Measures cross-core futex wake latency.
/// Thread B (core 1) futex_waits. Thread A (core 0) stores TSC, futex_wakes.
/// Thread B reads TSC on wake, stores delta.
pub fn main(_: u64) void {
    shared = .{};

    const rc = syscall.thread_create(&waiterEntry, 0, 4);
    if (rc < 0) {
        syscall.write("[PERF] futex_wake SKIP thread_create failed\n");
        syscall.shutdown();
    }

    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] futex_wake SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // Warmup
    var w: u32 = 0;
    while (w < 500) {
        while (@atomicLoad(u64, &shared.waiter_ready, .acquire) == 0) {
            syscall.thread_yield();
        }
        @atomicStore(u64, &shared.waiter_ready, 0, .release);
        @atomicStore(u64, &shared.wake_timestamp, bench.rdtscp(), .release);
        @atomicStore(u64, &shared.futex_val, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&shared.futex_val), 1);
        while (@atomicLoad(u64, &shared.waiter_done, .acquire) == 0) {
            syscall.thread_yield();
        }
        @atomicStore(u64, &shared.waiter_done, 0, .release);
        @atomicStore(u64, &shared.futex_val, 0, .release);
        w += 1;
    }

    // Measurement
    var i: u32 = 0;
    while (i < ITERATIONS) {
        while (@atomicLoad(u64, &shared.waiter_ready, .acquire) == 0) {
            syscall.thread_yield();
        }
        @atomicStore(u64, &shared.waiter_ready, 0, .release);

        @atomicStore(u64, &shared.wake_timestamp, bench.rdtscp(), .release);
        @atomicStore(u64, &shared.futex_val, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&shared.futex_val), 1);

        while (@atomicLoad(u64, &shared.waiter_done, .acquire) == 0) {
            syscall.thread_yield();
        }
        buf[i] = @atomicLoad(u64, &shared.measured_delta, .acquire);
        @atomicStore(u64, &shared.waiter_done, 0, .release);
        @atomicStore(u64, &shared.futex_val, 0, .release);
        i += 1;
    }

    @atomicStore(u64, &shared.exit, 1, .release);
    @atomicStore(u64, &shared.futex_val, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&shared.futex_val), 1);

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report("futex_wake", result);
    syscall.shutdown();
}

fn waiterEntry() void {
    _ = syscall.set_affinity(2);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    while (@atomicLoad(u64, &shared.exit, .acquire) == 0) {
        @atomicStore(u64, &shared.waiter_ready, 1, .release);
        _ = syscall.futex_wait(@ptrCast(&shared.futex_val), 0, ~@as(u64, 0));

        if (@atomicLoad(u64, &shared.exit, .acquire) != 0) break;

        const woke_at = bench.rdtscp();
        const wake_ts = @atomicLoad(u64, &shared.wake_timestamp, .acquire);
        @atomicStore(u64, &shared.measured_delta, woke_at -% wake_ts, .release);
        @atomicStore(u64, &shared.waiter_done, 1, .release);
    }

    syscall.thread_exit();
}
