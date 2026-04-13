const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;
const t = lib.testing;

const ITERATIONS: u32 = 1000;

/// Measures thread creation cost.
/// Each iteration creates a thread that immediately writes its TSC
/// and exits. Parent measures from before thread_create to child's
/// first TSC reading.
pub fn main(_: u64) void {
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    var shared = Shared{};

    // Warmup
    var w: u32 = 0;
    while (w < 100) {
        @atomicStore(u64, &shared.child_timestamp, 0, .release);
        _ = syscall.thread_create(&childEntry, @intFromPtr(&shared), 4);
        while (@atomicLoad(u64, &shared.child_timestamp, .acquire) == 0) {
            syscall.thread_yield();
        }
        w += 1;
    }

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] thread_create SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var i: u32 = 0;
    while (i < ITERATIONS) {
        @atomicStore(u64, &shared.child_timestamp, 0, .release);
        const t0 = bench.rdtscp();
        const rc = syscall.thread_create(&childEntry, @intFromPtr(&shared), 4);
        if (rc < 0) break;
        while (@atomicLoad(u64, &shared.child_timestamp, .acquire) == 0) {
            syscall.thread_yield();
        }
        buf[i] = @atomicLoad(u64, &shared.child_timestamp, .acquire) -% t0;
        i += 1;
    }

    if (i > 0) {
        const result = bench.computeStats(buf[0..i], @intCast(i));
        bench.report("thread_create", result);
    }
    syscall.shutdown();
}

const Shared = struct {
    child_timestamp: u64 = 0,
};

fn childEntry() void {
    const shared: *Shared = @ptrFromInt(asm volatile (""
        : [ret] "={rdi}" (-> u64),
    ));

    @atomicStore(u64, &shared.child_timestamp, bench.rdtscp(), .release);
    _ = syscall.futex_wake(@ptrCast(&shared.child_timestamp), 1);
    syscall.thread_exit();
}
