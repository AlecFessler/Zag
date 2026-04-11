const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn shortLivedWorker() void {
    // Worker immediately exits — kernel must free any PMU state automatically.
    syscall.thread_exit();
}

/// §2.14.9 — A thread's PMU state is automatically released on thread exit.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§2.14.9");
        syscall.shutdown();
    }

    // Spin up 32 worker threads, start PMU on each, and let them exit.
    // If thread exit leaked PMU state, PmuStateAllocator would exhaust
    // long before we shutdown. Successful completion proves auto-release.
    var i: u64 = 0;
    while (i < 32) : (i += 1) {
        const h = syscall.thread_create(&shortLivedWorker, 0, 4);
        if (h <= 0) {
            t.failWithVal("§2.14.9 thread_create", 1, h);
            syscall.shutdown();
        }
        const worker_h: u64 = @bitCast(h);

        var cfg = syscall.PmuCounterConfig{ .event = @intFromEnum(syscall.PmuEvent.cycles) };
        const start_rc = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
        // Might race with the worker exiting — accept either E_OK or
        // E_BADHANDLE (thread already exited). Either way the kernel
        // must not leak.
        if (start_rc != syscall.E_OK and start_rc != syscall.E_BADHANDLE) {
            t.failWithVal("§2.14.9 pmu_start", syscall.E_OK, start_rc);
            syscall.shutdown();
        }

        // Wait for the worker to exit by polling revoke_perm.
        while (syscall.revoke_perm(worker_h) != syscall.E_BADHANDLE) {
            syscall.thread_yield();
        }
    }

    t.pass("§2.14.9");
    syscall.shutdown();
}
