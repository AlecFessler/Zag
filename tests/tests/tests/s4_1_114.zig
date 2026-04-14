const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_exit: u64 align(8) = 0;
var worker_done: u64 align(8) = 0;

fn shortWorker() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_exit, .seq_cst) == 0) syscall.thread_yield();
    // Signal "about to exit" immediately before the syscall so the parent
    // can poll the perm view for actual slot removal.
    @atomicStore(u64, &worker_done, 1, .seq_cst);
    syscall.thread_exit();
}

/// §4.1.114 — A thread's PMU state is automatically released on thread exit, so an explicit `pmu_stop` is not required before exit.
///
/// INDIRECT EVIDENCE: we cannot directly observe allocator state from
/// userspace, so we loop 16 times, each iteration creating a worker,
/// starting PMU on it, letting it exit without calling `pmu_stop`, then
/// on the next iteration starting PMU on a fresh worker in the same
/// process. A naive leak where PMU state outlives the thread entry
/// would break on the second iteration (or soon after) because
/// `pmu_start` would either refuse to rebind a stuck slab entry or
/// eventually return `E_NOMEM` as the allocator is consumed. Successful
/// completion of all 16 iterations is therefore indirect but reasonably
/// strong evidence of auto-release, given that kernel allocator
/// instrumentation is not exposed to userspace.
///
/// The per-worker observable is still the perm-view thread-slot
/// disappearance: natural exit clears the slot.
pub fn main(pv: u64) void {
    const pmu = t.requirePmu("§4.1.114");

    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var iter: u64 = 0;
    while (iter < 16) : (iter += 1) {
        @atomicStore(u64, &worker_ready, 0, .seq_cst);
        @atomicStore(u64, &worker_exit, 0, .seq_cst);
        @atomicStore(u64, &worker_done, 0, .seq_cst);

        const h = syscall.thread_create(&shortWorker, 0, 4);
        if (h <= 0) {
            t.failWithVal("§4.1.114 thread_create", 1, h);
            syscall.shutdown();
        }
        const worker_h: u64 = @bitCast(h);
        while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

        // Remote pmu_start requires target to be .faulted or .suspended.
        // The worker spins on worker_exit so suspend/resume is deterministic.
        if (syscall.thread_suspend(worker_h) != syscall.E_OK) {
            t.fail("§4.1.114 thread_suspend pre-start");
            syscall.shutdown();
        }
        var cfg = syscall.PmuCounterConfig{ .event = pmu.event, .has_threshold = false, .overflow_threshold = 0 };
        const start_rc = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
        if (start_rc != syscall.E_OK) {
            // A leak from a prior iteration would typically surface here
            // as E_NOMEM or as the kernel refusing to rebind a stuck
            // slab entry.
            t.failWithVal("§4.1.114 pmu_start", syscall.E_OK, start_rc);
            syscall.shutdown();
        }
        _ = syscall.thread_resume(worker_h);

        // Tell worker to exit. The kernel must free its PMU state without
        // requiring an explicit pmu_stop.
        @atomicStore(u64, &worker_exit, 1, .seq_cst);

        // Wait for the worker's done-flag (it is about to call thread_exit).
        while (@atomicLoad(u64, &worker_done, .seq_cst) == 0) syscall.thread_yield();

        // Wait for the exit to actually take effect: the thread's perm
        // slot is cleared on natural exit, so slot disappearance is our
        // observable proof the exit happened.
        while (true) {
            var still_present = false;
            for (0..128) |j| {
                if (view[j].entry_type == perm_view.ENTRY_TYPE_THREAD and view[j].handle == worker_h) {
                    still_present = true;
                    break;
                }
            }
            if (!still_present) break;
            syscall.thread_yield();
        }
    }

    t.pass("§4.1.114");
    syscall.shutdown();
}
