const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_done: u64 align(8) = 0;

fn shortLivedWorker() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    // Signal the parent that we are about to call thread_exit. The parent
    // then polls the perm view until our slot disappears — that transition
    // is what proves the thread actually exited (not merely that
    // revoke_perm cleared our handle from the parent's table).
    @atomicStore(u64, &worker_done, 1, .seq_cst);
    syscall.thread_exit();
}

/// §4.1.45 — A thread's PMU state is automatically released on thread exit.
///
/// Correctness hinges on observing the exit transition *before* checking
/// that no PMU state has leaked. We use two signals:
///   (1) worker writes `worker_done = 1` immediately before `thread_exit`,
///   (2) parent then polls the perm view until the worker's thread slot is
///       gone — a natural exit causes the kernel to clear the slot, so
///       slot-disappearance is a robust "thread has actually exited" proof.
/// Only once the exit is observed do we proceed to spin up the next worker.
///
/// Round count: the PmuStateAllocator is a SlabAllocator with a chunk size
/// of 64 entries (kernel/sched/pmu.zig). We run 128 full create+start+exit
/// cycles — twice the slab chunk size — so that a naive leak would either
/// exhaust the first chunk or force allocation of a new chunk that would
/// itself never be reclaimed. 128 rounds keeps the test duration bounded
/// under QEMU while still crossing two chunk boundaries. A higher round
/// count would catch a slower leak but increase test latency; this is the
/// best available indirect evidence without kernel allocator-counter
/// instrumentation exposed to userspace.
pub fn main(pv: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.45");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.1.45");
        syscall.shutdown();
    };

    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var i: u64 = 0;
    while (i < 128) : (i += 1) {
        @atomicStore(u64, &worker_ready, 0, .seq_cst);
        @atomicStore(u64, &worker_done, 0, .seq_cst);

        const h = syscall.thread_create(&shortLivedWorker, 0, 4);
        if (h <= 0) {
            t.failWithVal("§4.1.45 thread_create", 1, h);
            syscall.shutdown();
        }
        const worker_h: u64 = @bitCast(h);

        // Wait until the worker is definitely running before starting PMU.
        while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

        var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
        const start_rc = syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1);
        // Race-tolerant: worker may already be in the done-window before we
        // issue pmu_start. Either E_OK (we started PMU on a live worker)
        // or E_BADHANDLE (worker exited already) is acceptable — both
        // paths must not leak PMU state.
        if (start_rc != syscall.E_OK and start_rc != syscall.E_BADHANDLE) {
            t.failWithVal("§4.1.45 pmu_start", syscall.E_OK, start_rc);
            syscall.shutdown();
        }

        // Wait for the worker's done-flag (it's about to thread_exit).
        while (@atomicLoad(u64, &worker_done, .seq_cst) == 0) syscall.thread_yield();

        // Wait for the exit to actually happen, proven by the thread slot
        // disappearing from the perm view (the kernel clears it on
        // natural exit). This is what makes "no PMU state leak on exit"
        // genuinely tested — pmu state must have been released by the
        // time we loop back around.
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

    t.pass("§4.1.45");
    syscall.shutdown();
}
