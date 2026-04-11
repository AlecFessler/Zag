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

/// §4.54.6 — A thread's PMU state is automatically released on thread exit, so an explicit `pmu_stop` is not required before exit.
///
/// To make this assertion observable we wait for the worker to actually
/// exit (its perm view thread slot is cleared on natural exit) before
/// concluding success. Simply calling `revoke_perm` in a loop would clear
/// the parent's handle immediately without ever observing the exit
/// transition.
pub fn main(pv: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.54.6");
        syscall.shutdown();
    }

    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const h = syscall.thread_create(&shortWorker, 0, 4);
    const worker_h: u64 = @bitCast(h);
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = .cycles, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.54.6 pmu_start");
        syscall.shutdown();
    }

    // Tell worker to exit. The kernel must free its PMU state without
    // requiring an explicit pmu_stop.
    @atomicStore(u64, &worker_exit, 1, .seq_cst);

    // Wait for the worker's done-flag (it is about to call thread_exit).
    while (@atomicLoad(u64, &worker_done, .seq_cst) == 0) syscall.thread_yield();

    // Now wait for the exit to actually take effect: the thread's perm
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

    t.pass("§4.54.6");
    syscall.shutdown();
}
