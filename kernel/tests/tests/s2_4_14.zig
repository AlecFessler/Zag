const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var child_counter: u64 align(8) = 0;

fn childFn() void {
    // Increment counter to prove we resumed and ran.
    @atomicStore(u64, &child_counter, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&child_counter), 1);
    syscall.thread_exit();
}

/// §2.4.14 — `thread_resume` on a `.suspended` thread moves it to `.ready` and re-enqueues it on the scheduler
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.14 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Immediately suspend the child before it runs.
    const s = syscall.thread_suspend(handle);
    if (s != 0) {
        t.failWithVal("§2.4.14 suspend", 0, s);
        syscall.shutdown();
    }

    // Verify it is suspended (state 4) before resuming.
    var suspended = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].threadState() == 4) {
                suspended = true;
            }
            break;
        }
    }
    if (!suspended) {
        t.fail("§2.4.14 not suspended");
        syscall.shutdown();
    }

    // Resume the child.
    const r = syscall.thread_resume(handle);
    if (r != 0) {
        t.failWithVal("§2.4.14 resume", 0, r);
        syscall.shutdown();
    }

    // Wait for the child to run and increment the counter, proving it was
    // re-enqueued on the scheduler.
    t.waitUntilNonZero(&child_counter);

    if (@atomicLoad(u64, &child_counter, .acquire) == 1) {
        t.pass("§2.4.14");
    } else {
        t.fail("§2.4.14");
    }
    syscall.shutdown();
}
