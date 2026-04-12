const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var child_counter: u64 align(8) = 0;

fn childFn() void {
    // Increment counter to prove we resumed and ran.
    @atomicStore(u64, &child_counter, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&child_counter), 1);
    syscall.thread_exit();
}

/// §2.2.21 — `thread_resume` on a `.suspended` thread moves it to `.ready` and re-enqueues it on the scheduler
pub fn main(pv: u64) void {
    _ = pv;
    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.21 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Immediately suspend the child before it runs. Success of thread_suspend
    // implies the target transitioned into .suspended (transient state is no
    // longer exposed via the perm view).
    const s = syscall.thread_suspend(handle);
    if (s != 0) {
        t.failWithVal("§2.2.21 suspend", 0, s);
        syscall.shutdown();
    }

    // Resume the child.
    const r = syscall.thread_resume(handle);
    if (r != 0) {
        t.failWithVal("§2.2.21 resume", 0, r);
        syscall.shutdown();
    }

    // Wait for the child to run and increment the counter, proving it was
    // re-enqueued on the scheduler.
    t.waitUntilNonZero(&child_counter);

    if (@atomicLoad(u64, &child_counter, .acquire) == 1) {
        t.pass("§2.2.21");
    } else {
        t.fail("§2.2.21");
    }
    syscall.shutdown();
}
