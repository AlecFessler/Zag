const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn childFn() void {
    // Spin until suspended by the parent.
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.4.10 — `thread_suspend` on a `.ready` thread removes it from the run queue and enters `.suspended`
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.10 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Yield a few times to let the child start and become ready/running.
    syscall.thread_yield();
    syscall.thread_yield();

    // Suspend the child thread.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret != 0) {
        t.failWithVal("§2.4.10 suspend", 0, suspend_ret);
        syscall.shutdown();
    }

    // Verify thread state is suspended (4) via perm_view.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].threadState() == 4) {
                found = true;
            }
            break;
        }
    }

    if (found) {
        t.pass("§2.4.10");
    } else {
        t.fail("§2.4.10");
    }
    syscall.shutdown();
}
