const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn childFn() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.2.22 — `thread_resume` on a thread not in `.suspended` state returns `E_INVAL`
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.22 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let the child start running/become ready.
    syscall.thread_yield();

    // Attempt to resume a thread that is not suspended (it is ready/running).
    const r = syscall.thread_resume(handle);
    const E_INVAL: i64 = -1;
    if (r == E_INVAL) {
        t.pass("§2.2.22");
    } else {
        t.failWithVal("§2.2.22", E_INVAL, r);
    }
    syscall.shutdown();
}
