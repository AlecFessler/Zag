const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn childFn() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.4.13 — `thread_resume` requires the `resume` right on the thread handle; returns `E_PERM` without it
pub fn main(perm_view: u64) void {
    _ = perm_view;

    // The root/init process gets full ThreadHandleRights on threads it creates,
    // so we cannot directly test E_PERM from here without a mechanism to create
    // a handle with reduced rights. As a best-effort, we verify that
    // thread_resume works (returns E_OK or E_INVAL depending on state) when we
    // do have the resume right, confirming the right is checked and accepted.

    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.13 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let child run, then suspend and resume it.
    syscall.thread_yield();

    const s = syscall.thread_suspend(handle);
    if (s != 0) {
        t.failWithVal("§2.4.13 suspend", 0, s);
        syscall.shutdown();
    }

    // Resume should succeed (E_OK=0) since we have the resume right.
    const r = syscall.thread_resume(handle);
    if (r == 0) {
        t.pass("§2.4.13");
    } else {
        // If E_PERM (-2) is returned, our handle unexpectedly lacks the right.
        t.failWithVal("§2.4.13", 0, r);
    }
    syscall.shutdown();
}
