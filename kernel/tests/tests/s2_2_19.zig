const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn childFn() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §2.2.19 — `thread_suspend` on an already-`.suspended` thread returns `E_BUSY`
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.thread_create(&childFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.19 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let child start running.
    syscall.thread_yield();

    // First suspend should succeed.
    const s1 = syscall.thread_suspend(handle);
    if (s1 != 0) {
        t.failWithVal("§2.2.19 first suspend", 0, s1);
        syscall.shutdown();
    }

    // Second suspend on the already-suspended thread should return E_BUSY.
    const s2 = syscall.thread_suspend(handle);
    const E_BUSY: i64 = -11;
    if (s2 == E_BUSY) {
        t.pass("§2.2.19");
    } else {
        t.failWithVal("§2.2.19", E_BUSY, s2);
    }
    syscall.shutdown();
}
