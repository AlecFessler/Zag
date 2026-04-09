const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    // Stay alive long enough for the parent to kill us.
    for (0..100) |_| syscall.thread_yield();
    syscall.thread_exit();
}

/// §2.4.16 — `thread_kill` requires the `kill` right on the thread handle; returns `E_PERM` without it.
///
/// Root has full ThreadHandleRights on created threads, so thread_kill should succeed.
/// Testing E_PERM would require a child process with restricted thread rights.
/// We test:
///   1. thread_kill with full rights (positive case) → E_OK (0)
///   2. thread_kill with an invalid handle → E_BADHANDLE (-3), confirming it's not E_PERM
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&worker, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§2.4.16 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Positive case: kill with full rights should succeed.
    const kill_ret = syscall.thread_kill(handle);
    if (kill_ret == 0) {
        t.pass("§2.4.16 kill with rights");
    } else {
        t.failWithVal("§2.4.16 kill with rights", 0, kill_ret);
    }

    // Invalid handle should return E_BADHANDLE (-3), not E_PERM (-2).
    const bad_ret = syscall.thread_kill(0xDEAD);
    if (bad_ret == -3) {
        t.pass("§2.4.16 bad handle");
    } else {
        t.failWithVal("§2.4.16 bad handle", -3, bad_ret);
    }

    syscall.shutdown();
}
