const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.2.79 — `thread_unpin` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;

    // Use a handle value that does not exist.
    const ret1 = syscall.thread_unpin(0xDEAD);
    t.expectEqual("§2.2.79 invalid handle", E_BADHANDLE, ret1);

    // Use handle 0 (HANDLE_SELF, which is a process handle, wrong type).
    const ret2 = syscall.thread_unpin(0);
    t.expectEqual("§2.2.79 wrong type", E_BADHANDLE, ret2);

    syscall.shutdown();
}
