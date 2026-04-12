const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.2.50 — `thread_suspend` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    // Test with a garbage handle value.
    const ret1 = syscall.thread_suspend(0xDEAD);
    t.expectEqual("§2.2.50 garbage handle", E_BADHANDLE, ret1);

    // Test with HANDLE_SELF (slot 0 = process handle, wrong type for thread_suspend).
    const ret2 = syscall.thread_suspend(0);
    t.expectEqual("§2.2.50 wrong type (process)", E_BADHANDLE, ret2);

    syscall.shutdown();
}
