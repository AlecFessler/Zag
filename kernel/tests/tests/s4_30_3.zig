const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.30.3 — `thread_suspend` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    // Test with a garbage handle value.
    const ret1 = syscall.thread_suspend(0xDEAD);
    t.expectEqual("§4.30.3 garbage handle", E_BADHANDLE, ret1);

    // Test with HANDLE_SELF (slot 0 = process handle, wrong type for thread_suspend).
    const ret2 = syscall.thread_suspend(0);
    t.expectEqual("§4.30.3 wrong type (process)", E_BADHANDLE, ret2);

    syscall.shutdown();
}
