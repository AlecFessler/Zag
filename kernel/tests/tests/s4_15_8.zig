const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.15.8 — `pin_exclusive` with an invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    // Test with a garbage handle value.
    const ret1 = syscall.pin_exclusive_thread(0xDEAD);
    t.expectEqual("§4.15.8 garbage handle", E_BADHANDLE, ret1);

    // Test with HANDLE_SELF (slot 0 = process handle, wrong type).
    const ret2 = syscall.pin_exclusive_thread(0);
    t.expectEqual("§4.15.8 wrong type (process)", E_BADHANDLE, ret2);

    syscall.shutdown();
}
