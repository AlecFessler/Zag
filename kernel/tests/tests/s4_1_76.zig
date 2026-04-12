const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.1.76 — `fault_set_thread_mode` with invalid or wrong-type `thread_handle` returns `E_BADHANDLE`
pub fn main(_: u64) void {
    // Test with a garbage handle value.
    const ret1 = syscall.fault_set_thread_mode(0xDEADBEEF, syscall.FAULT_MODE_STOP_ALL);
    t.expectEqual("§4.1.76 garbage handle", E_BADHANDLE, ret1);

    // Test with HANDLE_SELF (slot 0 = process handle, wrong type).
    const ret2 = syscall.fault_set_thread_mode(0, syscall.FAULT_MODE_STOP_ALL);
    t.expectEqual("§4.1.76 wrong type (process)", E_BADHANDLE, ret2);

    syscall.shutdown();
}
