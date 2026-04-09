const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.14.5 — `set_affinity` with an invalid or wrong-type `thread_handle` returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    // Test with a garbage handle value.
    const ret1 = syscall.set_affinity_thread(0xDEAD, 0b1);
    t.expectEqual("§4.14.5 garbage handle", E_BADHANDLE, ret1);

    // Test with HANDLE_SELF (slot 0 = process handle, wrong type).
    const ret2 = syscall.set_affinity_thread(0, 0b1);
    t.expectEqual("§4.14.5 wrong type (process)", E_BADHANDLE, ret2);

    syscall.shutdown();
}
