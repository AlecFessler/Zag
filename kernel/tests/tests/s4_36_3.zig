const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.36.3 — `fault_write_mem` with invalid or wrong-type `proc_handle` returns `E_BADHANDLE`
pub fn main(_: u64) void {
    var buf: [8]u8 = .{0} ** 8;

    // Test with a garbage handle value.
    const ret1 = syscall.fault_write_mem(0xDEADBEEF, 0x1000, @intFromPtr(&buf), 8);
    t.expectEqual("§4.36.3 garbage handle", E_BADHANDLE, ret1);

    // Test with a thread handle (wrong type).
    const self_thread = syscall.thread_self();
    if (self_thread > 0) {
        const ret2 = syscall.fault_write_mem(@bitCast(self_thread), 0x1000, @intFromPtr(&buf), 8);
        t.expectEqual("§4.36.3 wrong type (thread)", E_BADHANDLE, ret2);
    } else {
        t.fail("§4.36.3 could not get thread_self");
    }

    syscall.shutdown();
}
