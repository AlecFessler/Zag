const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.36.6 — `fault_write_mem` with `len` = 0 returns `E_INVAL`
pub fn main(_: u64) void {
    var buf: [8]u8 = .{0} ** 8;
    // Use HANDLE_SELF (0) as proc_handle. The len=0 check should fire.
    const ret = syscall.fault_write_mem(0, 0x1000, @intFromPtr(&buf), 0);
    t.expectEqual("§4.36.6", E_INVAL, ret);

    syscall.shutdown();
}
