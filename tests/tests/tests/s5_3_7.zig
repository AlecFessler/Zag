const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.3.7 — `sys_info` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    const rc = syscall.sys_info(@intFromPtr(&info), 0);
    t.expectEqual("§5.3.7", syscall.E_OK, rc);
    syscall.shutdown();
}
