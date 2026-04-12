const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.1 — `sys_info` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    const rc = syscall.sys_info(@intFromPtr(&info), 0);
    t.expectEqual("§4.55.1", syscall.E_OK, rc);
    syscall.shutdown();
}
