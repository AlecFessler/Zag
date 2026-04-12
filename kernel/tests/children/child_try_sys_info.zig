const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without any ProcessRights bits. Calls `sys_info`
/// (§4.55.2 says the syscall is callable by any process regardless
/// of rights) and reports the return code to the parent.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    var info: syscall.SysInfo = undefined;
    const rc = syscall.sys_info(@intFromPtr(&info), 0);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
