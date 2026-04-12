const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without `power` right. Calls `sys_cpu_power` with an
/// invalid action and reports the return code to the parent via IPC.
/// Without the power right, expected result is E_PERM.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const rc = syscall.sys_cpu_power(0xFF, 0);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
