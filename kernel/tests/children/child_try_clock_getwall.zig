const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without any ProcessRights bits. Calls `clock_getwall`
/// and reports the return code to the parent via IPC.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const rc = syscall.clock_getwall();
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
