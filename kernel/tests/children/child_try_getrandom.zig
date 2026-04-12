const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without any ProcessRights bits. Calls `getrandom`
/// and reports the return code to the parent via IPC.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    var buf: [32]u8 = undefined;
    const rc = syscall.getrandom(&buf, 32);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
