const lib = @import("lib");

const syscall = lib.syscall;

/// Receives a call, tries recv again (should get E_BUSY), replies with the result.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    // pending_reply is now true — try recv again
    var msg2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(false, &msg2);
    // Reply with the result of the second recv
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
