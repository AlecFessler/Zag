const lib = @import("lib");

const syscall = lib.syscall;

/// Receives an IPC call with a device handle cap transfer, replies, then exits.
/// The device handle should return to the parent.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    // Got the device handle via cap transfer. Reply to unblock caller.
    _ = syscall.ipc_reply(&.{});
    // Exit — device handle should return up the process tree.
}
