const lib = @import("lib");

const syscall = lib.syscall;

/// Receives device via IPC cap transfer, then waits for a second call before exiting.
/// The device handle returns up the process tree on exit.
pub fn main(_: u64) void {
    // 1st recv: device handle via cap transfer.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});
    // 2nd recv: signal to exit.
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{});
    // Exit — device returns up process tree.
}
