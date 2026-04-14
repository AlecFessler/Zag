const lib = @import("lib");

const syscall = lib.syscall;

/// Receives IPC from parent, calls fault_recv (non-blocking), and replies with the result.
/// Used to test E_PERM when the child has no fault_handler rights.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    // Call fault_recv non-blocking — expect E_PERM since we have no fault_handler.
    var fault_msg: syscall.FaultMessage = undefined;
    const rc = syscall.fault_recv(@intFromPtr(&fault_msg), 0);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
