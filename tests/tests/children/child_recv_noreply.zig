const lib = @import("lib");

const syscall = lib.syscall;

/// Receives an IPC message but never replies, then blocks forever.
/// The caller becomes pending_caller, stuck until this process is killed.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    // Don't reply — caller stays as pending_caller.
    // Block forever so parent must kill us.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
