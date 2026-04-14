const lib = @import("lib");

const syscall = lib.syscall;

/// Calls thread_self and reports the result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const handle = syscall.thread_self();
    _ = syscall.ipc_reply(&.{@bitCast(handle)});
}
