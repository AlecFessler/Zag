const lib = @import("lib");

const syscall = lib.syscall;

fn noop() void {}

/// Tries thread_create and reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const rc = syscall.thread_create(&noop, 0, 4);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
