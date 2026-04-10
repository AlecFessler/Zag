const lib = @import("lib");

const syscall = lib.syscall;

/// Receives a target priority via IPC word[0], calls set_priority, replies with result.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const priority = msg.words[0];
    const result = syscall.set_priority(priority);
    _ = syscall.ipc_reply(&.{@bitCast(result)});
}
