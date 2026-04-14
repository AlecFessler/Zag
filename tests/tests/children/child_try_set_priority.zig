const lib = @import("lib");

const syscall = lib.syscall;

/// Receives a priority level via IPC word 0, tries set_priority, reports result.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const priority: u64 = msg.words[0];
    const rc = syscall.set_priority(priority);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
