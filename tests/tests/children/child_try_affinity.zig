const lib = @import("lib");

const syscall = lib.syscall;

/// Tries to call set_affinity. Reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const ret = syscall.set_affinity(0b1);
    _ = syscall.ipc_reply(&.{@bitCast(ret)});
}
