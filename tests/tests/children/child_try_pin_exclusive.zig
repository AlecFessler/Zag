const lib = @import("lib");

const syscall = lib.syscall;

/// Sets single-core affinity, tries set_priority(PINNED), and reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.set_affinity(0b10);
    syscall.thread_yield();
    const rc = syscall.set_priority(syscall.PRIORITY_PINNED);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
