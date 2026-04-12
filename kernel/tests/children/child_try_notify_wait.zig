const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without any ProcessRights bits. Calls `notify_wait`
/// with timeout 0 (non-blocking) and reports the return code to the
/// parent via IPC. Expected: E_AGAIN (no pending notifications).
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const rc = syscall.notify_wait(0);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
