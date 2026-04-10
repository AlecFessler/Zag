const lib = @import("lib");

const syscall = lib.syscall;

/// Receives an IPC ping, then calls `thread_kill(thread_self())` and reports
/// the return code to the caller. Used by §4.32.2 to exercise the E_PERM
/// branch: the child is spawned with ThreadHandleRights.kill = false so the
/// self-kill attempt must fail with E_PERM.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const self_h = syscall.thread_self();
    if (self_h < 0) {
        _ = syscall.ipc_reply(&.{@bitCast(self_h)});
        return;
    }
    const rc = syscall.thread_kill(@bitCast(self_h));
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
