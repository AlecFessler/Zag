const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC with desired max_thread_priority in msg.words[0].
/// Tries proc_create_with_opts using that priority ceiling.
/// Replies with the return code.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const max_priority = msg.words[0];
    // Use our own code address as a readable buffer for the ELF pointer.
    // The priority ceiling check fires before ELF parsing.
    const child_rights = perms.ProcessRights{};
    const rc = syscall.proc_create_with_opts(
        @intFromPtr(&main),
        256,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        max_priority,
    );
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
