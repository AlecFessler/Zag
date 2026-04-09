const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;

/// Checks perm_view slot 1 for a thread handle entry and reports via IPC.
/// Optional action in request word 0:
///   0 = none, 1 = thread_suspend(slot1), 2 = thread_resume(slot1)
/// Reply: entry_type, handle, rights, action_rc
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const entry = view[1];
    const action: u64 = if (msg.word_count > 0) msg.words[0] else 0;
    var action_rc: u64 = 0;
    if (action == 1) {
        action_rc = @bitCast(syscall.thread_suspend(entry.handle));
    } else if (action == 2) {
        action_rc = @bitCast(syscall.thread_resume(entry.handle));
    }
    _ = syscall.ipc_reply(&.{ entry.entry_type, entry.handle, entry.rights, action_rc });
}
