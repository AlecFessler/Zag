const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// IPC server that crashes after first recv on first boot, then works normally after restart.
/// Uses its own perm_view slot 0 to detect restart.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const self_entry = view[0];
    const restart_count = self_entry.processRestartCount();

    if (restart_count == 0) {
        // First boot: recv one message but exit without replying.
        // The pending_caller gets re-enqueued in the wait list on restart.
        var msg: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &msg);
        _ = recv_rc;
        // Exit without replying — triggers restart, pending_caller re-queued
        return;
    } else {
        // After restart: recv again — the caller should be back in the wait list
        var msg: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &msg);
        if (recv_rc != 0) return;

        // Reply with first word + 100 to indicate we're the restarted instance
        msg.words[0] += 100;
        _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
    }
}
