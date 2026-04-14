const lib = @import("lib");

const syscall = lib.syscall;

/// Receives IPC with escalated rights bits in word[0], tries proc_create with those
/// rights using perm_view as a dummy ELF buffer, replies with the return code.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const escalated_rights = msg.words[0];
    // Use perm_view as a readable buffer for the ELF pointer (will fail ELF parse,
    // but the permission subset check fires before ELF parsing).
    const ret = syscall.proc_create(perm_view_addr, 4096, escalated_rights);
    _ = syscall.ipc_reply(&.{@bitCast(ret)});
}
