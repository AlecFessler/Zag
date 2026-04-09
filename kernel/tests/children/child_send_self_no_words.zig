const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC, replies with HANDLE_SELF but WITHOUT send_words right.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    // Reply with HANDLE_SELF — grant kill+grant but NOT send_words
    const rights: u64 = (perms.ProcessHandleRights{
        .kill = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });
    // Stay alive so the handle remains valid
    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}
