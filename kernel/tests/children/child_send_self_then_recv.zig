const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives a call from parent, replies with HANDLE_SELF (limited rights: send_words + grant only).
/// Then blocks on recv so parent can attempt send/call cap transfer to us.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });
    // Block on recv — parent can now send/call to us via the limited handle
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});
    // Block forever
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
