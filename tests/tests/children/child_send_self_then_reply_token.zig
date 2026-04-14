const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

const TOKEN: u64 = 0x5E1F_CA11_DEAD_BEEF;

/// Receives an IPC call, replies with HANDLE_SELF via cap transfer (so the
/// caller now holds a second process handle to us). Then receives ANOTHER
/// call through the new handle and replies with a fixed token. Used by
/// §2.3.18 to prove the transferred HANDLE_SELF actually lets the recipient
/// address us.
pub fn main(_: u64) void {
    var msg1: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg1);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{TOKEN});

    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
