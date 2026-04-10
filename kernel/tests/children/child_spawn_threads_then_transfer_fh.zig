const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

fn worker() void {
    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}

/// Spawns THREE worker threads (so the process has 4 total including main)
/// and THEN receives IPC and cap-transfers HANDLE_SELF + fault_handler.
/// Per §2.12.4, the acquirer's perm table should receive thread handles for
/// ALL four threads at cap-transfer time.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&worker, 0, 4);
    _ = syscall.thread_create(&worker, 0, 4);
    _ = syscall.thread_create(&worker, 0, 4);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}
