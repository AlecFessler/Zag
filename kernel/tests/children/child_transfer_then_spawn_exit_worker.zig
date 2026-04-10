const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

fn worker() void {
    syscall.thread_exit();
}

/// Receives an IPC call from the parent, replies with HANDLE_SELF via cap
/// transfer with fault_handler bit set (atomically transferring fault
/// handling to the parent per §2.12.3), spawns a worker thread that exits
/// immediately, then sleeps forever on a futex so the parent's handle
/// remains valid.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Spawn a worker thread that exits immediately. Per §2.12.5, this
    // inserts a thread handle into the parent's perm table; per §2.4.6,
    // when the worker exits, the handle is cleared from both this process
    // and the parent's table.
    _ = syscall.thread_create(&worker, 0, 4);

    // Stay alive so our handle in the parent remains valid.
    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}
