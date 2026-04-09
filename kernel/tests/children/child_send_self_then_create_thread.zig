const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

fn dummyThread() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// 1) Receives an IPC and replies with HANDLE_SELF + fault_handler bit set
///    via cap transfer (parent now holds fault_handler over us per §2.12.3).
/// 2) Receives a second IPC, calls thread_create to make a new thread, then
///    replies. The second IPC acts as a barrier so the parent can re-snapshot
///    its perm view after the new thread has been created and inserted.
/// 3) Stays alive so the new thread handle remains valid for inspection.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};

    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    _ = syscall.ipc_recv(true, &msg);
    const r = syscall.thread_create(&dummyThread, 0, 4);
    _ = syscall.ipc_reply(&.{@bitCast(r)});

    var fv: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&fv), 0, @bitCast(@as(i64, -1)));
}
