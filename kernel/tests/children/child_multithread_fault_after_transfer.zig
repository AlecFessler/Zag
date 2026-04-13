const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

fn worker() void {
    // Worker thread — loops yielding. Will be suspended by stop-all on fault.
    var i: u32 = 0;
    while (i < 1_000_000) : (i += 1) {
        syscall.thread_yield();
    }
    syscall.thread_exit();
}

/// Receives IPC, replies with HANDLE_SELF via cap transfer with fault_handler bit set,
/// spawns a worker thread, then triggers a null dereference fault on the main thread.
/// The worker thread should be suspended by stop-all when the main thread faults.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Spawn a worker thread before faulting.
    _ = syscall.thread_create(&worker, 0, 4);

    // Yield a few times to ensure the worker is running and the parent
    // has processed the cap transfer reply.
    for (0..10) |_| syscall.thread_yield();

    // Trigger a null dereference fault on the main thread.
    lib.fault.nullDeref();
}
