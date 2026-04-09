const lib = @import("lib");

const syscall = lib.syscall;

fn faulterThread() void {
    // Null pointer dereference — generates a fault routed to our own fault
    // box (we self-handle per §2.12.8).
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true });
    while (true) asm volatile ("pause");
}

/// Verifies §2.12.8 from inside the child:
///   1. Create a second thread that will null-deref.
///   2. Block in fault_recv on our own fault box. If §2.12.8 holds, this
///      returns the faulting thread's token (proving the message was
///      enqueued in our own box and that this main thread continued
///      running rather than being suspended by stop-all).
///   3. Wait for parent IPC and reply with the token so the parent can
///      observe the result.
pub fn main(_: u64) void {
    const tret = syscall.thread_create(&faulterThread, 0, 4);
    if (tret <= 0) {
        var msg: syscall.IpcMessage = .{};
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{@bitCast(@as(i64, -100))});
        return;
    }

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{@bitCast(token)});

    var fv: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&fv), 0, @bitCast(@as(i64, -1)));
}
