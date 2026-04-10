const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

// Thread 1 announces it's about to block, then calls blocking recv.
// Since nothing sends to us, it will stay blocked until shutdown.
var blocked_flag: u64 align(8) = 0;

fn blocking_recv_thread() void {
    // Signal we are about to enter recv.
    @atomicStore(u64, &blocked_flag, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&blocked_flag), 1);
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
}

/// §2.11.14 — Only one thread per process may be blocked on `recv` at a time; a second thread gets `E_BUSY`.
///
/// After the first thread reaches its recv, we also use a *blocking* recv
/// from a second thread and assert that it returns E_BUSY immediately
/// rather than itself blocking.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&blocking_recv_thread, 0, 4);

    // Wait until the other thread reports it is about to recv.
    t.waitUntilNonZero(&blocked_flag);

    // Yield many times to ensure the other thread has actually entered
    // the kernel recv path and installed itself as the blocked receiver.
    for (0..2000) |_| syscall.thread_yield();

    // Second blocking recv — must fail with E_BUSY.
    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(true, &msg);
    t.expectEqual("§2.11.14", E_BUSY, rc);
    syscall.shutdown();
}
