const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

var ready: u64 = 0;

fn blocking_recv() void {
    @atomicStore(u64, &ready, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&ready), 1);
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
}

/// §2.11.14 — Only one thread per process may be blocked on `recv` at a time; a second thread gets `E_BUSY`.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&blocking_recv, 0, 4);
    t.waitUntilNonZero(&ready);
    syscall.thread_yield();
    syscall.thread_yield();
    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(false, &msg);
    t.expectEqual("§2.11.14", E_BUSY, rc);
    syscall.shutdown();
}
