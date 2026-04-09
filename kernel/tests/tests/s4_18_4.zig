const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

fn blocking_recv() void {
    var msg: syscall.IpcMessage = .{};
    // This blocks forever (no one sends to us).
    _ = syscall.ipc_recv(true, &msg);
}

/// §4.18.4 — `recv` with another thread already blocked returns `E_BUSY`.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&blocking_recv, 0, 4);
    // Give thread time to enter ipc_recv. The thread starts and immediately
    // calls blocking recv. On a 4-core SMP system, it runs concurrently.
    for (0..50) |_| syscall.thread_yield();
    // Try recv from main thread — should get E_BUSY.
    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(false, &msg);
    t.expectEqual("§4.18.4", E_BUSY, rc);
    syscall.shutdown();
}
