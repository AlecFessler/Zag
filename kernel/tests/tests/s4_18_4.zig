const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

var sibling_about_to_recv: u64 align(8) = 0;

fn blocking_recv() void {
    var msg: syscall.IpcMessage = .{};
    // Signal the main thread via a futex that we are about to enter ipc_recv.
    // This is a best-effort handshake: main blocks on the futex until it
    // observes the signal, then yields once more to let this thread actually
    // cross into the kernel. Without the handshake, a pure yield-spin races.
    @atomicStore(u64, &sibling_about_to_recv, 1, .release);
    _ = syscall.futex_wake(&sibling_about_to_recv, 1);
    // Blocks forever (no one sends to us).
    _ = syscall.ipc_recv(true, &msg);
}

/// §4.18.4 — `recv` with another thread already blocked returns `E_BUSY`.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&blocking_recv, 0, 4);
    // Wait for the sibling's futex handshake — guarantees the sibling has
    // reached the line immediately before `ipc_recv`.
    t.waitUntilNonZero(&sibling_about_to_recv);
    // Give the sibling a few yields to cross into the kernel and register
    // as the blocking receiver before we race it.
    for (0..20) |_| syscall.thread_yield();

    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(false, &msg);
    t.expectEqual("§4.18.4", E_BUSY, rc);
    syscall.shutdown();
}
