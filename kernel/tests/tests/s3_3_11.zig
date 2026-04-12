const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §3.3.11 — `recv` without blocking flag returns `E_AGAIN` when the queue is empty.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(false, &msg);
    t.expectEqual("§3.3.11", E_AGAIN, rc);
    syscall.shutdown();
}
