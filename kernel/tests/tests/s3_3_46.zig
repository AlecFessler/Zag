const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §3.3.46 — `recv` non-blocking with no message returns `E_AGAIN`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    var msg: syscall.IpcMessage = .{};
    const ret = syscall.ipc_recv(false, &msg);
    t.expectEqual("§3.3.46", E_AGAIN, ret);
    syscall.shutdown();
}
