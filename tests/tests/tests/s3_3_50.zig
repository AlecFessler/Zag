const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §3.3.50 — `reply` with no pending message returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.ipc_reply(&.{});
    t.expectEqual("§3.3.50", E_INVAL, ret);
    syscall.shutdown();
}
