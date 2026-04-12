const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.2.76 — `set_priority` with an invalid priority value returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret1 = syscall.set_priority(5);
    t.expectEqual("§2.2.76 priority=5", E_INVAL, ret1);
    const ret2 = syscall.set_priority(0xFF);
    t.expectEqual("§2.2.76 priority=0xFF", E_INVAL, ret2);
    syscall.shutdown();
}
