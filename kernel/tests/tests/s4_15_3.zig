const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.15.3 — For non-pinned levels, `set_priority` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret_high = syscall.set_priority(syscall.PRIORITY_HIGH);
    t.expectEqual("§4.15.3 HIGH", E_OK, ret_high);
    const ret_normal = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectEqual("§4.15.3 NORMAL", E_OK, ret_normal);
    syscall.shutdown();
}
