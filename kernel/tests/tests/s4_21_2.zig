const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.21.2 — `disable_restart` without restart context returns `E_PERM`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // First call removes restart context — must succeed.
    const first = syscall.disable_restart();
    if (first != 0) {
        t.fail("§4.21.2");
        syscall.shutdown();
    }
    // Second call should fail — no restart context.
    const ret = syscall.disable_restart();
    t.expectEqual("§4.21.2", E_PERM, ret);
    syscall.shutdown();
}
