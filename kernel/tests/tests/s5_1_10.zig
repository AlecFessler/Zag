const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.10 — `clock_setwall` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Root service has set_time right, so this should succeed.
    const current = syscall.clock_getwall();
    const rc = syscall.clock_setwall(@bitCast(current));
    t.expectEqual("§5.1.10", syscall.E_OK, rc);
    syscall.shutdown();
}
