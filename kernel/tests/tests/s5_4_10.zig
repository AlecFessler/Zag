const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.10 — `sys_power` with an invalid `action` value returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Use an action value that doesn't correspond to any valid power action.
    const rc = syscall.sys_power(0xFF);
    t.expectEqual("§5.4.10", syscall.E_INVAL, rc);
    syscall.shutdown();
}
