const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.16 — `sys_cpu_power` with an invalid `action` value returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rc = syscall.sys_cpu_power(0xFF, 0);
    t.expectEqual("§5.4.16", syscall.E_INVAL, rc);
    syscall.shutdown();
}
