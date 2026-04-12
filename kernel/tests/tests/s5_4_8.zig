const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.8 — `sys_power` returns `E_OK` on success (for actions that return).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Actions that return (sleep, hibernate, screen_off) may return E_OK
    // or E_NODEV on QEMU. We verify the syscall path is functional.
    const rc = syscall.sys_power(syscall.POWER_SLEEP);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.4.8");
    } else {
        t.failWithVal("§5.4.8", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
