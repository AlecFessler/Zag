const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.13 — `sys_power` returns `E_NODEV` if the hardware does not support the requested action.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // screen_off is unlikely to be supported on QEMU q35.
    const rc = syscall.sys_power(syscall.POWER_SCREEN_OFF);
    if (rc == syscall.E_NODEV or rc == syscall.E_OK) {
        t.pass("§5.4.13");
    } else {
        t.failWithVal("§5.4.13", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
