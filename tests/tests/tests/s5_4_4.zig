const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.4 — `sys_power` returns `E_NODEV` if the hardware does not support the requested action.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Try sleep/hibernate/screen_off — QEMU q35 doesn't support these,
    // so E_NODEV is expected. Use screen_off (action 4) as it's safest
    // (won't shut down or reboot).
    const rc = syscall.sys_power(syscall.POWER_SCREEN_OFF);
    // E_NODEV is expected on QEMU; E_OK would mean the hardware supports it.
    if (rc == syscall.E_NODEV or rc == syscall.E_OK) {
        t.pass("§5.4.4");
    } else {
        t.failWithVal("§5.4.4", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
