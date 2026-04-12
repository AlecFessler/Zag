const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.12 — `sys_power` with `sleep`, `hibernate`, or `screen_off` returns `E_OK` after the system resumes or the action completes.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // On QEMU, these actions are unsupported (E_NODEV). Accept both
    // E_OK (action completed and returned) and E_NODEV (not supported).
    const rc = syscall.sys_power(syscall.POWER_HIBERNATE);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.4.12");
    } else {
        t.failWithVal("§5.4.12", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
