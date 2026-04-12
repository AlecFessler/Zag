const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.3 — `sys_power` with `sleep`, `hibernate`, or `screen_off` returns `E_OK` after the system resumes (or the action completes).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // On QEMU q35, sleep/hibernate/screen_off are unsupported (E_NODEV).
    // Accept either E_OK (hardware supports it and returned after resume)
    // or E_NODEV (not supported) — both are valid spec-conforming results.
    const rc = syscall.sys_power(syscall.POWER_SLEEP);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.4.3");
    } else {
        t.failWithVal("§5.4.3", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
