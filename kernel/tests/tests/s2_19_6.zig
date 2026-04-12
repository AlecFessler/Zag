const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.19.6 — `sys_cpu_power` with `set_idle` sets the maximum C-state idle level for the calling core.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support C-state control, so E_NODEV is expected.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_IDLE, 1);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§2.19.6");
    } else {
        t.failWithVal("§2.19.6", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
