const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.62.5 — `sys_cpu_power` with `set_idle` uses `value` as the maximum C-state level.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support C-state control, so E_NODEV is expected.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_IDLE, 2);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§4.62.5");
    } else {
        t.failWithVal("§4.62.5", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
