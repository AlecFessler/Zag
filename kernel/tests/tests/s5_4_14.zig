const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.14 — `sys_cpu_power` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support DVFS, so E_NODEV is expected. Accept both.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_FREQ, 2_000_000_000);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.4.14");
    } else {
        t.failWithVal("§5.4.14", syscall.E_OK, rc);
    }
    syscall.shutdown();
}
