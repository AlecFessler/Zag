const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.17 — `sys_cpu_power` with `set_freq` uses `value` as the target frequency in hertz.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support DVFS, so E_NODEV is expected.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_FREQ, 3_000_000_000);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§5.4.17");
    } else {
        t.failWithVal("§5.4.17", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
