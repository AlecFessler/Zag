const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.19.5 — `sys_cpu_power` with `set_freq` sets the target CPU frequency in hertz.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support DVFS, so E_NODEV is expected.
    // E_OK would mean the frequency was set.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_FREQ, 2_000_000_000);
    if (rc == syscall.E_OK or rc == syscall.E_NODEV) {
        t.pass("§2.19.5");
    } else {
        t.failWithVal("§2.19.5", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
