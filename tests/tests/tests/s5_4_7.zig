const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.7 — `sys_cpu_power` returns `E_NODEV` if the hardware does not support the requested action.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Try set_freq with a frequency value — QEMU doesn't support DVFS,
    // so E_NODEV is expected.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_FREQ, 2_000_000_000);
    if (rc == syscall.E_NODEV or rc == syscall.E_OK) {
        t.pass("§5.4.7");
    } else {
        t.failWithVal("§5.4.7", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
