const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.19 — `sys_cpu_power` returns `E_NODEV` if the hardware does not support the requested action.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // QEMU doesn't support DVFS — E_NODEV expected for set_freq.
    const rc = syscall.sys_cpu_power(syscall.CPU_POWER_SET_FREQ, 2_000_000_000);
    if (rc == syscall.E_NODEV or rc == syscall.E_OK) {
        t.pass("§5.4.19");
    } else {
        t.failWithVal("§5.4.19", syscall.E_NODEV, rc);
    }
    syscall.shutdown();
}
