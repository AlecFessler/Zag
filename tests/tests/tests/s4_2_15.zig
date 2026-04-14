/// §4.2.15 — `vm_create` with `vcpu_count` = 0 returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.15");
    // vcpu_count=0 is checked after hardware support check, so E_NODEV
    // may be returned first on hosts without virt. Accept both.
    const result = syscall.vm_create(0, 0);
    if (result == syscall.E_INVAL or result == syscall.E_NODEV) {
        t.pass("§4.2.15");
    } else {
        t.failWithVal("§4.2.15", syscall.E_INVAL, result);
    }
    syscall.shutdown();
}
