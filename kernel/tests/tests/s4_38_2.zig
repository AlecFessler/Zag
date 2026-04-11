/// §4.38.2 — `vm_create` with `vcpu_count` = 0 returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // vcpu_count=0 is checked after hardware support check, so E_NODEV
    // may be returned first on hosts without virt. Accept both.
    const result = syscall.vm_create(0, 0);
    if (result == syscall.E_INVAL or result == syscall.E_NODEV) {
        t.pass("§4.38.2");
    } else {
        t.failWithVal("§4.38.2", syscall.E_INVAL, result);
    }
    syscall.shutdown();
}
