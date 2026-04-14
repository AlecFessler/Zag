/// §4.2.16 — `vm_create` with `vcpu_count` exceeding `MAX_VCPUS` (64) returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // vcpu_count=65 exceeds MAX_VCPUS. Checked after hardware support, so
    // E_NODEV may be returned first on hosts without virt. Accept both.
    const result = syscall.vm_create(65, 0);
    if (result == syscall.E_INVAL or result == syscall.E_NODEV) {
        t.pass("§4.2.16");
    } else {
        t.failWithVal("§4.2.16", syscall.E_INVAL, result);
    }
    syscall.shutdown();
}
