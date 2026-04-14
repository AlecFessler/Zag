/// §4.2.20 — `vm_create` reads an `arch.VmPolicy` struct from `policy_ptr`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // Pass policy_ptr=0 (null), which is not readable — should return E_BADADDR.
    // vcpu_count=1 is valid, so the only error should be from policy_ptr.
    const result = syscall.vm_create(1, 0);
    // On hardware without virt support, E_NODEV is returned before policy_ptr
    // is checked, so accept both.
    if (result == syscall.E_BADADDR or result == syscall.E_NODEV) {
        t.pass("§4.2.20");
    } else {
        t.failWithVal("§4.2.20", syscall.E_BADADDR, result);
    }
    syscall.shutdown();
}
