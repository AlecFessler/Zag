/// §4.2.20 — `vm_create` reads an `arch.VmPolicy` struct from `policy_ptr`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // Pass policy_ptr=0 (null), which is not readable — should return E_BADADDR.
    // vcpu_count=1 is valid, so the only error should be from policy_ptr.
    // On hosts without HW virt the VM layer short-circuits before policy_ptr
    // is validated, so skip rather than silently "pass".
    const result = syscall.vm_create(1, 0);
    t.skipIfNoVm("§4.2.20", result);
    t.expectEqual("§4.2.20", syscall.E_BADADDR, result);
    syscall.shutdown();
}
