/// §4.2.16 — `vm_create` with `vcpu_count` exceeding `MAX_VCPUS` (64) returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // vcpu_count=65 exceeds MAX_VCPUS. The vcpu_count check runs after the
    // hardware-support check, so on hosts without virt the VM layer short-
    // circuits before the MAX_VCPUS path is reached — skip in that case so
    // a green run isn't confused with a real assertion.
    const result = syscall.vm_create(65, 0);
    t.skipIfNoVm("§4.2.16", result);
    t.expectEqual("§4.2.16", syscall.E_INVAL, result);
    syscall.shutdown();
}
