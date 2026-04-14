/// §4.2.15 — `vm_create` with `vcpu_count` = 0 returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // vcpu_count=0 is checked after the hardware-support check, so on hosts
    // without virt the VM layer short-circuits before the vcpu_count path is
    // reached — skip in that case so a green run isn't confused with a real
    // assertion.
    const result = syscall.vm_create(0, 0);
    t.skipIfNoVm("§4.2.15", result);
    t.expectEqual("§4.2.15", syscall.E_INVAL, result);
    syscall.shutdown();
}
