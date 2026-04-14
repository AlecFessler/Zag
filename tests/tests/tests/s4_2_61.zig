/// §4.2.61 — `vm_ioapic_assert_irq` with an invalid VM handle returns `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.61");
    // Probe for VM support — on aarch64 KVM syscalls return E_NODEV.
    const probe = syscall.vm_create(1, @intFromPtr(&policy));
    if (probe == syscall.E_NODEV) {
        t.pass("§4.2.61");
        syscall.shutdown();
    }
    if (probe >= 0) _ = syscall.revoke_vm(@bitCast(probe));

    // No vm_create — pass a bogus handle.
    const result = syscall.vm_ioapic_assert_irq(0xDEAD, 0);
    t.expectEqual("§4.2.61", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}
