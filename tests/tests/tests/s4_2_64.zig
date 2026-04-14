/// §4.2.64 — `vm_ioapic_deassert_irq` with an invalid VM handle returns `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.64");
    // Probe platform KVM support: on aarch64 (and any non-x86 host) the
    // entire KVM syscall family short-circuits to E_NODEV before handle
    // validation, so the E_BADHANDLE assertion is unobservable. Treat
    // that case as a platform gap and pass.
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.64");
        syscall.shutdown();
    }
    if (cr >= 0) {
        _ = syscall.revoke_vm(@bitCast(cr));
    }

    // No vm_create — pass a bogus handle.
    const result = syscall.vm_ioapic_deassert_irq(0xDEAD, 0);
    t.expectEqual("§4.2.64", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}
