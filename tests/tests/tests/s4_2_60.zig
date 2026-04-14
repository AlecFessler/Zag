/// §4.2.60 — `vm_intc_assert_irq` returns `E_OK` on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.60");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.60", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.60 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Walk every valid IRQ line — all should succeed.
    var passed = true;
    var irq: u64 = 0;
    while (irq < 24) : (irq += 1) {
        const result = syscall.vm_intc_assert_irq(@bitCast(cr), irq);
        if (result != syscall.E_OK) {
            t.failWithVal("§4.2.60", syscall.E_OK, result);
            passed = false;
        }
    }

    if (passed) {
        t.pass("§4.2.60");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
