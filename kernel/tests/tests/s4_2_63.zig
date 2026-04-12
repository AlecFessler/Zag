/// §4.2.63 — `vm_ioapic_deassert_irq` returns `E_OK` on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.63");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.63 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Walk every valid IRQ line — all should succeed even if never asserted.
    var passed = true;
    var irq: u64 = 0;
    while (irq < 24) : (irq += 1) {
        const result = syscall.vm_ioapic_deassert_irq(@bitCast(cr), irq);
        if (result != syscall.E_OK) {
            t.failWithVal("§4.2.63", syscall.E_OK, result);
            passed = false;
        }
    }

    if (passed) {
        t.pass("§4.2.63");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
