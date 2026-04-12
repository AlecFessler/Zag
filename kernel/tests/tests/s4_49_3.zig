/// §4.49.3 — `vm_ioapic_deassert_irq` with `irq_num` greater than or equal to 24 returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.49.3");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.49.3 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    var passed = true;

    const r24 = syscall.vm_ioapic_deassert_irq(@bitCast(cr), 24);
    if (r24 != syscall.E_INVAL) {
        t.failWithVal("§4.49.3 irq=24", syscall.E_INVAL, r24);
        passed = false;
    }

    const r99 = syscall.vm_ioapic_deassert_irq(@bitCast(cr), 99);
    if (r99 != syscall.E_INVAL) {
        t.failWithVal("§4.49.3 irq=99", syscall.E_INVAL, r99);
        passed = false;
    }

    if (passed) {
        t.pass("§4.49.3");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
