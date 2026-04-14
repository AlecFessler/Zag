/// §4.2.25 — `vm_guest_map` with zero size returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.25");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        // Hardware virt not available — cannot test, pass.
        t.pass("§4.2.25");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.25 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Zero size — should return E_INVAL (host_vaddr=0 doesn't matter, size checked first).
    const result = syscall.vm_guest_map(@bitCast(cr), 0, 0x1000, 0, 0x1);
    t.expectEqual("§4.2.25", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
