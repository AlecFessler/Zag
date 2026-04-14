/// §4.2.26 — `vm_guest_map` with non-page-aligned `guest_addr` returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.26");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.26", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.26 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Non-page-aligned guest_addr (0x1001) with valid size and rights.
    const result = syscall.vm_guest_map(@bitCast(cr), 0, 0x1001, 0x1000, 0x1);
    t.expectEqual("§4.2.26", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
