/// §4.40.3 — `vm_guest_map` with non-page-aligned `guest_addr` returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.40.3");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.40.3 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Non-page-aligned guest_addr (0x1001) with valid size and rights.
    const result = syscall.vm_guest_map(@bitCast(cr), 0, 0x1001, 0x1000, 0x1);
    t.expectEqual("§4.40.3", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
