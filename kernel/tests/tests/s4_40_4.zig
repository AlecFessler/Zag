/// §4.40.4 — `vm_guest_map` with non-page-aligned `size` returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.40.4");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.40.4 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Page-aligned guest_addr, non-page-aligned size (0x1001).
    const result = syscall.vm_guest_map(@bitCast(cr), 0, 0x1000, 0x1001, 0x1);
    t.expectEqual("§4.40.4", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
