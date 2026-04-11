/// §4.40.6 — `guest_map` with non-page-aligned `host_vaddr` returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.40.6");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§4.40.6 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Non-page-aligned host_vaddr (0x1001) with valid guest_addr, size, and rights.
    const result = syscall.guest_map(0x1001, 0x1000, 0x1000, 0x1);
    t.expectEqual("§4.40.6", syscall.E_INVAL, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
