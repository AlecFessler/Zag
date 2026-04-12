/// §4.40.5 — `vm_guest_map` with invalid rights bits returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.40.5");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.40.5 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Valid guest_addr and size, but invalid rights bits (0xFF has undefined upper bits).
    const result = syscall.vm_guest_map(@bitCast(cr), 0, 0x1000, 0x1000, 0xFF);
    t.expectEqual("§4.40.5", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
