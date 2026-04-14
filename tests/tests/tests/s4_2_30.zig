/// §4.2.30 — `vm_guest_map` with `host_vaddr` not pointing to a valid mapped region in the caller's address space returns `E_BADADDR`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.30");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.30 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Page-aligned host_vaddr pointing to unmapped memory in user address space.
    const unmapped_addr: u64 = 0x0000_7000_0000_0000;
    const result = syscall.vm_guest_map(@bitCast(cr), unmapped_addr, 0x1000, 0x1000, 0x1);
    t.expectEqual("§4.2.30", syscall.E_BADADDR, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
