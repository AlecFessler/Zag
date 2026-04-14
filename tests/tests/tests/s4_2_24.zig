/// §4.2.24 — `vm_guest_map` returns `E_OK` on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.24");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.24");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.24 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve a host buffer to back the guest mapping.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    const host_vaddr = res.val2;
    if (res.val < 0) {
        t.failWithVal("§4.2.24 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Map host buffer into guest at guest physical 0x1000 with read rights.
    const result = syscall.vm_guest_map(@bitCast(cr), host_vaddr, 0x1000, syscall.PAGE4K, 0x1);
    t.expectEqual("§4.2.24", syscall.E_OK, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
