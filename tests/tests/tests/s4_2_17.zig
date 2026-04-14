/// §4.2.17 — `vm_create` when the calling process already has a VM returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    // First vm_create — should succeed or E_NODEV if no hardware virt.
    const r1 = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.17", r1);
    if (r1 < 0) {
        t.failWithVal("§4.2.17 first create", 1, r1);
        syscall.shutdown();
    }

    // Second vm_create — should return E_INVAL.
    const r2 = syscall.vm_create(1, @intFromPtr(&policy));
    t.expectEqual("§4.2.17", syscall.E_INVAL, r2);

    // Clean up.
    _ = syscall.revoke_vm(@bitCast(r1));
    syscall.shutdown();
}
