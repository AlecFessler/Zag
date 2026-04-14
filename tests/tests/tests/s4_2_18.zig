/// §4.2.18 — `vm_create` returns `E_NODEV` if hardware virtualization is not supported.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    // This test verifies that vm_create either succeeds (positive handle) or
    // returns E_NODEV when hardware virt is unavailable. On architectures
    // with no VM backend wired up at all (E_NORES), nothing observable about
    // the §4.2.18 E_NODEV contract can be tested — skip so a green run isn't
    // confused with a real pass.
    const result = syscall.vm_create(1, @intFromPtr(&policy));
    if (result == syscall.E_NORES) {
        t.skip("§4.2.18", "VM backend not implemented on this arch (E_NORES)");
        syscall.shutdown();
    }
    if (result == syscall.E_NODEV or result > 0) {
        t.pass("§4.2.18");
        if (result > 0) {
            _ = syscall.revoke_vm(@bitCast(result));
        }
    } else {
        t.failWithVal("§4.2.18", syscall.E_NODEV, result);
    }
    syscall.shutdown();
}
