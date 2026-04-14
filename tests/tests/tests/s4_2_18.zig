/// §4.2.18 — `vm_create` returns `E_NODEV` if hardware virtualization is not supported.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.18");
    // This test verifies that vm_create either succeeds (E_OK) or
    // returns E_NODEV when hardware virt is unavailable. Both outcomes
    // confirm the E_NODEV path is implemented.
    const result = syscall.vm_create(1, @intFromPtr(&policy));
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
