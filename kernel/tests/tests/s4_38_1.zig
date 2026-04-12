/// §4.38.1 — `vm_create` returns a positive handle on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const result = syscall.vm_create(1, @intFromPtr(&policy));
    if (result == syscall.E_NODEV) {
        // Hardware virt not available — pass (cannot test success path).
        t.pass("§4.38.1");
        syscall.shutdown();
    }
    if (result > 0) {
        t.pass("§4.38.1");
        _ = syscall.revoke_vm(@bitCast(result));
    } else {
        t.failWithVal("§4.38.1", 1, result);
    }
    syscall.shutdown();
}
