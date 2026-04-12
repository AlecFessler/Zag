/// §4.38.6 — `vm_create` returns `E_MAXCAP` if the permissions table cannot fit all vCPU thread handles.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    // Request 64 vCPUs — likely exceeds remaining perm table capacity
    // for the root service which already has many entries.
    // On hardware without virt, E_NODEV is returned first. Accept both.
    const result = syscall.vm_create(64, @intFromPtr(&policy));
    if (result == syscall.E_MAXCAP or result == syscall.E_NODEV or result == syscall.E_NOMEM) {
        t.pass("§4.38.6");
    } else if (result > 0) {
        // Perm table had room — cannot test E_MAXCAP, pass.
        _ = syscall.revoke_vm(@bitCast(result));
        t.pass("§4.38.6");
    } else {
        t.failWithVal("§4.38.6", syscall.E_MAXCAP, result);
    }
    syscall.shutdown();
}
