/// §4.2.34 — `vm_recv` with blocking flag clear returns `E_AGAIN` when no exits are pending.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.34", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.34 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Non-blocking vm_recv with valid buf — no exits pending → E_AGAIN.
    const result = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 0);
    t.expectEqual("§4.2.34", syscall.E_AGAIN, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
