/// §4.41.3 — `vm_recv` with blocking flag clear returns `E_AGAIN` when no exits are pending.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.41.3");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§4.41.3 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Non-blocking vm_recv with valid buf — no exits pending → E_AGAIN.
    const result = syscall.vm_recv(@intFromPtr(&buf), 0);
    t.expectEqual("§4.41.3", syscall.E_AGAIN, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
