/// §4.41.4 — `vm_recv` with `buf_ptr` not pointing to a writable region of `sizeof(VmExitMessage)` bytes returns `E_BADADDR`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.41.4");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.41.4 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Pass null buf_ptr — should return E_BADADDR.
    const result = syscall.vm_recv(@bitCast(cr), 0, 0);
    t.expectEqual("§4.41.4", syscall.E_BADADDR, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
