/// §4.2.21 — `vm_destroy` returns `E_OK` on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(_: u64) void {
    // Create a VM first.
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        // Hardware virt not available — cannot test destroy, pass.
        t.pass("§4.2.21");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.21 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Destroy it.
    const result = syscall.revoke_vm(@bitCast(cr));
    if (result != syscall.E_OK) {
        t.failWithVal("§4.2.21", syscall.E_OK, result);
        syscall.shutdown();
    }

    // vm_recv after revoke must return E_BADCAP since the handle is gone.
    const recv_result = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 0);
    t.expectEqual("§4.2.21", syscall.E_BADHANDLE, recv_result);

    syscall.shutdown();
}
