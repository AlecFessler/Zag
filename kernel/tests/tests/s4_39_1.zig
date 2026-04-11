/// §4.39.1 — `vm_destroy` returns `E_OK` on success.
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
        t.pass("§4.39.1");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§4.39.1 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Destroy it.
    const result = syscall.vm_destroy();
    if (result != syscall.E_OK) {
        t.failWithVal("§4.39.1", syscall.E_OK, result);
        syscall.shutdown();
    }

    // vm_recv after vm_destroy must return E_INVAL since the VM no longer exists.
    const recv_result = syscall.vm_recv(@intFromPtr(&buf), 0);
    t.expectEqual("§4.39.1", syscall.E_INVAL, recv_result);

    syscall.shutdown();
}
