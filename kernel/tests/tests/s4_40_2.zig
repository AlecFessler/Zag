/// §4.40.2 — `guest_map` with zero size returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        // Hardware virt not available — cannot test, pass.
        t.pass("§4.40.2");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§4.40.2 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Zero size — should return E_INVAL (host_vaddr=0 doesn't matter, size checked first).
    const result = syscall.guest_map(0, 0x1000, 0, 0x1);
    t.expectEqual("§4.40.2", syscall.E_INVAL, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
