/// §4.2.51 — `vm_vcpu_run` with `thread_handle` not referring to a vCPU thread returns `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.51");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.51");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.51 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Use our own thread handle (not a vCPU) — should return E_BADHANDLE.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    const result = syscall.vm_vcpu_run(self_handle);
    t.expectEqual("§4.2.51", syscall.E_BADHANDLE, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
