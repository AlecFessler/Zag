/// §4.2.61 — `vm_intc_assert_irq` with an invalid VM handle returns `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var probe_policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    // Probe the VM layer: on hosts with no HW virt the VM syscalls short-
    // circuit before validating handle arguments, which would cause the
    // E_BADHANDLE assertion below to observe the wrong error code.
    const probe = syscall.vm_create(1, @intFromPtr(&probe_policy));
    t.skipIfNoVm("§4.2.61", probe);
    if (probe > 0) {
        _ = syscall.revoke_vm(@bitCast(probe));
    }

    // No vm_create — pass a bogus handle.
    const result = syscall.vm_intc_assert_irq(0xDEAD, 0);
    t.expectEqual("§4.2.61", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}
