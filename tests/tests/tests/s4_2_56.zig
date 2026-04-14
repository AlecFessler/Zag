/// §4.2.56 — `vm_msr_passthrough` returns `E_OK` on success.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

// IA32_TSC (0x10) — not security-critical, safe to passthrough.
const MSR_IA32_TSC: u64 = 0x10;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.56");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.56", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.56 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const result = syscall.vm_msr_passthrough(@bitCast(cr), MSR_IA32_TSC, 1, 1);
    t.expectEqual("§4.2.56", syscall.E_OK, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
