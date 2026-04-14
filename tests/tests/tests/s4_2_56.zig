/// §4.2.56 — `vm_sysreg_passthrough` returns `E_OK` on success.
const builtin = @import("builtin");
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

// A benign, non-security-critical sysreg safe to passthrough.
//   x86-64:   IA32_TSC (0x10)
//   aarch64:  TPIDR_EL0 — op0=3, op1=3, CRn=13, CRm=0, op2=2 → 0xDE82
const BENIGN_SYSREG: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 0x10,
    .aarch64 => (3 << 14) | (3 << 11) | (13 << 7) | (0 << 3) | 2,
    else => @compileError("unsupported arch"),
};

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.56", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.56 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const result = syscall.vm_sysreg_passthrough(@bitCast(cr), BENIGN_SYSREG, 1, 1);
    t.expectEqual("§4.2.56", syscall.E_OK, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
