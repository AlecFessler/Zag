/// §4.2.59 — `vm_sysreg_passthrough` with a system register in the security blocklist returns `E_PERM`.
const builtin = @import("builtin");
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

// Arch-specific blocklist sample — must match the kernel's security blocklist.
//
// x86-64 (kernel/arch/x64/kvm/vm.zig `isSecurityCriticalSysreg`):
//   The full set of security-critical MSRs enumerated in spec §2.13.
//
// ARMv8 (kernel/arch/aarch64/kvm/vm.zig `isSecurityCriticalSysreg`):
//   Every sysreg with Op1 >= 4 (EL2/EL3 regime) and every ID register
//   (Op0=3, Op1=0, CRn=0, CRm<=7). We sample both categories. Encoding is
//   (op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2.
const blocklist: []const u64 = switch (builtin.cpu.arch) {
    .x86_64 => &.{
        0xC0000080, // EFER
        0xC0000081, // STAR
        0xC0000082, // LSTAR
        0xC0000083, // CSTAR
        0xC0000084, // SFMASK
        0x1B, // IA32_APIC_BASE
        0xC0000102, // KERNEL_GS_BASE
        0x174, // IA32_SYSENTER_CS
        0x175, // IA32_SYSENTER_ESP
        0x176, // IA32_SYSENTER_EIP
    },
    .aarch64 => &.{
        // EL2 registers (op1 >= 4 — blocklisted wholesale).
        (3 << 14) | (4 << 11) | (1 << 7) | (0 << 3) | 0, // SCTLR_EL2
        (3 << 14) | (4 << 11) | (1 << 7) | (1 << 3) | 0, // HCR_EL2
        (3 << 14) | (4 << 11) | (2 << 7) | (0 << 3) | 0, // TTBR0_EL2
        (3 << 14) | (4 << 11) | (2 << 7) | (1 << 3) | 0, // VTTBR_EL2
        (3 << 14) | (4 << 11) | (12 << 7) | (0 << 3) | 0, // VBAR_EL2
            // EL3 register (op1 = 6).
        (3 << 14) | (6 << 11) | (1 << 7) | (0 << 3) | 0, // SCTLR_EL3
            // AArch64 ID registers (op0=3, op1=0, CRn=0, CRm in {0..7}).
        (3 << 14) | (0 << 11) | (0 << 7) | (0 << 3) | 0, // MIDR_EL1
        (3 << 14) | (0 << 11) | (0 << 7) | (4 << 3) | 0, // ID_AA64PFR0_EL1
        (3 << 14) | (0 << 11) | (0 << 7) | (7 << 3) | 0, // ID_AA64MMFR0_EL1
    },
    else => @compileError("unsupported arch"),
};

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.59", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.59 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    var passed = true;
    for (blocklist) |id| {
        // Try read-only, write-only, and read+write — all should be denied.
        const r_ro = syscall.vm_sysreg_passthrough(@bitCast(cr), id, 1, 0);
        if (r_ro != syscall.E_PERM) {
            t.failWithVal("§4.2.59 ro", syscall.E_PERM, r_ro);
            passed = false;
        }
        const r_wo = syscall.vm_sysreg_passthrough(@bitCast(cr), id, 0, 1);
        if (r_wo != syscall.E_PERM) {
            t.failWithVal("§4.2.59 wo", syscall.E_PERM, r_wo);
            passed = false;
        }
        const r_rw = syscall.vm_sysreg_passthrough(@bitCast(cr), id, 1, 1);
        if (r_rw != syscall.E_PERM) {
            t.failWithVal("§4.2.59 rw", syscall.E_PERM, r_rw);
            passed = false;
        }
    }

    if (passed) {
        t.pass("§4.2.59");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
