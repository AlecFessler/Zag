/// §4.2.59 — `vm_msr_passthrough` with an MSR in the security blocklist returns `E_PERM`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

// Full security-critical MSR blocklist enumerated in spec §2.13 (MSR Passthrough subsection).
const blocklist = [_]u64{
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
};

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.59");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.59");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.59 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    var passed = true;
    for (blocklist) |msr| {
        // Try both read-only and write-only and read+write — all should be denied.
        const r_ro = syscall.vm_msr_passthrough(@bitCast(cr), msr, 1, 0);
        if (r_ro != syscall.E_PERM) {
            t.failWithVal("§4.2.59 ro", syscall.E_PERM, r_ro);
            passed = false;
        }
        const r_wo = syscall.vm_msr_passthrough(@bitCast(cr), msr, 0, 1);
        if (r_wo != syscall.E_PERM) {
            t.failWithVal("§4.2.59 wo", syscall.E_PERM, r_wo);
            passed = false;
        }
        const r_rw = syscall.vm_msr_passthrough(@bitCast(cr), msr, 1, 1);
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
