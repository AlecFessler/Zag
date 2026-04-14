/// §4.2.58 — `vm_sysreg_passthrough` with `sysreg_id` outside the 32-bit identifier range returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.58", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.58 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    var passed = true;

    // sysreg_id just past u32 max (0x100000000) — first value outside the range.
    const r_one_past = syscall.vm_sysreg_passthrough(@bitCast(cr), @as(u64, 1) << 32, 1, 1);
    if (r_one_past != syscall.E_INVAL) {
        t.failWithVal("§4.2.58 one_past", syscall.E_INVAL, r_one_past);
        passed = false;
    }

    // Largest possible u64.
    const r_max_u64 = syscall.vm_sysreg_passthrough(@bitCast(cr), 0xFFFF_FFFF_FFFF_FFFF, 1, 1);
    if (r_max_u64 != syscall.E_INVAL) {
        t.failWithVal("§4.2.58 max_u64", syscall.E_INVAL, r_max_u64);
        passed = false;
    }

    // Arbitrary mid-range out-of-bounds value.
    const r_mid = syscall.vm_sysreg_passthrough(@bitCast(cr), 0xDEAD_BEEF_DEAD_BEEF, 1, 1);
    if (r_mid != syscall.E_INVAL) {
        t.failWithVal("§4.2.58 mid", syscall.E_INVAL, r_mid);
        passed = false;
    }

    // Inclusive valid edge: 0xFFFFFFFF is the largest in-range sysreg_id and
    // must NOT return E_INVAL. The id need not actually exist, and the kernel
    // may still return E_PERM for blocklist reasons — the range check is the
    // only thing under test here.
    const r_valid_edge = syscall.vm_sysreg_passthrough(@bitCast(cr), 0xFFFFFFFF, 1, 1);
    if (r_valid_edge == syscall.E_INVAL) {
        t.failWithVal("§4.2.58 valid_edge", 0, r_valid_edge);
        passed = false;
    }

    if (passed) {
        t.pass("§4.2.58");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
