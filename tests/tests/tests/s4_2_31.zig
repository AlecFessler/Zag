/// §4.2.31 — `vm_guest_map` with a guest physical region overlapping any MMIO page reserved by the in-kernel interrupt controller returns `E_INVAL`.
const builtin = @import("builtin");
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

// Arch-specific MMIO pages owned by the in-kernel interrupt controller.
// These must match the kernel's reserved regions — any overlap with a
// `vm_guest_map` request must return E_INVAL.
//
// x86-64: LAPIC @ 0xFEE00000 + IOAPIC @ 0xFEC00000 (single 4K page each).
// ARMv8:  vGIC distributor/redistributor pages owned by the kernel vGIC.
//         We sample each by base address; the kernel reserves at least one
//         4K page at each of these bases.
const INTC_BASES: []const u64 = switch (builtin.cpu.arch) {
    .x86_64 => &.{ 0xFEE00000, 0xFEC00000 },
    .aarch64 => &.{ 0x08000000, 0x080A0000 },
    else => @compileError("unsupported arch"),
};

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.31", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.31 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve a host page so vm_guest_map has valid host backing memory.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.31 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_va: u64 = res.val2;

    var passed = true;

    for (INTC_BASES) |base| {
        // Region exactly at the intc page.
        const r_exact = syscall.vm_guest_map(@bitCast(cr), host_va, base, syscall.PAGE4K, 0x7);
        if (r_exact != syscall.E_INVAL) {
            t.failWithVal("§4.2.31 exact", syscall.E_INVAL, r_exact);
            passed = false;
        }

        // Region starting one page below the intc page, two pages long — straddles it.
        const r_straddle = syscall.vm_guest_map(@bitCast(cr), host_va, base - syscall.PAGE4K, 2 * syscall.PAGE4K, 0x7);
        if (r_straddle != syscall.E_INVAL) {
            t.failWithVal("§4.2.31 straddle", syscall.E_INVAL, r_straddle);
            passed = false;
        }

        // Upper-edge straddle: guest_addr begins inside the intc page and
        // extends past it. Targets a known-bug class where only
        // `guest_addr <= base` was checked. A non-page-aligned guest_addr
        // also violates §4.2.26, so either rule returning E_INVAL is
        // acceptable — the test only asserts E_INVAL.
        const r_midpage = syscall.vm_guest_map(@bitCast(cr), host_va, base + 0x800, syscall.PAGE4K, 0x7);
        if (r_midpage != syscall.E_INVAL) {
            t.failWithVal("§4.2.31 midpage", syscall.E_INVAL, r_midpage);
            passed = false;
        }

        // Region wholly contains the intc page: starts one page below, three pages long.
        const r_contain = syscall.vm_guest_map(@bitCast(cr), host_va, base - syscall.PAGE4K, 3 * syscall.PAGE4K, 0x7);
        if (r_contain != syscall.E_INVAL) {
            t.failWithVal("§4.2.31 contain", syscall.E_INVAL, r_contain);
            passed = false;
        }
    }

    if (passed) {
        t.pass("§4.2.31");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
