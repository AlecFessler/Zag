/// §4.40.8 — `vm_guest_map` with a guest physical region overlapping the in-kernel LAPIC page (`0xFEE00000`) or IOAPIC page (`0xFEC00000`) returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

const LAPIC_BASE: u64 = 0xFEE00000;
const IOAPIC_BASE: u64 = 0xFEC00000;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.40.8");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.40.8 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve a host page so vm_guest_map has valid host backing memory.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.40.8 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_va: u64 = res.val2;

    var passed = true;

    // Region exactly at LAPIC base.
    const r_lapic_exact = syscall.vm_guest_map(@bitCast(cr), host_va, LAPIC_BASE, syscall.PAGE4K, 0x7);
    if (r_lapic_exact != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 lapic_exact", syscall.E_INVAL, r_lapic_exact);
        passed = false;
    }

    // Region exactly at IOAPIC base.
    const r_ioapic_exact = syscall.vm_guest_map(@bitCast(cr), host_va, IOAPIC_BASE, syscall.PAGE4K, 0x7);
    if (r_ioapic_exact != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 ioapic_exact", syscall.E_INVAL, r_ioapic_exact);
        passed = false;
    }

    // Region starting one page below LAPIC, two pages long — overlaps LAPIC.
    const r_lapic_straddle = syscall.vm_guest_map(@bitCast(cr), host_va, LAPIC_BASE - syscall.PAGE4K, 2 * syscall.PAGE4K, 0x7);
    if (r_lapic_straddle != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 lapic_straddle", syscall.E_INVAL, r_lapic_straddle);
        passed = false;
    }

    // Region starting one page below IOAPIC, two pages long — overlaps IOAPIC.
    const r_ioapic_straddle = syscall.vm_guest_map(@bitCast(cr), host_va, IOAPIC_BASE - syscall.PAGE4K, 2 * syscall.PAGE4K, 0x7);
    if (r_ioapic_straddle != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 ioapic_straddle", syscall.E_INVAL, r_ioapic_straddle);
        passed = false;
    }

    // Upper-edge straddle: guest_addr begins inside the LAPIC/IOAPIC page and
    // extends past it. These specifically target a known kernel bug where only
    // `guest_addr <= mmio_base` was checked, letting mid-page starts slip through.
    // (A non-page-aligned guest_addr also violates §4.40.3, so either rule
    // returning E_INVAL is acceptable — the test only asserts E_INVAL.)
    const r_lapic_midpage = syscall.vm_guest_map(@bitCast(cr), host_va, LAPIC_BASE + 0x800, syscall.PAGE4K, 0x7);
    if (r_lapic_midpage != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 lapic_midpage", syscall.E_INVAL, r_lapic_midpage);
        passed = false;
    }

    const r_ioapic_midpage = syscall.vm_guest_map(@bitCast(cr), host_va, IOAPIC_BASE + 0x800, syscall.PAGE4K, 0x7);
    if (r_ioapic_midpage != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 ioapic_midpage", syscall.E_INVAL, r_ioapic_midpage);
        passed = false;
    }

    // Region wholly contains the LAPIC page: starts one page below, three pages long.
    const r_lapic_contain = syscall.vm_guest_map(@bitCast(cr), host_va, LAPIC_BASE - syscall.PAGE4K, 3 * syscall.PAGE4K, 0x7);
    if (r_lapic_contain != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 lapic_contain", syscall.E_INVAL, r_lapic_contain);
        passed = false;
    }

    // Region wholly contains the IOAPIC page.
    const r_ioapic_contain = syscall.vm_guest_map(@bitCast(cr), host_va, IOAPIC_BASE - syscall.PAGE4K, 3 * syscall.PAGE4K, 0x7);
    if (r_ioapic_contain != syscall.E_INVAL) {
        t.failWithVal("§4.40.8 ioapic_contain", syscall.E_INVAL, r_ioapic_contain);
        passed = false;
    }

    if (passed) {
        t.pass("§4.40.8");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
