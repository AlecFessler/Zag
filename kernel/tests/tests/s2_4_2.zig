const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.2 — Device user view `field0` encodes: `device_type(u8) | device_class(u8) << 8 | size_or_port_count(u32) << 32`.
/// Verify the encoding against the known-stable AHCI MMIO BAR (4 KiB, class storage).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const mmio = t.requireMmioDevice(view, "§2.4.2 mmio");
    // AHCI MMIO BAR: type=0 (MMIO), class=storage (2), size=4096.
    const f0 = mmio.field0;
    const expected_type: u8 = 0;
    const expected_class: u8 = @intFromEnum(perms.DeviceClass.storage);
    const expected_size: u32 = 4096;
    const expected_f0: u64 = @as(u64, expected_type) |
        (@as(u64, expected_class) << 8) |
        (@as(u64, expected_size) << 32);
    if (f0 != expected_f0) {
        t.failWithVal("§2.4.2 mmio_f0", @bitCast(expected_f0), @bitCast(f0));
        syscall.shutdown();
    }
    if (mmio.deviceType() != expected_type) {
        t.fail("§2.4.2 mmio_type");
        syscall.shutdown();
    }
    if (mmio.deviceClass() != expected_class) {
        t.fail("§2.4.2 mmio_class");
        syscall.shutdown();
    }
    if (mmio.deviceSizeOrPortCount() != expected_size) {
        t.fail("§2.4.2 mmio_size");
        syscall.shutdown();
    }

    const pio = t.requirePioDevice(view, "§2.4.2 pio");
    // AHCI PIO BAR: type=1, class=storage (2), size=32 ports.
    const pf0 = pio.field0;
    const pexpected_type: u8 = 1;
    const pexpected_size: u32 = 32;
    const pexpected_f0: u64 = @as(u64, pexpected_type) |
        (@as(u64, expected_class) << 8) |
        (@as(u64, pexpected_size) << 32);
    if (pf0 != pexpected_f0) {
        t.failWithVal("§2.4.2 pio_f0", @bitCast(pexpected_f0), @bitCast(pf0));
        syscall.shutdown();
    }

    t.pass("§2.4.2");
    syscall.shutdown();
}
