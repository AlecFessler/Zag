//! PL011 UART driver for AArch64 serial output.
//!
//! The PL011 is ARM's standard UART IP. It replaces x86's NS16550 (COM port).
//! Base address is discovered from ACPI SPCR (Serial Port Console Redirection)
//! table or DBG2 (Debug Port Table 2).
//!
//! Only the transmit path is implemented: poll UARTFR.TXFF, write UARTDR.
//! UEFI firmware initializes baud rate, line control, and FIFO settings
//! before handoff, so this driver skips hardware setup entirely.
//!
//! References:
//! - ARM DDI 0183G: PrimeCell UART (PL011) Technical Reference Manual
//! - ACPI 6.5, Section 5.2.32: SPCR

const std = @import("std");
const zag = @import("zag");

const sync = zag.utils.sync;

/// PL011 register offsets from base address.
/// DDI0183G Section 3.2, Table 3-1.
const offsets = struct {
    /// Data Register — write byte to transmit FIFO.
    /// DDI0183G Section 3.3.1, Table 3-2.
    const uartdr = 0x000;

    /// Flag Register — contains TX/RX status flags.
    /// DDI0183G Section 3.3.3, Table 3-4.
    const uartfr = 0x018;
};

/// UARTFR bit masks.
/// DDI0183G Section 3.3.3, Table 3-4.
const fr_bits = struct {
    /// Bit 5: Transmit FIFO full. When set, the TX FIFO cannot accept more data.
    const txff: u32 = (1 << 5);
};

/// MMIO base address of the PL011 UART, set at runtime from ACPI SPCR.
/// Null until `setBase` is called during early boot.
var base_addr: ?u64 = null;

var print_lock = sync.SpinLock{};

/// Set the PL011 MMIO base address. Called by ACPI SPCR/DBG2 parsing
/// during early boot before any serial output is needed.
pub fn setBase(addr: u64) void {
    base_addr = addr;
}

/// Initialize the PL011 UART for transmit.
/// Currently a no-op because UEFI firmware configures baud rate, line
/// control (UARTLCR_H), and enables the UART (UARTCR) before handoff.
pub fn init() void {}

/// Format and transmit a string over the PL011 UART.
/// Silently returns if the base address has not yet been set (early boot
/// before ACPI SPCR discovery).
pub fn print(comptime format: []const u8, args: anytype) void {
    const base = base_addr orelse return;

    var temp_buffer: [256]u8 = undefined;
    const s = std.fmt.bufPrint(
        temp_buffer[0..],
        format,
        args,
    ) catch @panic("Print would be truncated!");

    print_lock.lock();
    defer print_lock.unlock();

    for (s) |b| {
        writeByte(b, base);
    }
}

/// Poll UARTFR.TXFF until the transmit FIFO has space, then write one
/// byte to UARTDR.
/// DDI0183G Section 3.3.3 (UARTFR) and Section 3.3.1 (UARTDR).
fn writeByte(byte: u8, base: u64) void {
    const fr_ptr: *volatile u32 = @ptrFromInt(base + offsets.uartfr);
    const dr_ptr: *volatile u32 = @ptrFromInt(base + offsets.uartdr);

    while ((fr_ptr.* & fr_bits.txff) != 0) {}
    dr_ptr.* = byte;
}
