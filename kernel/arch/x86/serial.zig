//! Serial port driver for x86 PCs (16550-compatible UART).
//!
//! Provides minimal initialization and byte/format printing for use during
//! early kernel bring-up. Defaults to `COM1` unless reconfigured. Intended
//! for debugging, logging, and panic output before any higher-level I/O
//! facilities are available.

const cpu = @import("cpu.zig");
const std = @import("std");

pub const Ports = enum(u16) {
    com1 = 0x3F8,
    com2 = 0x2F8,
    com3 = 0x3E8,
    com4 = 0x2E8,
};

const offsets = struct {
    const txr = 0;
    const rxr = 0;
    const dll = 0;
    const ier = 1;
    const dlh = 1;
    const iir = 2;
    const fcr = 2;
    const lcr = 3;
    const mcr = 4;
    const lsr = 5;
    const msr = 6;
    const sr = 7;
};

var g_port: Ports = .com1;

/// Initializes the given serial port for 8N1 operation at the requested baud.
///
/// Arguments:
/// - `port`: which hardware UART to configure (`com1`/`com2`/`com3`/`com4`).
/// - `baud`: desired baud rate (e.g., 115200).
///
/// Behavior:
/// - Programs divisor latches, line control, and FIFO settings.
/// - Sets `g_port` so later writes use this device.
///
/// Returns:
/// - `void`
pub fn init(port: Ports, baud: u32) void {
    const p = @intFromEnum(port);
    cpu.outb(0b00_000_0_00, p + offsets.lcr);
    cpu.outb(0, p + offsets.ier);
    cpu.outb(0, p + offsets.fcr);

    const divisor = 115200 / baud;
    const c = cpu.inb(p + offsets.lcr);
    cpu.outb(c | 0b1000_0000, p + offsets.lcr);
    cpu.outb(@truncate(divisor & 0xFF), p + offsets.dll);
    cpu.outb(@truncate((divisor >> 8) & 0xFF), p + offsets.dlh);
    cpu.outb(c & 0b0111_1111, p + offsets.lcr);

    g_port = port;
}

/// Formats a string and writes it to the current serial port.
///
/// Arguments:
/// - `format`: printf-style format string.
/// - `args`: arguments substituted into the format.
///
/// Panics:
/// - If the formatted output would exceed the internal buffer (256 bytes).
pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    var temp_buffer: [256]u8 = undefined;
    const s = std.fmt.bufPrint(
        temp_buffer[0..],
        format,
        args,
    ) catch @panic("Print would be truncated!");
    for (s) |b| {
        writeByte(b, g_port);
    }
}

/// Writes a single byte to the given serial port, blocking until ready.
///
/// Arguments:
/// - `byte`: the byte to transmit.
/// - `port`: which UART to write to.
///
/// Behavior:
/// - Waits until the transmit holding register is ready before sending.
pub fn writeByte(
    byte: u8,
    port: Ports,
) void {
    while ((cpu.inb(@intFromEnum(port) + offsets.lsr) & 0b0010_0000) == 0) {}
    cpu.outb(byte, @intFromEnum(port));
}
