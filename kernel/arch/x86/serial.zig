//! Serial port driver for x86 PCs (16550-compatible UART).
//!
//! Provides minimal initialization and byte/format printing for use during
//! early kernel bring-up. Defaults to `COM1` unless reconfigured. Intended
//! for debugging, logging, and panic output before any higher-level I/O
//! facilities are available.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Ports` – enumeration of standard legacy UART base I/O ports.
//!
//! ## Constants
//! - `offsets.txr` – transmit holding register offset (THR).
//! - `offsets.rxr` – receive buffer register offset (RBR).
//! - `offsets.dll` – divisor latch low byte offset (DLL).
//! - `offsets.ier` – interrupt enable register offset (IER).
//! - `offsets.dlh` – divisor latch high byte offset (DLH).
//! - `offsets.iir` – interrupt identification register offset (IIR).
//! - `offsets.fcr` – FIFO control register offset (FCR).
//! - `offsets.lcr` – line control register offset (LCR).
//! - `offsets.mcr` – modem control register offset (MCR).
//! - `offsets.lsr` – line status register offset (LSR).
//! - `offsets.msr` – modem status register offset (MSR).
//! - `offsets.sr`  – scratch register offset (SCR).
//!
//! ## Variables
//! - `g_port` – currently selected UART base port used by print/write APIs.
//!
//! ## Functions
//! - `init` – configure a UART for 8N1 at a requested baud and select it.
//! - `print` – formatted write to the currently selected UART.
//! - `writeByte` – blocking single-byte write to a specific UART.

const cpu = @import("cpu.zig");
const std = @import("std");

/// Enumeration of standard legacy UART base I/O ports.
pub const Ports = enum(u16) {
    com1 = 0x3F8,
    com2 = 0x2F8,
    com3 = 0x3E8,
    com4 = 0x2E8,
};

/// Register offsets relative to a UART base port.
const offsets = struct {
    /// Transmit holding register (THR).
    const txr = 0;
    /// Receive buffer register (RBR).
    const rxr = 0;
    /// Divisor latch low byte (DLL).
    const dll = 0;
    /// Interrupt enable register (IER).
    const ier = 1;
    /// Divisor latch high byte (DLH).
    const dlh = 1;
    /// Interrupt identification register (IIR).
    const iir = 2;
    /// FIFO control register (FCR).
    const fcr = 2;
    /// Line control register (LCR).
    const lcr = 3;
    /// Modem control register (MCR).
    const mcr = 4;
    /// Line status register (LSR).
    const lsr = 5;
    /// Modem status register (MSR).
    const msr = 6;
    /// Scratch register (SCR).
    const sr = 7;
};

/// Currently selected UART base port for subsequent writes.
var g_port: Ports = .com1;

/// Summary:
/// Configures a 16550-compatible UART for 8N1 at `baud` and selects it as current.
///
/// Args:
/// - `port`: UART base port to configure (`.com1`/`.com2`/`.com3`/`.com4`).
/// - `baud`: desired baud rate (e.g., 115200).
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn init(port: Ports, baud: u32) void {
    const p = @intFromEnum(port);
    // 8N1, clear IER/FCR before programming divisor.
    cpu.outb(0b00_000_0_00, p + offsets.lcr);
    cpu.outb(0, p + offsets.ier);
    cpu.outb(0, p + offsets.fcr);

    // Program divisor latches (DLAB=1), then restore LCR.
    const divisor = 115200 / baud;
    const c = cpu.inb(p + offsets.lcr);
    cpu.outb(c | 0b1000_0000, p + offsets.lcr); // DLAB=1
    cpu.outb(@truncate(divisor & 0xFF), p + offsets.dll);
    cpu.outb(@truncate((divisor >> 8) & 0xFF), p + offsets.dlh);
    cpu.outb(c & 0b0111_1111, p + offsets.lcr); // DLAB=0

    g_port = port;
}

/// Summary:
/// Formats a string and writes it to the currently selected UART.
///
/// Args:
/// - `format`: compile-time format string.
/// - `args`: values substituted into the format string.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if the formatted output would exceed the internal buffer (256 bytes).
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

/// Summary:
/// Writes a single byte to `port`, blocking until the transmitter is ready.
///
/// Args:
/// - `byte`: the byte to transmit.
/// - `port`: UART base port to write to.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn writeByte(
    byte: u8,
    port: Ports,
) void {
    while ((cpu.inb(@intFromEnum(port) + offsets.lsr) & 0b0010_0000) == 0) {}
    cpu.outb(byte, @intFromEnum(port));
}
