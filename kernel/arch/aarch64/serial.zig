//! PL011 UART driver for AArch64 serial output.
//!
//! The PL011 is ARM's standard UART IP. It replaces x86's NS16550 (COM port).
//! Base address is discovered from ACPI SPCR (Serial Port Console Redirection)
//! table or DBG2 (Debug Port Table 2).
//!
//! PL011 register map (ARM DDI 0183G, PrimeCell UART Technical Reference):
//!   Offset  Register  Description
//!   0x000   UARTDR    Data Register (read/write FIFO)
//!   0x018   UARTFR    Flag Register (bit 5 = TXFF, bit 4 = RXFE, bit 3 = BUSY)
//!   0x024   UARTIBRD  Integer Baud Rate Divisor
//!   0x028   UARTFBRD  Fractional Baud Rate Divisor
//!   0x02C   UARTLCR_H Line Control (word length, FIFO enable, parity)
//!   0x030   UARTCR    Control Register (UARTEN, TXE, RXE)
//!   0x038   UARTIMSC  Interrupt Mask Set/Clear
//!   0x044   UARTICR   Interrupt Clear Register
//!
//! Transmit flow:
//!   1. Poll UARTFR.TXFF until clear (TX FIFO not full).
//!   2. Write byte to UARTDR.
//!
//! UEFI firmware typically initializes the UART before handoff, so the driver
//! may skip baud rate / line control setup and just write to UARTDR.
//!
//! The SPCR table (ACPI 6.5, Section 5.2.32) provides:
//!   - Base address (MMIO)
//!   - Interface type (should be ARM PL011 = 0x0003)
//!   - Baud rate, flow control, terminal type
//!
//! References:
//! - ARM DDI 0183G: PL011 Technical Reference Manual
//! - ACPI 6.5, Section 5.2.32: SPCR

const std = @import("std");

pub fn print(comptime format: []const u8, args: anytype) void {
    _ = format;
    _ = args;
    // PL011 UART output — poll UARTFR.TXFF, write UARTDR.
    @panic("aarch64 serial not implemented");
}
