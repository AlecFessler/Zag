//! PL011 PrimeCell UART emulation.
//!
//! Models just enough of the ARM PL011 r1p5 register file (ARM DDI 0183G)
//! to let Linux's amba-pl011 driver push characters to the host. Only TX
//! is implemented — RX is a no-op (UARTFR.RXFE is permanently set).
//!
//! Register map (relative to UARTBASE, all u32 unless noted):
//!   0x000  UARTDR    — data register        (r1p5 §3.3.1)
//!   0x004  UARTRSR   — receive status / err (r1p5 §3.3.2)
//!   0x018  UARTFR    — flag register        (r1p5 §3.3.3)
//!   0x020  UARTILPR  — IrDA low-power       (r1p5 §3.3.4)
//!   0x024  UARTIBRD  — integer baud divisor (r1p5 §3.3.5)
//!   0x028  UARTFBRD  — fractional baud      (r1p5 §3.3.6)
//!   0x02C  UARTLCR_H — line control         (r1p5 §3.3.7)
//!   0x030  UARTCR    — control              (r1p5 §3.3.8)
//!   0x034  UARTIFLS  — interrupt FIFO level (r1p5 §3.3.9)
//!   0x038  UARTIMSC  — interrupt mask       (r1p5 §3.3.10)
//!   0x03C  UARTRIS   — raw interrupt status (r1p5 §3.3.11)
//!   0x040  UARTMIS   — masked int status    (r1p5 §3.3.12)
//!   0x044  UARTICR   — interrupt clear      (r1p5 §3.3.13)
//!
//! The only side effect on writes is UARTDR: the byte is forwarded to
//! the VMM's write syscall so the host debug console sees guest output.

const lib = @import("lib");

const log = @import("log.zig");

const syscall = lib.syscall;

pub const UART_BASE: u64 = 0x09000000;
pub const UART_SIZE: u64 = 0x1000;

/// Guest physical MMIO range covered by this device.
pub fn contains(addr: u64) bool {
    return addr >= UART_BASE and addr < UART_BASE + UART_SIZE;
}

/// UARTFR bits we advertise (r1p5 §3.3.3):
///   bit 4  RXFE — receive FIFO empty (always 1 — no host→guest input)
///   bit 7  TXFE — transmit FIFO empty (always 1 — we flush instantly)
const UARTFR_RXFE: u32 = 1 << 4;
const UARTFR_TXFE: u32 = 1 << 7;

/// Read an emulated PL011 register. Returns the 64-bit load value to
/// place in the guest's destination register.
pub fn read(offset: u64) u64 {
    return switch (offset) {
        // UARTDR: no input available; return 0 and keep UARTFR.RXFE high.
        0x000 => 0,
        // UARTFR: permanently "TX empty, RX empty, not busy" so Linux
        // busy-loops never stall waiting for the FIFO.
        0x018 => UARTFR_RXFE | UARTFR_TXFE,
        // PrimeCell peripheral / PrimeCell ID registers live at the top
        // of the page. Linux probes these to confirm the part is a PL011.
        // Values are from r1p5 §4.3 Table 4-2. Returning zero works for
        // DT-driven probes because Linux's amba-pl011 binding matches on
        // the "arm,pl011" compatible string; the ID page read is only
        // used for the AMBA bus probe. We still supply them for safety.
        0xFE0 => 0x11, // PeriphID0
        0xFE4 => 0x10, // PeriphID1
        0xFE8 => 0x34, // PeriphID2 (rev)
        0xFEC => 0x00, // PeriphID3
        0xFF0 => 0x0D, // PCellID0
        0xFF4 => 0xF0, // PCellID1
        0xFF8 => 0x05, // PCellID2
        0xFFC => 0xB1, // PCellID3
        else => 0,
    };
}

/// Write an emulated PL011 register. Only UARTDR has a side effect.
pub fn write(offset: u64, value: u64) void {
    switch (offset) {
        0x000 => {
            // UARTDR: low 8 bits are the TX byte; push it to the host
            // debug console via the `write` syscall.
            const ch: u8 = @intCast(value & 0xFF);
            const buf = [_]u8{ch};
            syscall.write(&buf);
        },
        // Baud rate / line control / control / interrupt mask — Linux
        // writes them during probe and console takeover. We accept and
        // ignore; no interrupts fire because we advertise TXFE always
        // clear (the transmit path is effectively a noop-fast-path).
        0x004, 0x020, 0x024, 0x028, 0x02C, 0x030, 0x034, 0x038, 0x044 => {},
        else => {
            // Unknown writes: swallow silently but announce the offset
            // so a genuine driver bug is still observable.
            log.print("pl011: wr @");
            log.hex64(offset);
            log.print("\n");
        },
    }
}
