/// I/O port emulation for non-serial devices.
/// Stubs for PIC, PIT, PS/2, CMOS, PCI, VGA, etc.
/// These are needed because Linux probes many legacy devices during boot.

const log = @import("log.zig");
const serial = @import("serial.zig");

const GuestState = @import("main.zig").GuestState;

// PIC
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// PIT
const PIT_CH0: u16 = 0x40;
const PIT_CH1: u16 = 0x41;
const PIT_CH2: u16 = 0x42;
const PIT_CMD: u16 = 0x43;

// PS/2
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

// CMOS/RTC
const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// POST diagnostic
const POST_PORT: u16 = 0x80;

// PCI config space
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// Shadow state
var cmos_index: u8 = 0;
var pic1_mask: u8 = 0xFF;
var pic2_mask: u8 = 0xFF;

// PIC initialization tracking
// ICW sequence: ICW1 (cmd) → ICW2 (data, vector offset) → ICW3 (data) → ICW4 (data)
const PicPhase = enum { ready, icw2, icw3, icw4 };
var pic1_phase: PicPhase = .ready;
var pic2_phase: PicPhase = .ready;
pub var pic1_vector_base: u8 = 0x08; // Default: IRQ0 → INT 8
pub var pic2_vector_base: u8 = 0x70; // Default: IRQ8 → INT 0x70

pub fn handleOut(port: u16, size: u8, value: u32, state: *GuestState) void {
    _ = state;
    _ = size;

    if (serial.isSerialPort(port)) {
        serial.handleOut(port, @truncate(value));
        return;
    }

    switch (port) {
        PIC1_CMD => {
            const v: u8 = @truncate(value);
            if (v & 0x10 != 0) { // ICW1
                pic1_phase = .icw2;
            }
            // OCW2 (EOI): ignore
        },
        PIC1_DATA => {
            const v: u8 = @truncate(value);
            switch (pic1_phase) {
                .icw2 => { pic1_vector_base = v; pic1_phase = .icw3; },
                .icw3 => { pic1_phase = .icw4; },
                .icw4 => { pic1_phase = .ready; },
                .ready => { pic1_mask = v; }, // OCW1: interrupt mask
            }
        },
        PIC2_CMD => {
            const v: u8 = @truncate(value);
            if (v & 0x10 != 0) { pic2_phase = .icw2; }
        },
        PIC2_DATA => {
            const v: u8 = @truncate(value);
            switch (pic2_phase) {
                .icw2 => { pic2_vector_base = v; pic2_phase = .icw3; },
                .icw3 => { pic2_phase = .icw4; },
                .icw4 => { pic2_phase = .ready; },
                .ready => { pic2_mask = v; },
            }
        },
        PIT_CH0, PIT_CH1, PIT_CH2, PIT_CMD => {},
        PS2_DATA, PS2_STATUS => {},
        CMOS_ADDR => cmos_index = @truncate(value & 0x7F),
        CMOS_DATA => {},
        POST_PORT => {
            // POST code — useful for debugging boot progress
            log.print("POST: 0x");
            log.hex8(@truncate(value));
            log.print("\n");
        },
        // VGA registers
        0x3C0...0x3DA => {},
        // PCI config
        PCI_CONFIG_ADDR => {},
        PCI_CONFIG_DATA...PCI_CONFIG_DATA + 3 => {},
        // DMA controller
        0x00...0x0F => {},
        0xC0...0xDF => {},
        0x81...0x8F => {}, // DMA page registers (0x80 handled as POST_PORT above)
        // Port 0x61: NMI status / speaker
        0x61 => {},
        // ELCR (edge/level control)
        0x4D0, 0x4D1 => {},
        else => {},
    }
}

pub fn handleIn(port: u16, size: u8, state: *GuestState) u32 {
    _ = state;
    _ = size;

    if (serial.isSerialPort(port)) {
        return serial.handleIn(port);
    }

    return switch (port) {
        PIC1_CMD => 0x00,
        PIC1_DATA => pic1_mask,
        PIC2_CMD => 0x00,
        PIC2_DATA => pic2_mask,
        PIT_CH0, PIT_CH1, PIT_CH2 => 0x00,
        PS2_STATUS => 0x00, // No PS/2 data
        PS2_DATA => 0x00,
        CMOS_DATA => handleCmosRead(cmos_index),
        PCI_CONFIG_ADDR => 0x00,
        PCI_CONFIG_DATA...PCI_CONFIG_DATA + 3 => 0xFFFFFFFF, // No PCI devices
        // Port 0x61
        0x61 => 0x20, // Timer 2 output high
        // VGA
        0x3C0...0x3DA => 0x00,
        // ELCR
        0x4D0, 0x4D1 => 0x00,
        else => 0xFF,
    };
}

fn handleCmosRead(index: u8) u32 {
    return switch (index) {
        // Memory size fields
        0x15 => 0x00, // Base memory low
        0x16 => 0x02, // Base memory high (512 KB)
        0x17 => 0x00, // Extended memory low
        0x18 => 0x00, // Extended memory high
        // RTC fields — return zeros (no real clock)
        0x00...0x09 => 0x00,
        0x0A => 0x26, // Status A: divider + rate
        0x0B => 0x02, // Status B: 24hr mode
        0x0C => 0x00, // Status C
        0x0D => 0x80, // Status D: valid RAM
        else => 0x00,
    };
}
