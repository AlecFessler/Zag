/// COM1 serial port emulation (0x3F8-0x3FF).
/// Forwards guest TX data to Zag's serial console.
/// Presents as a basic 16550-compatible UART.

const lib = @import("lib");

const syscall = lib.syscall;

const GuestState = @import("main.zig").GuestState;

// COM1 register offsets from base 0x3F8
const COM1_BASE: u16 = 0x3F8;
const COM1_DATA: u16 = 0x3F8; // TX/RX data (DLAB=0) or DLL (DLAB=1)
const COM1_IER: u16 = 0x3F9; // Interrupt enable (DLAB=0) or DLM (DLAB=1)
const COM1_IIR: u16 = 0x3FA; // Interrupt identification (read) / FCR (write)
const COM1_LCR: u16 = 0x3FB; // Line control
const COM1_MCR: u16 = 0x3FC; // Modem control
const COM1_LSR: u16 = 0x3FD; // Line status
const COM1_MSR: u16 = 0x3FE; // Modem status
const COM1_SCR: u16 = 0x3FF; // Scratch register

// Shadow state
var lcr: u8 = 0;
var mcr: u8 = 0;
var ier: u8 = 0;
var dll: u8 = 0;
var dlm: u8 = 0;
var scr: u8 = 0;

fn dlab() bool {
    return (lcr & 0x80) != 0;
}

pub fn isSerialPort(port: u16) bool {
    return port >= COM1_BASE and port <= COM1_SCR;
}

pub fn handleOut(port: u16, value: u8) void {
    switch (port) {
        COM1_DATA => {
            if (dlab()) {
                dll = value;
            } else {
                // Transmit character to Zag serial
                const ch: [1]u8 = .{value};
                syscall.write(&ch);
            }
        },
        COM1_IER => {
            if (dlab()) {
                dlm = value;
            } else {
                ier = value;
            }
        },
        COM1_IIR => {}, // FCR write — ignore
        COM1_LCR => lcr = value,
        COM1_MCR => mcr = value,
        COM1_SCR => scr = value,
        else => {},
    }
}

pub fn handleIn(port: u16) u32 {
    return switch (port) {
        COM1_DATA => if (dlab()) @as(u32, dll) else 0xFF,
        COM1_IER => if (dlab()) @as(u32, dlm) else @as(u32, ier),
        COM1_IIR => 0x01, // No interrupt pending, 16550 FIFO
        COM1_LCR => lcr,
        COM1_MCR => mcr,
        COM1_LSR => 0x60, // TX empty + TX holding register empty (always ready)
        COM1_MSR => 0xB0, // CTS + DSR + DCD asserted
        COM1_SCR => scr,
        else => 0xFF,
    };
}
