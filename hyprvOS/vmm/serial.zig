/// COM1 serial port emulation (0x3F8-0x3FF).
/// Bridges guest serial I/O to Zag's host serial port:
///   TX: guest OUT 0x3F8 → host serial write
///   RX: host serial read → guest IN 0x3F8
/// Presents as a 16550-compatible UART.

const lib = @import("lib");

const log = @import("log.zig");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const GuestState = @import("main.zig").GuestState;

// COM1 port addresses
const COM1_BASE: u16 = 0x3F8;
const COM1_DATA: u16 = 0x3F8;
const COM1_IER: u16 = 0x3F9;
const COM1_IIR: u16 = 0x3FA;
const COM1_LCR: u16 = 0x3FB;
const COM1_MCR: u16 = 0x3FC;
const COM1_LSR: u16 = 0x3FD;
const COM1_MSR: u16 = 0x3FE;
const COM1_SCR: u16 = 0x3FF;

// Host serial register offsets
const REG_DATA: u64 = 0;
const REG_LSR: u64 = 5;
const LSR_DATA_READY: u8 = 0x01;

// Guest-side shadow state
var lcr: u8 = 0;
var mcr: u8 = 0;
var ier: u8 = 0;

// Interrupt pending flag — set when we need to inject IRQ4
pub var irq_pending: bool = false;
var dll: u8 = 0;
var dlm: u8 = 0;
var scr: u8 = 0;

// Host serial device handle (0 = not found)
var host_serial_handle: u64 = 0;

// RX buffer: circular buffer for host→guest data
var rx_buf: [256]u8 = undefined;
var rx_head: u8 = 0; // next write position
var rx_tail: u8 = 0; // next read position

fn dlab() bool {
    return (lcr & 0x80) != 0;
}

fn rxHasData() bool {
    return rx_head != rx_tail;
}

fn rxPush(byte: u8) void {
    const next = rx_head +% 1;
    if (next == rx_tail) return; // buffer full, drop
    rx_buf[rx_head] = byte;
    rx_head = next;
}

fn rxPop() u8 {
    if (!rxHasData()) return 0;
    const byte = rx_buf[rx_tail];
    rx_tail +%= 1;
    return byte;
}

/// Initialize: find the host serial device handle from perm_view.
pub noinline fn init(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and
            view[i].deviceClass() == @intFromEnum(perms.DeviceClass.serial) and
            view[i].deviceType() == 1) // PIO device
        {
            host_serial_handle = view[i].handle;
            log.print("serial: host handle=");
            log.dec(host_serial_handle);
            log.print("\n");
            return;
        }
    }
    log.print("serial: no host serial device found\n");
}

/// Poll host serial for available data and buffer it.
/// Call this periodically from the exit loop.
pub fn pollHostRx() void {
    if (host_serial_handle == 0) return;

    // Check host LSR for data ready
    const lsr_val = syscall.ioport_read(host_serial_handle, REG_LSR, 1);
    if (lsr_val < 0) return;
    if (@as(u8, @truncate(@as(u64, @bitCast(lsr_val)))) & LSR_DATA_READY == 0) return;

    // Read the byte
    const data_val = syscall.ioport_read(host_serial_handle, REG_DATA, 1);
    if (data_val < 0) return;
    rxPush(@truncate(@as(u64, @bitCast(data_val))));
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
                // TX: forward to Zag serial
                const ch: [1]u8 = .{value};
                syscall.write(&ch);
                // Signal TX complete interrupt if IER has THRE enabled (bit 1)
                if (ier & 0x02 != 0) {
                    irq_pending = true;
                }
            }
        },
        COM1_IER => {
            if (dlab()) {
                dlm = value;
            } else {
                ier = value;
            }
        },
        COM1_IIR => {},
        COM1_LCR => lcr = value,
        COM1_MCR => mcr = value,
        COM1_SCR => scr = value,
        else => {},
    }
}

pub fn handleIn(port: u16) u32 {
    return switch (port) {
        COM1_DATA => blk: {
            if (dlab()) {
                break :blk @as(u32, dll);
            }
            // RX: return buffered byte from host serial
            break :blk @as(u32, rxPop());
        },
        COM1_IER => if (dlab()) @as(u32, dlm) else @as(u32, ier),
        COM1_IIR => blk: {
            // IIR: bits 3:1 = interrupt ID, bit 0 = 0 if interrupt pending
            if (irq_pending) {
                irq_pending = false; // Reading IIR clears the interrupt
                break :blk @as(u32, 0x02); // TX holding register empty interrupt
            }
            if (rxHasData() and (ier & 0x01 != 0)) {
                break :blk @as(u32, 0x04); // RX data available interrupt
            }
            break :blk @as(u32, 0x01); // No interrupt pending
        },
        COM1_LCR => lcr,
        COM1_MCR => mcr,
        COM1_LSR => blk: {
            // Bit 0: Data Ready (RX buffer has data)
            // Bit 5: TX holding register empty (always ready)
            // Bit 6: TX empty (always ready)
            var lsr_val: u32 = 0x60; // TX empty + TX holding empty
            if (rxHasData()) {
                lsr_val |= 0x01; // Data ready
            }
            break :blk lsr_val;
        },
        COM1_MSR => 0xB0, // CTS + DSR + DCD
        COM1_SCR => scr,
        else => 0xFF,
    };
}
