const std = @import("std");

const paging = @import("paging.zig");

const VGA_BUFFER_PADDR = 0xB8000;
const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_SIZE = VGA_WIDTH * VGA_HEIGHT;
const TEMP_BUFFER_SIZE = 256;

pub const VgaColor = enum(u8) {
    Black,
    Blue,
    Green,
    Cyan,
    Red,
    Magenta,
    Brown,
    LightGray,
    DarkGray,
    LightBlue,
    LightGreen,
    LightCyan,
    LightRed,
    LightMagenta,
    Yellow,
    White,
};

var buffer: [*]volatile u16 = undefined;
var row: u64 = 0;
var column: u64 = 0;
var color: u8 = 0;

pub fn initialize(foreground: VgaColor, background: VgaColor) void {
    buffer = @ptrFromInt(paging.physToVirt(VGA_BUFFER_PADDR));
    setColor(foreground, background);
    clear();
}

pub fn clear() void {
    const blank = makeEntry(' ', color);
    for (0..VGA_SIZE) |i| {
        buffer[i] = blank;
    }
    row = 0;
    column = 0;
}

pub fn setColor(foreground: VgaColor, background: VgaColor) void {
    color = makeColor(foreground, background);
}

pub fn print(comptime format: []const u8, args: anytype) void {
    var temp_buffer: [TEMP_BUFFER_SIZE]u8 = undefined;
    const out = std.fmt.bufPrint(temp_buffer[0..], format, args) catch @panic("Print would be truncated!");
    for (out) |c| {
        if (c == '\n') {
            column = 0;
            row += 1;
        } else {
            const index = row * VGA_WIDTH + column;
            buffer[index] = makeEntry(c, color);
            column += 1;
        }

        if (column == VGA_WIDTH) {
            column = 0;
            row += 1;
        }

        if (row == VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
    }
}

fn scroll() void {
    for (0..VGA_HEIGHT - 1) |y| {
        for (0..VGA_WIDTH) |x| {
            buffer[y * VGA_WIDTH + x] = buffer[(y + 1) * VGA_WIDTH + x];
        }
    }

    const blank = makeEntry(' ', color);
    for (0..VGA_WIDTH) |x| {
        buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = blank;
    }
}

pub fn makeColor(foreground: VgaColor, background: VgaColor) u8 {
    return @intFromEnum(foreground) | (@intFromEnum(background) << 4);
}

pub fn makeEntry(c: u8, entry_color: u8) u16 {
    return c | (@as(u16, entry_color) << 8);
}
