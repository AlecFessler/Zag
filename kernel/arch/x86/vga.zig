const std = @import("std");

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_SIZE = VGA_WIDTH * VGA_HEIGHT;

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

var row: usize = 0;
var column: usize = 0;
var color: u8 = 0;

pub fn initialize(foreground: VgaColor, background: VgaColor) void {
    setColor(foreground, background);
    clear();
}

pub fn clear() void {
    const buffer: [*]volatile u16 = @ptrFromInt(0xB8000);
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
    const buffer: [*]volatile u16 = @ptrFromInt(0xB8000);
    var temp_buf: [256]u8 = undefined;
    const out = std.fmt.bufPrint(
        temp_buf[0..],
        format,
        args,
    ) catch @panic("Print would be truncated!");
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
    const buffer: [*]volatile u16 = @ptrFromInt(0xB8000);
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
