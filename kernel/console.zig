const std = @import("std");
const fmt = std.fmt;
const Writer = std.io.Writer;

const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_SIZE = VGA_WIDTH * VGA_HEIGHT;

const VgaChar = u16;

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
var buffer: [*]volatile VgaChar = @ptrFromInt(0xB8000);

pub fn initialize(
    foreground: VgaColor,
    background: VgaColor,
) void {
    clear();
    setColor(foreground, background);
}

pub fn clear() void {
    const blank = makeEntry(' ', color);
    @memset(buffer[0..VGA_SIZE], blank);
    row = 0;
    column = 0;
}

pub fn setColor(
    foreground: VgaColor,
    background: VgaColor,
) void {
    color = makeColor(foreground, background);
}

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    const w = Writer(
        void,
        error{},
        printCallback,
    ){ .context = {} };
    fmt.format(
        w,
        format,
        args,
    ) catch unreachable;
}

fn printCallback(
    _: void,
    string: []const u8,
) error{}!usize {
    for (string) |c| {
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
    return string.len;
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

fn makeColor(
    foreground: VgaColor,
    background: VgaColor,
) u8 {
    return @intFromEnum(foreground) | (@intFromEnum(background) << 4);
}

fn makeEntry(
    c: u8,
    entry_color: u8,
) VgaChar {
    return c | (@as(VgaChar, entry_color) << 8);
}
