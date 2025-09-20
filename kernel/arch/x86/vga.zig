//! Minimal VGA text mode console for freestanding environments.
//!
//! Provides character output to the VGA buffer at `0xB8000` in standard 80×25 text mode.
//! This module enables formatted printing using `std.fmt.format` under the hood, allowing
//! idiomatic Zig formatting even in early boot or freestanding kernel code.
//!
//! Primarily intended for debugging and early-stage output, including kernel panic messages.

const std = @import("std");
const fmt = std.fmt;
const Writer = std.io.Writer;

/// Number of character columns in standard VGA text mode (80 characters per row).
const VGA_WIDTH = 80;

/// Number of character rows in standard VGA text mode (25 lines on screen).
const VGA_HEIGHT = 25;

/// Total number of character cells on screen (80 columns × 25 rows = 2000 characters).
const VGA_SIZE = VGA_WIDTH * VGA_HEIGHT;

/// Represents a single VGA text mode character cell, combining an ASCII byte and a color byte.
/// The low 8 bits store the ASCII character, and the high 8 bits store the foreground/background color.
const VgaChar = u16;

/// VGA color values used for foreground and background attributes in text mode.
/// Each value corresponds to a 4-bit color understood by the VGA text buffer.
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

/// Current cursor row position in the VGA text buffer.
var row: usize = 0;

/// Current cursor column position in the VGA text buffer.
var column: usize = 0;

/// Current combined foreground/background color used for character output.
var color: u8 = 0;

/// Pointer to the VGA text buffer located at physical address 0xB8000.
/// Each entry is a `VgaChar` representing a single character cell on screen.
var buffer: [*]volatile VgaChar = @ptrFromInt(0xB8000);

/// Initializes the VGA console with the given foreground and background colors,
/// and clears the screen.
///
/// This should be called before any text output is attempted.
pub fn initialize(
    foreground: VgaColor,
    background: VgaColor,
) void {
    clear();
    setColor(foreground, background);
}

/// Clears the entire screen by filling the VGA text buffer with spaces,
/// using the current color setting. Resets the cursor to the top-left corner.
pub fn clear() void {
    const blank = makeEntry(' ', color);
    @memset(buffer[0..VGA_SIZE], blank);
    row = 0;
    column = 0;
}

/// Sets the current text color used for future character output.
///
/// The color is a packed byte combining the foreground and background `VgaColor` values.
pub fn setColor(
    foreground: VgaColor,
    background: VgaColor,
) void {
    color = makeColor(foreground, background);
}

/// Writes formatted text to the VGA text buffer using the current cursor position and color.
///
/// This function uses `std.fmt.format` for formatting, but targets the VGA buffer instead of a stream.
/// Newlines are handled automatically, and the screen will scroll if output exceeds the bottom row.
///
/// - `format`: A compile-time format string.
/// - `args`: Arguments interpolated into the format string.
pub fn print(comptime format: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;

    var fw: std.Io.Writer = std.Io.Writer.fixed(buf[0..]);

    const w: *std.Io.Writer = &fw;
    w.print(format, args) catch unreachable;
    w.flush() catch unreachable;

    const out = buf[0..fw.end];
    for (out) |c| {
        if (c == '\n') {
            column = 0;
            row += 1;
        } else {
            const i = row * VGA_WIDTH + column;
            buffer[i] = makeEntry(c, color);
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

/// Scrolls the VGA text buffer up by one row, discarding the top line and clearing the bottom.
///
/// The bottom row is filled with blank spaces using the current color.
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

/// Combines a foreground and background `VgaColor` into a single VGA attribute byte.
///
/// The foreground occupies the low 4 bits, and the background occupies the high 4 bits.
fn makeColor(
    foreground: VgaColor,
    background: VgaColor,
) u8 {
    return @intFromEnum(foreground) | (@intFromEnum(background) << 4);
}

/// Constructs a `VgaChar` from an ASCII character and a VGA attribute byte.
///
/// The character byte occupies the low 8 bits, and the color occupies the high 8 bits.
fn makeEntry(
    c: u8,
    entry_color: u8,
) VgaChar {
    return c | (@as(VgaChar, entry_color) << 8);
}
