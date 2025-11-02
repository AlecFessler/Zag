//! UEFI file helpers: ASCII→UCS-2 path conversion and safe open wrapper.
//!
//! Provides a tiny adapter over `SimpleFileSystem.File.open` that accepts a
//! comptime ASCII file name, converts it to UCS-2 at comptime, and opens the
//! file read-only. Intended for bootloader use where file names are fixed.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `openFile` — open a read-only file by ASCII name (converts to UCS-2).
//! - `toUCS2` — convert comptime ASCII to UCS-2 buffer (private).

const std = @import("std");
const uefi = std.os.uefi;

/// Summary:
/// Open a file from a UEFI directory using a comptime ASCII path.
///
/// Arguments:
/// - `root`: already-opened UEFI directory handle (e.g., volume root).
/// - `name`: comptime, NUL-terminated ASCII path (e.g., "kernel.elf").
///
/// Returns:
/// - `*uefi.protocol.File` on success.
///
/// Errors:
/// - `error.aborted` on failure; logs the UEFI status code.
///
/// Panics:
/// - None.
pub fn openFile(
    root: *uefi.protocol.File,
    comptime name: [:0]const u8,
) !*uefi.protocol.File {
    const file: *uefi.protocol.File = root.open(
        &toUCS2(name),
        .read,
        .{},
    ) catch |err| {
        std.log.err("Failed to open file: {s} {}", .{ name, err });
        return error.aborted;
    };
    return file;
}

/// Summary:
/// Convert a comptime ASCII string to a UCS-2 buffer suitable for UEFI.
///
/// Arguments:
/// - `str`: comptime, NUL-terminated ASCII string.
///
/// Returns:
/// - A sentinel-terminated (`:0`) UCS-2 buffer sized `[str.len * 2:0]u16`,
///   widened from ASCII bytes.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn toUCS2(comptime str: [:0]const u8) [str.len * 2:0]u16 {
    var usc2: [str.len * 2:0]u16 = [_:0]u16{0} ** (str.len * 2);
    for (str, 0..) |char, i| {
        usc2[i] = char;
        usc2[i + 1] = 0;
    }
    return usc2;
}
