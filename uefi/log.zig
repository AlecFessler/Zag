//! Minimal UEFI console logger for `std.log` integration.
//!
//! Provides a `std.log` backend that writes to UEFI `SimpleTextOutput`,
//! plus a module-level `std.Options` to set the global log behavior.
//! Initialize once with `init(system_table.con_out.?)`, then set
//! `pub const std_options = default_log_options` in the caller module.

const option = @import("option");
const std = @import("std");

const uefi = std.os.uefi;

/// Default `std.log` configuration for UEFI boot code.
///
/// Usage:
/// - In the main module, set `pub const std_options = default_log_options;`
///   so that `std.log` uses this sink.
pub const default_log_options = std.Options{
    .log_level = switch (option.log_level) {
        .debug => .debug,
        .info => .info,
        .warn => .warn,
        .err => .err,
    },
    .logFn = log,
};

/// UEFI console handle used by the logger.
///
/// Set by `init`; required before any logging occurs.
pub var cout: *uefi.protocol.SimpleTextOutput = undefined;

/// Initialize the logger with a UEFI console output handle.
///
/// Arguments:
/// - `con_out`: pointer to `SimpleTextOutput` (e.g., `system_table.con_out.?`).
///
/// Returns:
/// - `!void` — propagates errors from `clearScreen`.
///
/// Effects:
/// - Clears the screen to provide a fresh log surface.
pub fn init(con_out: *uefi.protocol.SimpleTextOutput) !void {
    try con_out.clearScreen();
}

/// `std.log` sink that prints to UEFI text output (CRLF-terminated).
///
/// Formats messages as:
/// `[LEVEL] (scope): message\r\n`
/// where `scope` is omitted for `.default`.
///
/// Arguments:
/// - `level`: compile-time log level (`std.log.Level`).
/// - `scope`: compile-time scope tag (enum literal).
/// - `fmt`: printf-style format string.
/// - `args`: variadic arguments matched to `fmt`.
///
/// Returns:
/// - `void`. Panics on unexpected formatting or output failures.
///
/// Notes:
/// - Converts the formatted line and emits it one code unit at a time via
///   `outputString`, using a sentinel `u16` slice per character.
fn log(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime fmt: []const u8,
    args: anytype,
) void {
    const level_str = comptime switch (level) {
        .debug => "[DEBUG]",
        .info => "[INFO ]",
        .warn => "[WARN ]",
        .err => "[ERROR]",
    };
    const scope_str = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    var buf: [256]u8 = undefined;
    const str = std.fmt.bufPrint(
        &buf,
        level_str ++ " " ++ scope_str ++ fmt ++ "\r\n",
        args,
    ) catch unreachable;

    for (str) |char| {
        _ = cout.outputString(&[_:0]u16{char}) catch unreachable;
    }
}
