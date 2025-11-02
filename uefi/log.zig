//! Minimal UEFI console logger for `std.log` integration.
//!
//! Provides a `std.log` backend that writes to UEFI `SimpleTextOutput`,
//! plus a module-level `std.Options` to set global log behavior. Initialize
//! once with `uefi_logger.init(system_table.con_out.?)`, then set
//! `pub const std_options = uefi_logger.default_log_options` in the caller.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - `uefi_logger.default_log_options` — default `std.log` configuration for UEFI boot code.
//!
//! ## Variables
//! - `uefi_logger.cout` — UEFI `SimpleTextOutput` handle used by the sink.
//!
//! ## Functions
//! - `uefi_logger.init` — initialize the logger with a console handle.
//! - `uefi_logger.log` — `std.log` sink that prints to UEFI text output.

const option = @import("option");
const std = @import("std");

const uefi = std.os.uefi;

/// Default `std.log` configuration for UEFI boot code.
///
/// Usage:
/// Set `pub const std_options = uefi_logger.default_log_options;` in the module
/// that owns the logger to route `std.log` to this sink.
pub const default_log_options = std.Options{
    .log_level = switch (option.log_level) {
        .debug => .debug,
        .info => .info,
        .warn => .warn,
        .err => .err,
    },
    .logFn = log,
};

/// UEFI console handle used by the logger. Must be set before logging.
pub var cout: *uefi.protocol.SimpleTextOutput = undefined;

/// Function: `uefi_logger.init`
///
/// Summary:
/// Initialize the logger with a UEFI console output handle and clear the screen.
///
/// Arguments:
/// - `con_out`: Pointer to `SimpleTextOutput` (e.g., `system_table.con_out.?`).
///
/// Returns:
/// - `!void`: Propagates errors from `clearScreen`.
///
/// Errors:
/// - `uefi` errors originating from `clearScreen`.
///
/// Panics:
/// - None.
///
/// Notes:
/// - Call this before any `std.log.*` usage that relies on this sink.
pub fn init(con_out: *uefi.protocol.SimpleTextOutput) !void {
    try con_out.clearScreen();
}

/// Function: `uefi_logger.log`
///
/// Summary:
/// `std.log` sink that prints to UEFI text output, formatting lines as
/// `[LEVEL] (scope): message\r\n` (scope omitted for `.default`).
///
/// Arguments:
/// - `level`: Compile-time log level (`std.log.Level`).
/// - `scope`: Compile-time scope tag (enum literal).
/// - `fmt`: Printf-style format string.
/// - `args`: Variadic arguments matched to `fmt`.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics on unexpected formatting or output failures.
///
/// Notes:
/// - Emits one UTF-16 code unit at a time via `outputString`, using a sentinel
///   `u16` slice per character.
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
    const str = std.fmt.bufPrint(&buf, level_str ++ " " ++ scope_str ++ fmt ++ "\r\n", args) catch unreachable;

    for (str) |char| {
        _ = cout.outputString(&[_:0]u16{char}) catch unreachable;
    }
}
