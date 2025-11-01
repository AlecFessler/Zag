const option = @import("option");
const std = @import("std");

const uefi = std.os.uefi;

pub const default_log_options = std.Options{
    .log_level = switch (option.log_level) {
        .debug => .debug,
        .info => .info,
        .warn => .warn,
        .err => .err,
    },
    .logFn = log,
};

pub var cout: *uefi.protocol.SimpleTextOutput = undefined;

pub fn init(con_out: *uefi.protocol.SimpleTextOutput) !void {
    cout = con_out;
    try cout.clearScreen();
}

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
