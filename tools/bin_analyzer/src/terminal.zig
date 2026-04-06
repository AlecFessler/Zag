const std = @import("std");

pub const WinSize = struct { rows: u16, cols: u16 };

pub fn enableRawMode(fd: std.posix.fd_t, orig: std.posix.termios) void {
    var raw = orig;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ISIG = false;
    raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
    raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
    std.posix.tcsetattr(fd, .FLUSH, raw) catch {};
}

pub fn getWinSize(fd: std.posix.fd_t) WinSize {
    var ws: std.posix.winsize = undefined;
    const rc = std.posix.system.ioctl(fd, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
    if (rc == 0) {
        return .{ .rows = ws.row, .cols = ws.col };
    }
    return .{ .rows = 24, .cols = 80 };
}
