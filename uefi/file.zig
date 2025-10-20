const std = @import("std");

const uefi = std.os.uefi;

inline fn toUCS2(comptime str: [:0]const u8) [str.len * 2:0]u16 {
    var usc2: [str.len * 2:0]u16 = [_:0]u16{0} ** (str.len * 2);
    for (str, 0..) |char, i| {
        usc2[i] = char;
        usc2[i + 1] = 0;
    }
    return usc2;
}

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
