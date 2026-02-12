const std = @import("std");

pub const PageSize = enum(u64) {
    page4k = 0x1000,
    page2m = 0x200000,
    page1g = 0x40000000,
};

pub const PAGE4K: u64 = @intFromEnum(PageSize.page4k);
pub const PAGE2M: u64 = @intFromEnum(PageSize.page2m);
pub const PAGE1G: u64 = @intFromEnum(PageSize.page1g);

pub fn pageAlign(size: PageSize) std.mem.Alignment {
    return std.mem.Alignment.fromByteUnits(@intFromEnum(size));
}

pub fn PageMem(comptime size: PageSize) type {
    const size_bytes = @intFromEnum(size);
    return struct {
        mem: [size_bytes]u8 align(size_bytes),
    };
}
