const std = @import("std");

pub const PAGE_ALIGN = std.mem.Alignment.fromByteUnits(PAGE4K);

pub const PAGE4K: u64 = 0x1000;
pub const PAGE2M: u64 = 0x200000;
pub const PAGE1G: u64 = 0x40000000;
