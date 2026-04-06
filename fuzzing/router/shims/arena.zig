const std = @import("std");

pub const Arena = struct {
    start_addr: u64,
    free_addr: u64,
    end_addr: u64,

    pub fn init(_: u64) ?Arena {
        return null;
    }

    pub fn allocator(_: *Arena) std.mem.Allocator {
        unreachable;
    }
};
