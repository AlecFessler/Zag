const std = @import("std");
const memory = @import("memory");
const PAddr = memory.address.PAddr;

pub const SharedMemory = struct {
    pages: []PAddr,
    refcount: std.atomic.Value(u32),

    pub fn size(self: *const SharedMemory) u64 {
        return self.pages.len * 0x1000;
    }
};
