const std = @import("std");

pub const PhysicalMemoryManager = struct {
    backing_allocator: std.mem.Allocator,

    pub fn allocator(self: *PhysicalMemoryManager) std.mem.Allocator {
        return self.backing_allocator;
    }
};

pub var global_pmm: ?PhysicalMemoryManager = .{
    .backing_allocator = std.heap.page_allocator,
};
