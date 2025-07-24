const std = @import("std");

pub const PhysicalMemoryManager = struct {
    backing_allocator: *std.mem.Allocator,

    pub fn init(backing_allocator: *std.mem.Allocator) PhysicalMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    pub fn allocator(self: *PhysicalMemoryManager) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawAlloc(
            len,
            alignment,
            ret_addr,
        );
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawResize(
            memory,
            alignment,
            new_len,
            ret_addr,
        );
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawRemap(
            memory,
            alignment,
            new_len,
            ret_addr,
        );
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        self.backing_allocator.rawFree(
            buf,
            alignment,
            ret_addr,
        );
    }
};
