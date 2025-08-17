const std = @import("std");

/// Delegating allocator. Requires a backing allocator, can also act as a backing allocator.
pub const VirtualMemoryManager = struct {
    backing_allocator: std.mem.Allocator,

    pub fn init(backing_allocator: std.mem.Allocator) VirtualMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    pub fn allocator(self: *VirtualMemoryManager) std.mem.Allocator {
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
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawAlloc(
            len,
            alignment,
            ret_addr,
        );
    }

    // no op
    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    // no op
    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ptr));
        self.backing_allocator.rawFree(
            buf,
            alignment,
            ret_addr,
        );
    }
};
