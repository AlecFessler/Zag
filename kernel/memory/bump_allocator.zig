const std = @import("std");

/// Owning allocator. Manages a contiguous address space, does not take a backing allocator, can act as a backing allocator;
pub const BumpAllocator = struct {
    start_addr: usize,
    free_addr: usize,
    end_addr: usize,

    pub fn init(start_addr: usize, end_addr: usize) BumpAllocator {
        std.debug.assert(end_addr > start_addr);

        return .{
            .start_addr = start_addr,
            .free_addr = start_addr,
            .end_addr = end_addr,
        };
    }

    pub fn allocator(self: *BumpAllocator) std.mem.Allocator {
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
        _ = ret_addr;
        const self: *BumpAllocator = @alignCast(@ptrCast(ptr));

        const aligned = std.mem.alignForward(
            usize,
            self.free_addr,
            alignment.toByteUnits(),
        );
        const free_addr = aligned + len;

        if (free_addr > self.end_addr) {
            return null;
        }

        self.free_addr = free_addr;
        return @ptrFromInt(aligned);
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
        return false;
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
        return null;
    }

    // no op
    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = ptr;
        _ = buf;
        _ = alignment;
        _ = ret_addr;
    }
};
