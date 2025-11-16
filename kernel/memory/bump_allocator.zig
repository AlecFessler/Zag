const std = @import("std");

pub const BumpAllocator = struct {
    start_addr: u64,
    free_addr: u64,
    end_addr: u64,

    pub fn init(start_addr: u64, end_addr: u64) BumpAllocator {
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
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *BumpAllocator = @alignCast(@ptrCast(ptr));

        const aligned = std.mem.alignForward(
            u64,
            self.free_addr,
            alignment.toByteUnits(),
        );
        const next_free = aligned + len;

        if (next_free > self.end_addr) {
            return null;
        }

        self.free_addr = next_free;
        return @ptrFromInt(aligned);
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
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
        ret_addr: u64,
    ) void {
        _ = ptr;
        _ = buf;
        _ = alignment;
        _ = ret_addr;
        unreachable;
    }
};
