const std = @import("std");

const allocator_interface = @import("allocator.zig");

const Allocator = allocator_interface.Allocator;
const AllocationError = allocator_interface.AllocationError;

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

    pub fn allocator(self: *BumpAllocator) Allocator {
        return .{
            .ctx = self,
            .vtable = &.{
                .alloc = alloc,
                .free = free,
                .deinit = deinit,
            },
        };
    }

    fn alloc(ctx: *anyopaque, n: usize, alignment: usize) AllocationError![*]u8 {
        const self: *BumpAllocator = @alignCast(@ptrCast(ctx));

        const aligned = std.mem.alignForward(usize, self.free_addr, alignment);
        const free_addr = aligned + n;

        if (free_addr > self.end_addr) {
            return AllocationError.OutOfMemory;
        }

        self.free_addr = free_addr;
        return @ptrFromInt(aligned);
    }

    fn free(ctx: *anyopaque, addr: usize) void {
        _ = ctx;
        _ = addr;
    }

    fn deinit(ctx: *anyopaque) void {
        _ = ctx;
    }
};
