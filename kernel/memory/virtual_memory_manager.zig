const allocator_interface = @import("allocator.zig");

const Allocator = allocator_interface.Allocator;
const AllocationError = allocator_interface.AllocationError;

pub const VirtualMemoryManager = struct {
    backing_allocator: *Allocator,

    pub fn init(backing_allocator: *Allocator) VirtualMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    pub fn allocator(self: *VirtualMemoryManager) Allocator {
        return .{
            .ctx = self,
            .vtable = &.{
                .alloc = alloc,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, bytes: usize, alignment: usize) AllocationError![*]u8 {
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ctx));
        return self.backing_allocator.alloc(bytes, alignment);
    }

    fn free(ctx: *anyopaque, addr: usize) void {
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ctx));
        self.backing_allocator.free(addr);
    }
};
