//! Early boot bump allocator for physical memory under 2MiB
//! Starts at `_kernel_end`
//! Stops at 2MiB (identity-mapped boot memory)
//! Never frees individual allocations

const std = @import("std");

const Allocator = @import("allocator.zig").Allocator;

extern const _kernel_end: u8;

pub const BootAllocator = struct {
    allocator: Allocator,
    free_addr: usize,
    end_addr: usize,

    pub fn init(self: *BootAllocator) void {
        const end_addr = 0x200000;
        const free_addr = @intFromPtr(&_kernel_end);
        const ptr: [*]u8 = @ptrFromInt(free_addr);
        const free_size = end_addr - free_addr;
        const slice = ptr[0..free_size];
        @memset(slice, 0);

        self.* = BootAllocator{
            .allocator = undefined,
            .free_addr = free_addr,
            .end_addr = end_addr,
        };

        self.allocator = Allocator.init(self, BootAllocator.alloc);
    }

    fn alloc(ctx: *anyopaque, size: usize, alignment: usize) [*]u8 {
        std.debug.assert(std.mem.isAligned(size, 8));

        const self: *BootAllocator = @alignCast(@ptrCast(ctx));

        const aligned = std.mem.alignForward(usize, self.free_addr, alignment);
        const new_end = aligned + size;

        if (new_end > self.end_addr) {
            @panic("BootAllocator out of memory");
        }

        self.free_addr = new_end;

        return @ptrFromInt(aligned);
    }
};
