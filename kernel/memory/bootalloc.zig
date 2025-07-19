//! Early boot bump allocator for physical memory under 2MiB
//! Starts at `_kernel_end`
//! Stops at 2MiB (identity-mapped boot memory)
//! Never frees individual allocations

const std = @import("std");

extern const _kernel_end: u8;

pub const BootAllocator = struct {
    free_addr: usize,
    end_addr: usize = 0x200000,

    pub fn init() BootAllocator {
        return BootAllocator{
            .free_addr = @intFromPtr(&_kernel_end),
        };
    }

    pub fn alloc(self: *BootAllocator, size: usize, alignment: usize) []u8 {
        const aligned = std.mem.alignForward(usize, self.free_addr, alignment);
        const new_end = aligned + size;

        if (new_end > self.end_addr) {
            @panic("BootAllocator out of memory");
        }

        self.free_addr = new_end;

        const ptr: [*]u8 = @ptrFromInt(aligned);
        return ptr[0..size];
    }
};
