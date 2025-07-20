//! Early boot-time bump allocator for the kernel.
//!
//! This module defines a simple linear allocator used during early kernel initialization,
//! before paging and dynamic memory management are fully available. It allocates memory
//! from a fixed region starting at the end of the kernel image (`_kernel_end`) and ending
//! at 2 MiB, the range identity-mapped by the bootstrap shim.
//!
//! The `BootAllocator` conforms to the kernel's custom `Allocator` interface and is intended
//! for one-way allocation only — individual allocations cannot be freed. It is suitable for
//! setting up initial data structures such as page tables, region lists, and other static
//! kernel components during boot.

const std = @import("std");

const allocator_interface = @import("allocator.zig");
const Allocator = allocator_interface.Allocator;

/// Symbol marking the end of the kernel’s `.bss` section, defined in the linker script.
///
/// The boot allocator begins allocating memory immediately after this address,
/// assuming the kernel and its static data have been fully loaded below it.
extern const _kernel_end: u8;

/// A simple bump allocator used during early kernel initialization.
///
/// `BootAllocator` is designed to allocate memory linearly from a fixed region starting
/// immediately after the kernel image. It does not support freeing memory and is intended
/// only for one-way allocation during boot. It conforms to the kernel’s custom `Allocator`
/// interface and is intended to be used before more advanced memory management is available.
pub const BootAllocator = struct {
    allocator: Allocator,
    free_addr: usize,
    end_addr: usize,

    /// Initializes the boot allocator to use memory between the end of the kernel image
    /// (defined by `_kernel_end`) and the 2 MiB mark.
    ///
    /// The upper bound of 2 MiB is chosen because the bootstrap shim maps exactly one
    /// 2 MiB identity-mapped page for early kernel use. The allocator zeroes out this
    /// entire available region before use.
    pub fn init(self: *BootAllocator) void {
        const end_addr = 0x200000; // 2MiB identity mapped memory
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

        self.allocator = Allocator.init(
            self,
            BootAllocator.alloc,
        );
    }

    /// Allocates a block of memory using bump allocation semantics.
    ///
    /// This function implements the kernel's `Allocator` interface. It aligns the
    /// allocation as requested and panics if there is insufficient space left in the
    /// mapped region. Running out of memory here typically means the bootstrap shim
    /// needs to identity-map additional pages so the kernel can continue initialization.
    fn alloc(
        ctx: *anyopaque,
        size: usize,
        alignment: usize,
    ) [*]u8 {
        const self: *BootAllocator = @alignCast(@ptrCast(ctx));

        const aligned = std.mem.alignForward(
            usize,
            self.free_addr,
            alignment,
        );
        const new_end = aligned + size;

        if (new_end > self.end_addr) {
            @panic("BootAllocator out of memory");
        }

        self.free_addr = new_end;

        return @ptrFromInt(aligned);
    }
};
