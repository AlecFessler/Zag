//! Physical memory manager.
//!
//! Thin wrapper over a backing `std.mem.Allocator` to represent the PMM
//! until a real frame allocator lands. Exposes a `std.mem.Allocator`
//! interface for early boot and low-level subsystems.

const std = @import("std");

/// Physical memory manager backed by a delegate allocator.
///
/// Fields:
/// - `backing_allocator`: allocator used for physical allocations.
pub const PhysicalMemoryManager = struct {
    backing_allocator: std.mem.Allocator,

    /// Initializes a PMM that delegates to `backing_allocator`.
    ///
    /// Arguments:
    /// - `backing_allocator`: allocator to fulfill PMM requests.
    ///
    /// Returns:
    /// - A `PhysicalMemoryManager` instance.
    pub fn init(backing_allocator: std.mem.Allocator) PhysicalMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    /// Returns a `std.mem.Allocator` interface backed by this PMM.
    ///
    /// Arguments:
    /// - `self`: PMM instance.
    ///
    /// Returns:
    /// - A `std.mem.Allocator` whose vtable dispatches to this PMM.
    ///   `resize` and `remap` are unsupported (trap).
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

    /// `std.mem.Allocator.alloc` entry point.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to the `PhysicalMemoryManager`.
    /// - `len`: size in bytes to allocate.
    /// - `alignment`: required alignment.
    /// - `ret_addr`: caller return address (for diagnostics).
    ///
    /// Returns:
    /// - Pointer to `len` bytes on success, or `null` on OOM.
    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawAlloc(len, alignment, ret_addr);
    }

    /// `std.mem.Allocator.resize` entry point (unsupported).
    ///
    /// Always traps; PMM does not support in-place growth/shrink.
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

    /// `std.mem.Allocator.remap` entry point (unsupported).
    ///
    /// Always traps; PMM does not support remapping.
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

    /// `std.mem.Allocator.free` entry point.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to the `PhysicalMemoryManager`.
    /// - `buf`: slice previously returned by `alloc`.
    /// - `alignment`: alignment used at allocation time.
    /// - `ret_addr`: caller return address (for diagnostics).
    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        self.backing_allocator.rawFree(buf, alignment, ret_addr);
    }
};

/// Global physical memory manager instance.
/// Used primarily by the page fault handler and low-level allocators.
pub var global_pmm: ?PhysicalMemoryManager = null;
