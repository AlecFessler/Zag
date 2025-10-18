//! Monotonic bump allocator for a fixed address range.
//!
//! Owns a contiguous region and returns aligned slices by advancing a single
//! pointer. No deallocation; only growth until the end of the region. Useful
//! during early boot/bring-up or as a simple backing allocator for metadata.

const std = @import("std");

/// Owning allocator. Manages a contiguous address space; does not take a
/// backing allocator; can itself be used as a backing allocator.
///
/// Fields:
/// - `start_addr`: start of the managed range (inclusive).
/// - `free_addr`: next allocation will begin at or after this address.
/// - `end_addr`: end of the managed range (exclusive).
pub const BumpAllocator = struct {
    start_addr: u64,
    free_addr: u64,
    end_addr: u64,

    /// Initializes a bump allocator over `[start_addr, end_addr)`.
    ///
    /// Arguments:
    /// - `start_addr`: start of the region (inclusive).
    /// - `end_addr`: end of the region (exclusive). Must be `> start_addr`.
    ///
    /// Returns:
    /// - A `BumpAllocator` with `free_addr = start_addr`.
    pub fn init(start_addr: u64, end_addr: u64) BumpAllocator {
        std.debug.assert(end_addr > start_addr);

        return .{
            .start_addr = start_addr,
            .free_addr = start_addr,
            .end_addr = end_addr,
        };
    }

    /// Exposes this allocator as a `std.mem.Allocator`.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    ///
    /// Returns:
    /// - A `std.mem.Allocator` whose vtable redirects to this bump allocator.
    ///   `resize`, `remap`, and `free` trap (unsupported).
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

    /// `std.mem.Allocator.alloc` entry point.
    ///
    /// Grows `free_addr` monotonically. The returned pointer is aligned to the
    /// requested `alignment`. Memory is not zeroed.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to `BumpAllocator` (provided by vtable).
    /// - `len`: requested size in bytes.
    /// - `alignment`: required alignment for the returned pointer.
    /// - `ret_addr`: caller return address for diagnostics (unused).
    ///
    /// Returns:
    /// - `[*]u8` pointer on success, or `null` if the region would overflow.
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
        const free_addr = aligned + len;

        if (free_addr > self.end_addr) {
            return null;
        }

        self.free_addr = free_addr;
        return @ptrFromInt(aligned);
    }

    /// `std.mem.Allocator.resize` entry point (unsupported).
    ///
    /// A bump allocator cannot grow/shrink in place; this always traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `memory`: previously allocated slice (ignored).
    /// - `alignment`: required alignment (ignored).
    /// - `new_len`: requested new length (ignored).
    /// - `ret_addr`: caller return address (ignored).
    ///
    /// Returns:
    /// - Never returns; traps with `unreachable`.
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

    /// `std.mem.Allocator.remap` entry point (unsupported).
    ///
    /// A bump allocator cannot remap; this always traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `memory`: previously allocated slice (ignored).
    /// - `alignment`: required alignment (ignored).
    /// - `new_len`: requested new length (ignored).
    /// - `ret_addr`: caller return address (ignored).
    ///
    /// Returns:
    /// - Never returns; traps with `unreachable`.
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

    /// `std.mem.Allocator.free` entry point (unsupported).
    ///
    /// Bump allocators don’t free individual allocations; this always traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `buf`: slice to free (ignored).
    /// - `alignment`: alignment (ignored).
    /// - `ret_addr`: caller return address (ignored).
    ///
    /// Returns:
    /// - Nothing; traps with `unreachable`.
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
