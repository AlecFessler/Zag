//! Monotonic bump allocator for a fixed address range.
//!
//! Owns a contiguous region and returns aligned slices by advancing a single
//! pointer. No deallocation; only growth until the end of the region. Useful
//! during early boot/bring-up or as a simple backing allocator for metadata.
//!
//! # Directory
//!
//! ## Type Definitions
//! - BumpAllocator – monotonic allocator over a `[start, end)` region.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - BumpAllocator.init – construct a bump allocator for a region.
//! - BumpAllocator.allocator – expose as `std.mem.Allocator`.
//! - BumpAllocator.alloc – vtable entry: allocate (monotonic grow).
//! - BumpAllocator.resize – vtable entry: unsupported (traps).
//! - BumpAllocator.remap – vtable entry: unsupported (traps).
//! - BumpAllocator.free – vtable entry: unsupported (traps).

const std = @import("std");

/// Monotonic allocator over a half-open `[start, end)` address range.
pub const BumpAllocator = struct {
    start_addr: u64,
    free_addr: u64,
    end_addr: u64,

    /// Summary:
    /// Initializes a bump allocator over `[start_addr, end_addr)`.
    ///
    /// Arguments:
    /// - start_addr: Start of the region (inclusive).
    /// - end_addr: End of the region (exclusive). Must be `> start_addr`.
    ///
    /// Returns:
    /// - `BumpAllocator`: New allocator with `free_addr = start_addr`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Panics if `end_addr <= start_addr` (failed precondition).
    pub fn init(start_addr: u64, end_addr: u64) BumpAllocator {
        std.debug.assert(end_addr > start_addr);

        return .{
            .start_addr = start_addr,
            .free_addr = start_addr,
            .end_addr = end_addr,
        };
    }

    /// Summary:
    /// Exposes this allocator as a `std.mem.Allocator`.
    ///
    /// Arguments:
    /// - self: Allocator instance.
    ///
    /// Returns:
    /// - `std.mem.Allocator`: Vtable whose operations dispatch to this bump allocator.
    ///   `resize`, `remap`, and `free` are unsupported and trap.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

    /// Summary:
    /// `std.mem.Allocator.alloc` entry point. Advances `free_addr` monotonically
    /// and returns an aligned pointer to uninitialized memory.
    ///
    /// Arguments:
    /// - ptr: Opaque pointer to `BumpAllocator` (provided by vtable).
    /// - len: Requested size in bytes.
    /// - alignment: Required alignment for the returned pointer.
    /// - ret_addr: Caller return address for diagnostics (unused).
    ///
    /// Returns:
    /// - `?[*]u8`: Non-null on success; `null` if the region would overflow.
    ///
    /// Errors:
    /// - None (uses nullable return instead of error codes).
    ///
    /// Panics:
    /// - None.
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

    /// Summary:
    /// `std.mem.Allocator.resize` entry point (unsupported for bump allocators).
    ///
    /// Arguments:
    /// - ptr: Opaque pointer (ignored).
    /// - memory: Previously allocated slice (ignored).
    /// - alignment: Required alignment (ignored).
    /// - new_len: Requested new length (ignored).
    /// - ret_addr: Caller return address (ignored).
    ///
    /// Returns:
    /// - `bool`: Never returns; traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Always panics (traps with `unreachable`).
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

    /// Summary:
    /// `std.mem.Allocator.remap` entry point (unsupported for bump allocators).
    ///
    /// Arguments:
    /// - ptr: Opaque pointer (ignored).
    /// - memory: Previously allocated slice (ignored).
    /// - alignment: Required alignment (ignored).
    /// - new_len: Requested new length (ignored).
    /// - ret_addr: Caller return address (ignored).
    ///
    /// Returns:
    /// - `?[*]u8`: Never returns; traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Always panics (traps with `unreachable`).
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

    /// Summary:
    /// `std.mem.Allocator.free` entry point (unsupported for bump allocators).
    ///
    /// Arguments:
    /// - ptr: Opaque pointer (ignored).
    /// - buf: Slice to free (ignored).
    /// - alignment: Alignment (ignored).
    /// - ret_addr: Caller return address (ignored).
    ///
    /// Returns:
    /// - `void`: Never returns; traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Always panics (traps with `unreachable`).
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
