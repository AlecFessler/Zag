//! UEFI-backed single-page allocator for page table mapping.
//!
//! Wraps UEFI `BootServices.allocatePages` as a `std.mem.Allocator` so
//! paging helpers (e.g., `mapPage`) can request page-sized (4 KiB) buffers
//! via the standard interface. This allocator:
//! - Allocates exactly one 4 KiB page per request.
//! - Requires `alignment == 4096` and `len == 4096`.
//! - Does not support `resize`, `remap`, or `free` (these trap).
//!
//! Notes:
//! - Allocations are tagged with the provided UEFI `MemoryType`.
//! - Memory is returned untracked by this wrapper; freeing via this API traps.

const std = @import("std");

const uefi = std.os.uefi;

/// Thin wrapper around UEFI Boot Services for 4 KiB page allocations.
///
/// Fields:
/// - `boot`: pointer to UEFI Boot Services
/// - `mem_type`: UEFI memory type used for page allocations
pub const PageAllocator = struct {
    boot: *uefi.tables.BootServices,
    mem_type: uefi.tables.MemoryType,

    /// Initialize a `PageAllocator` with a boot services handle and memory type.
    ///
    /// Arguments:
    /// - `boot`: UEFI Boot Services pointer.
    /// - `mem_type`: UEFI memory classification for allocations.
    ///
    /// Returns:
    /// - A `PageAllocator` ready to expose a `std.mem.Allocator`.
    pub fn init(
        boot: *uefi.tables.BootServices,
        mem_type: uefi.tables.MemoryType,
    ) PageAllocator {
        return .{
            .boot = boot,
            .mem_type = mem_type,
        };
    }

    /// Expose this wrapper as a `std.mem.Allocator`.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    ///
    /// Returns:
    /// - A `std.mem.Allocator` whose vtable calls into this wrapper.
    ///   `resize`, `remap`, and `free` trap (unsupported).
    pub fn allocator(self: *PageAllocator) std.mem.Allocator {
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

    /// Allocate a single 4 KiB page with 4 KiB alignment via UEFI.
    ///
    /// Constraints:
    /// - `len` must be exactly 4096.
    /// - `alignment` must be exactly 4096.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to `PageAllocator` (provided by vtable).
    /// - `len`: requested size in bytes (must be 4096).
    /// - `alignment`: required alignment (must be 4096).
    /// - `ret_addr`: caller return address for diagnostics (unused).
    ///
    /// Returns:
    /// - `[*]u8` on success.
    /// - `null` on allocation failure.
    fn alloc(
        ptr: *anyopaque,
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *PageAllocator = @alignCast(@ptrCast(ptr));
        std.debug.assert(len == 4096);
        std.debug.assert(alignment.toByteUnits() == 4096);
        const pages = self.boot.allocatePages(
            .any,
            self.mem_type,
            1,
        ) catch return null;
        const page: *[4096]u8 = &pages[0];
        return @ptrCast(page);
    }

    /// Unsupported: bump/UEFI page allocator cannot resize; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `memory`: previous allocation (ignored).
    /// - `alignment`: alignment (ignored).
    /// - `new_len`: requested new size (ignored).
    /// - `ret_addr`: caller return address (ignored).
    ///
    /// Returns:
    /// - Never; traps with `unreachable`.
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

    /// Unsupported: remapping is not provided; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `memory`: previous allocation (ignored).
    /// - `alignment`: alignment (ignored).
    /// - `new_len`: requested new size (ignored).
    /// - `ret_addr`: caller return address (ignored).
    ///
    /// Returns:
    /// - Never; traps with `unreachable`.
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

    /// Unsupported: freeing via this wrapper is not implemented; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (ignored).
    /// - `buf`: buffer to free (ignored).
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
