//! UEFI-backed single-page allocator for page table mapping.
//!
//! Wraps UEFI `BootServices.allocatePages` behind a `std.mem.Allocator` so
//! paging helpers (e.g., `mapPage`) can request page-sized (4 KiB) buffers via
//! the standard interface. This allocator:
//! - Allocates exactly one 4 KiB page per request.
//! - Requires `alignment == 4096` and `len == 4096`.
//! - Does not support `resize`, `remap`, or `free` (these trap).
//!
//! Notes:
//! - Allocations are tagged with the provided UEFI `MemoryType`.
//! - Memory is returned untracked by this wrapper; freeing via this API traps.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `PageAllocator` — thin wrapper over UEFI Boot Services for 4 KiB pages.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `PageAllocator.init` — construct a wrapper with Boot Services + MemoryType.
//! - `PageAllocator.allocator` — expose a `std.mem.Allocator` facade.
//! - `PageAllocator.alloc` — allocate one 4 KiB page (private vtable).
//! - `PageAllocator.resize` — unsupported; traps (private vtable).
//! - `PageAllocator.remap` — unsupported; traps (private vtable).
//! - `PageAllocator.free` — unsupported; traps (private vtable).

const std = @import("std");
const uefi = std.os.uefi;

/// Thin wrapper around UEFI Boot Services for 4 KiB page allocations.
pub const PageAllocator = struct {
    boot: *uefi.tables.BootServices,
    mem_type: uefi.tables.MemoryType,

    /// Summary:
    /// Initialize a `PageAllocator` with a boot services handle and memory type.
    ///
    /// Arguments:
    /// - `boot`: UEFI Boot Services pointer.
    /// - `mem_type`: UEFI memory classification for allocations.
    ///
    /// Returns:
    /// - `PageAllocator` ready to expose a `std.mem.Allocator`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(
        boot: *uefi.tables.BootServices,
        mem_type: uefi.tables.MemoryType,
    ) PageAllocator {
        return .{
            .boot = boot,
            .mem_type = mem_type,
        };
    }

    /// Summary:
    /// Expose this wrapper as a `std.mem.Allocator`.
    ///
    /// Arguments:
    /// - `self`: allocator instance.
    ///
    /// Returns:
    /// - `std.mem.Allocator` whose vtable calls into this wrapper.
    ///   `resize`, `remap`, and `free` trap (unsupported).
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

    /// Summary:
    /// Allocate a single 4 KiB page with 4 KiB alignment via UEFI.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer to `PageAllocator` (vtable-provided).
    /// - `len`: requested size in bytes (must be exactly 4096).
    /// - `alignment`: required alignment (must be exactly 4096).
    /// - `ret_addr`: caller return address for diagnostics (unused).
    ///
    /// Returns:
    /// - `?[*]u8` — non-null on success, `null` on allocation failure.
    ///
    /// Errors:
    /// - None (nullable return indicates failure).
    ///
    /// Panics:
    /// - Asserts if `len != 4096` or `alignment != 4096`.
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

    /// Summary:
    /// Unsupported: cannot resize; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (unused).
    /// - `memory`: previous allocation (unused).
    /// - `alignment`: alignment (unused).
    /// - `new_len`: requested new size (unused).
    /// - `ret_addr`: caller return address (unused).
    ///
    /// Returns:
    /// - `bool` — never returns normally; function traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Traps unconditionally (`unreachable`).
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
    /// Unsupported: remapping is not provided; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (unused).
    /// - `memory`: previous allocation (unused).
    /// - `alignment`: alignment (unused).
    /// - `new_len`: requested new size (unused).
    /// - `ret_addr`: caller return address (unused).
    ///
    /// Returns:
    /// - `?[*]u8` — never returns normally; function traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Traps unconditionally (`unreachable`).
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
    /// Unsupported: freeing via this wrapper is not implemented; traps.
    ///
    /// Arguments:
    /// - `ptr`: opaque pointer (unused).
    /// - `buf`: buffer to free (unused).
    /// - `alignment`: alignment (unused).
    /// - `ret_addr`: caller return address (unused).
    ///
    /// Returns:
    /// - `void` — never returns normally; function traps.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Traps unconditionally (`unreachable`).
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
