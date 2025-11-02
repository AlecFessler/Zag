//! Physical memory manager.
//!
//! Thin wrapper over a backing `std.mem.Allocator` to represent the PMM
//! until a real frame allocator lands. Exposes a `std.mem.Allocator`
//! interface for early boot and low-level subsystems.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `PhysicalMemoryManager` — PMM that delegates all ops to a backing allocator.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - `global_pmm` — optional process-wide PMM handle for low-level users.
//!
//! ## Functions
//! - `PhysicalMemoryManager.init` — construct a PMM over a delegate allocator.
//! - `PhysicalMemoryManager.allocator` — expose a `std.mem.Allocator` vtable.
//! - `PhysicalMemoryManager.alloc` — allocator vtable `alloc` entry; forwards to delegate.
//! - `PhysicalMemoryManager.resize` — allocator vtable `resize`; unsupported (traps).
//! - `PhysicalMemoryManager.remap` — allocator vtable `remap`; unsupported (traps).
//! - `PhysicalMemoryManager.free` — allocator vtable `free`; forwards to delegate.

const std = @import("std");

/// PMM that delegates all allocations to a backing allocator.
pub const PhysicalMemoryManager = struct {
    backing_allocator: std.mem.Allocator,

    /// Function: `PhysicalMemoryManager.init`
    ///
    /// Summary:
    /// Construct a `PhysicalMemoryManager` that delegates to `backing_allocator`.
    ///
    /// Arguments:
    /// - `backing_allocator`: Allocator used to fulfill PMM requests.
    ///
    /// Returns:
    /// - `PhysicalMemoryManager`: Newly initialized PMM instance.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(backing_allocator: std.mem.Allocator) PhysicalMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    /// Function: `PhysicalMemoryManager.allocator`
    ///
    /// Summary:
    /// Produce a `std.mem.Allocator` interface whose vtable forwards to this PMM.
    ///
    /// Arguments:
    /// - `self`: Pointer to the PMM instance.
    ///
    /// Returns:
    /// - `std.mem.Allocator`: Vtable that dispatches to `alloc`, `free`, and traps on `resize`/`remap`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

    /// Function: `PhysicalMemoryManager.alloc`
    ///
    /// Summary:
    /// Vtable entry for `alloc`; forwards to the backing allocator's `rawAlloc`.
    ///
    /// Arguments:
    /// - `ptr`: Opaque pointer to `PhysicalMemoryManager` (`self`).
    /// - `len`: Number of bytes to allocate.
    /// - `alignment`: Required alignment for the allocation.
    /// - `ret_addr`: Caller return address (for diagnostics/accounting).
    ///
    /// Returns:
    /// - `?[*]u8`: Pointer to `len` bytes on success, or `null` on OOM.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *PhysicalMemoryManager = @alignCast(@ptrCast(ptr));
        return self.backing_allocator.rawAlloc(len, alignment, ret_addr);
    }

    /// Function: `PhysicalMemoryManager.resize`
    ///
    /// Summary:
    /// Vtable entry for `resize`; unsupported for the PMM and traps if called.
    ///
    /// Arguments:
    /// - `ptr`: Opaque pointer to `PhysicalMemoryManager` (unused).
    /// - `memory`: Previously allocated memory slice (unused).
    /// - `alignment`: Alignment of `memory` (unused).
    /// - `new_len`: Requested new length (unused).
    /// - `ret_addr`: Caller return address (unused).
    ///
    /// Returns:
    /// - `bool`: Never returns (traps).
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Always panics (unreachable) because resize is unsupported.
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

    /// Function: `PhysicalMemoryManager.remap`
    ///
    /// Summary:
    /// Vtable entry for `remap`; unsupported for the PMM and traps if called.
    ///
    /// Arguments:
    /// - `ptr`: Opaque pointer to `PhysicalMemoryManager` (unused).
    /// - `memory`: Previously allocated memory slice (unused).
    /// - `alignment`: Alignment of `memory` (unused).
    /// - `new_len`: Requested new length (unused).
    /// - `ret_addr`: Caller return address (unused).
    ///
    /// Returns:
    /// - `?[*]u8`: Never returns (traps).
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Always panics (unreachable) because remap is unsupported.
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

    /// Function: `PhysicalMemoryManager.free`
    ///
    /// Summary:
    /// Vtable entry for `free`; forwards to the backing allocator's `rawFree`.
    ///
    /// Arguments:
    /// - `ptr`: Opaque pointer to `PhysicalMemoryManager` (`self`).
    /// - `buf`: Slice previously returned by `alloc`.
    /// - `alignment`: Alignment used at allocation time.
    /// - `ret_addr`: Caller return address (for diagnostics/accounting).
    ///
    /// Returns:
    /// - None.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

/// Optional process-wide PMM handle for low-level users.
pub var global_pmm: ?PhysicalMemoryManager = null;
