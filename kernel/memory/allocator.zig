//! Minimal allocator interface used as the default for kernel memory management.
//!
//! This interface provides a lightweight, idiomatic way to abstract over allocator
//! implementations in a freestanding environment. It serves as the kernel's default
//! allocation mechanism instead of `std.mem.Allocator`, as it is better aligned
//! with current kernel needs and constraints.
//!
//! The interface includes only the essentials: a context pointer and an `alloc` function.
//! It is intended for use with custom allocators including as boot-time bump allocators
//! or early region-based allocators.

/// A minimal allocator interface for use in freestanding environments.
///
/// This interface allows allocation functions to be passed around in a generic and idiomatic
/// Zig style without relying on the standard library's `std.mem.Allocator`. It consists of a
/// context pointer and an allocation function pointer. The function must accept a context,
/// size, and alignment, and return a pointer to the allocated memory.
///
/// This interface does not define `free` or `resize` operations and is currently intended
/// for basic, one-way allocation flows (e.g. bump allocators or boot-time memory setup).
pub const Allocator = struct {
    ctx: *anyopaque,
    alloc_fn: *const fn (
        ctx: *anyopaque,
        size: usize,
        alignment: usize,
    ) [*]u8,

    /// Creates a new `Allocator` interface using the provided context and allocation function.
    ///
    /// - `ctx`: A pointer to the allocator's state or implementation-specific data.
    /// - `alloc_fn`: A function that performs the allocation given a context, size, and alignment.
    pub fn init(
        ctx: *anyopaque,
        alloc_fn: *const fn (
            *anyopaque,
            usize,
            usize,
        ) [*]u8,
    ) Allocator {
        return Allocator{
            .ctx = ctx,
            .alloc_fn = alloc_fn,
        };
    }

    /// Allocates a block of memory with the given size and alignment using the underlying allocator.
    ///
    /// Delegates the allocation to the function pointer stored in the interface.
    pub fn alloc(
        self: *Allocator,
        size: usize,
        alignment: usize,
    ) [*]u8 {
        return self.alloc_fn(
            self.ctx,
            size,
            alignment,
        );
    }
};
