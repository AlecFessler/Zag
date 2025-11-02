//! Internal memory subsystem module index.
//!
//! These memory allocators and managers are re-exported by `zag`.
//! Higher-level code should import `zag` rather than importing `memory` directly.
//!
//! This file provides a unified namespace for all core kernel memory infrastructure,
//! including physical/virtual memory management and allocator implementations.
//! Subsystems throughout the kernel refer to memory components via `zag.memory.*`
//! for consistency, clarity, and architectural separation.
//!
//! # Included Submodules
//!
//! - `bitmap_freelist.zig`        – Bitset-backed free page tracking
//! - `buddy_allocator.zig`        – Power-of-two block allocator for page regions
//! - `bump_allocator.zig`         – Linear region allocator for early boot
//! - `heap_allocator.zig`         – Kernel heap allocation with free-lists
//! - `intrusive_freelist.zig`     – Pointer-linked free list for fixed-size nodes
//! - `physical_memory_manager.zig` – Global PMM built on top of allocatable regions
//! - `slab_allocator.zig`         – Cache of fixed-size object slabs for fast alloc/free
//! - `stack_freelist.zig`         – Pre-allocated kernel thread stacks pool
//! - `virtual_memory_manager.zig` – Page table manipulation and address space control

pub const BitmapFreelist = @import("bitmap_freelist.zig");
pub const BuddyAllocator = @import("buddy_allocator.zig");
pub const BumpAllocator = @import("bump_allocator.zig");
pub const HeapAllocator = @import("heap_allocator.zig");
pub const IntrusiveFreelist = @import("intrusive_freelist.zig");
pub const PhysicalMemoryManager = @import("physical_memory_manager.zig");
pub const SlabAllocator = @import("slab_allocator.zig");
pub const StackFreelist = @import("stack_freelist.zig");
pub const VirtualMemoryManager = @import("virtual_memory_manager.zig");
