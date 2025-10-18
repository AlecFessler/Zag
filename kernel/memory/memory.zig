//! Memory module entry point.
//!
//! Provides import access to all core kernel memory allocators and managers,
//! including physical, virtual, and heap subsystems. Serves as the canonical
//! import surface for kernel memory infrastructure.

pub const BitmapFreelist = @import("bitmap_freelist.zig");
pub const BuddyAllocator = @import("buddy_allocator.zig");
pub const BumpAllocator = @import("bump_allocator.zig");
pub const HeapAllocator = @import("heap_allocator.zig");
pub const IntrusiveFreelist = @import("intrusive_freelist.zig");
pub const PhysicalMemoryManager = @import("physical_memory_manager.zig");
pub const SlabAllocator = @import("slab_allocator.zig");
pub const StackFreelist = @import("stack_freelist.zig");
pub const VirtualMemoryManager = @import("virtual_memory_manager.zig");
