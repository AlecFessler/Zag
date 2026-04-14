// Allocators shim - re-exports kernel allocator modules for fuzzer builds.
pub const bitmap_freelist = @import("bitmap_freelist");
pub const intrusive_freelist = @import("intrusive_freelist");
pub const slab = @import("slab_allocator");
