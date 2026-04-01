// Minimal memory shim - only re-exports modules that compile in userspace.
pub const address = @import("address");
pub const bitmap_freelist = @import("bitmap_freelist");
pub const device_region = @import("device_region");
pub const intrusive_freelist = @import("intrusive_freelist");
pub const paging = @import("paging");
pub const pmm = @import("pmm");
pub const shared = @import("shared");
pub const slab_allocator = @import("slab_allocator");
