pub const AllocationError = error{OutOfMemory};
pub const Allocator = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        alloc: *const fn (ctx: *anyopaque, bytes: usize, alignment: usize) AllocationError![*]u8,
        free: *const fn (ctx: *anyopaque, addr: usize) void,
    };

    pub fn alloc(self: *Allocator, bytes: usize, alignment: usize) AllocationError![*]u8 {
        return self.vtable.alloc(self.ctx, bytes, alignment);
    }

    pub fn free(self: *Allocator, addr: usize) void {
        self.vtable.free(self.ctx, addr);
    }
};
