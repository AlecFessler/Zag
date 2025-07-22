pub const AllocationError = error{OutOfMemory};
pub const Allocator = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        alloc: *const fn (ctx: *anyopaque, n: usize, alignment: usize) AllocationError![*]u8,
        free: *const fn (ctx: *anyopaque, addr: usize) void,
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn alloc(self: *Allocator, n: usize, alignment: usize) AllocationError![*]u8 {
        return self.vtable.alloc(self.ctx, n, alignment);
    }

    pub fn free(self: *Allocator, addr: usize) void {
        self.vtable.free(self.ctx, addr);
    }

    pub fn deinit(self: *Allocator) void {
        self.vtable.deinit(self.ctx);
    }
};
