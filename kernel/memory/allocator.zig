pub const Allocator = struct {
    ctx: *anyopaque,
    alloc_fn: *const fn (
        ctx: *anyopaque,
        size: usize,
        alignment: usize,
    ) [*]u8,

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
            .alloc_fn = @ptrCast(alloc_fn),
        };
    }

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
