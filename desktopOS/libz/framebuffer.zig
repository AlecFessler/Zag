pub const FRAMEBUFFER_MAGIC: u32 = 0x5A414746; // "ZAGF"
pub const FRAMEBUFFER_SHM_SIZE: u64 = 4 * 1024 * 1024; // 4 MB
pub const PIXEL_DATA_OFFSET: u64 = 4096;

pub const FramebufferHeader = extern struct {
    magic: u32,
    width: u32,
    height: u32,
    stride: u32, // pixels per row
    format: u32, // 0=BGR8, 1=RGB8
    _pad0: u32 = 0,
    frame_counter: u64 align(8),
    layout_generation: u64 align(8) = 0,
    _padding: [4096 - 40]u8 = .{0} ** (4096 - 40),

    pub fn pixelData(self: anytype) [*]volatile u32 {
        return @ptrFromInt(@intFromPtr(self) + PIXEL_DATA_OFFSET);
    }

    pub fn pixelDataConst(self: anytype) [*]const volatile u32 {
        return @ptrFromInt(@intFromPtr(self) + PIXEL_DATA_OFFSET);
    }

    pub fn isValid(self: anytype) bool {
        const ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&self.magic)));
        return @atomicLoad(u32, ptr, .acquire) == FRAMEBUFFER_MAGIC;
    }

    pub fn readFrameCounter(self: anytype) u64 {
        const ptr: *const u64 = @ptrCast(@volatileCast(@constCast(&self.frame_counter)));
        return @atomicLoad(u64, ptr, .acquire);
    }

    pub fn incrementFrameCounter(self: anytype) void {
        const ptr: *u64 = @ptrCast(@volatileCast(@constCast(&self.frame_counter)));
        _ = @atomicRmw(u64, ptr, .Add, 1, .release);
    }

    pub fn readLayoutGeneration(self: anytype) u64 {
        const ptr: *const u64 = @ptrCast(@volatileCast(@constCast(&self.layout_generation)));
        return @atomicLoad(u64, ptr, .acquire);
    }

    pub fn incrementLayoutGeneration(self: anytype) void {
        const ptr: *u64 = @ptrCast(@volatileCast(@constCast(&self.layout_generation)));
        _ = @atomicRmw(u64, ptr, .Add, 1, .release);
    }
};
