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
    heartbeat: u64 align(8) = 0,
    _padding: [4096 - 48]u8 = .{0} ** (4096 - 48),

    pub fn pixelData(self: *FramebufferHeader) [*]u32 {
        return @ptrFromInt(@intFromPtr(self) + PIXEL_DATA_OFFSET);
    }

    pub fn pixelDataConst(self: *const FramebufferHeader) [*]const u32 {
        return @ptrFromInt(@intFromPtr(self) + PIXEL_DATA_OFFSET);
    }

    pub fn isValid(self: *const FramebufferHeader) bool {
        return @atomicLoad(u32, &self.magic, .acquire) == FRAMEBUFFER_MAGIC;
    }

    pub fn readFrameCounter(self: *const FramebufferHeader) u64 {
        return @atomicLoad(u64, &self.frame_counter, .acquire);
    }

    pub fn incrementFrameCounter(self: *FramebufferHeader) void {
        _ = @atomicRmw(u64, &self.frame_counter, .Add, 1, .release);
    }

    pub fn readLayoutGeneration(self: *const FramebufferHeader) u64 {
        return @atomicLoad(u64, &self.layout_generation, .acquire);
    }

    pub fn incrementLayoutGeneration(self: *FramebufferHeader) void {
        _ = @atomicRmw(u64, &self.layout_generation, .Add, 1, .release);
    }

    pub fn readHeartbeat(self: *const FramebufferHeader) u64 {
        return @atomicLoad(u64, &self.heartbeat, .acquire);
    }

    pub fn tickHeartbeat(self: *FramebufferHeader) void {
        _ = @atomicRmw(u64, &self.heartbeat, .Add, 1, .release);
    }

    pub fn setMagic(self: *FramebufferHeader, val: u32) void {
        @atomicStore(u32, &self.magic, val, .release);
    }

    pub fn setWidth(self: *FramebufferHeader, val: u32) void {
        @atomicStore(u32, &self.width, val, .release);
    }

    pub fn setHeight(self: *FramebufferHeader, val: u32) void {
        @atomicStore(u32, &self.height, val, .release);
    }

    pub fn setStride(self: *FramebufferHeader, val: u32) void {
        @atomicStore(u32, &self.stride, val, .release);
    }

    pub fn setFormat(self: *FramebufferHeader, val: u32) void {
        @atomicStore(u32, &self.format, val, .release);
    }

    pub fn readWidth(self: *const FramebufferHeader) u32 {
        return @atomicLoad(u32, &self.width, .acquire);
    }

    pub fn readHeight(self: *const FramebufferHeader) u32 {
        return @atomicLoad(u32, &self.height, .acquire);
    }

    pub fn readStride(self: *const FramebufferHeader) u32 {
        return @atomicLoad(u32, &self.stride, .acquire);
    }

    pub fn readFormat(self: *const FramebufferHeader) u8 {
        return @truncate(@atomicLoad(u32, &self.format, .acquire));
    }
};
