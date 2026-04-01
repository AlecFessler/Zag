// No-op SpinLock for userspace fuzzing (single-threaded).
pub const SpinLock = struct {
    state: @import("std").atomic.Value(u32) = @import("std").atomic.Value(u32).init(0),

    pub fn lock(self: *SpinLock) void {
        _ = self;
    }

    pub fn unlock(self: *SpinLock) void {
        _ = self;
    }
};
