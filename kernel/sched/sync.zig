const std = @import("std");
const zag = @import("zag");

pub const SpinLock = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        std.debug.assert(self.state.load(.monotonic) == 1);
        self.state.store(0, .release);
    }
};
