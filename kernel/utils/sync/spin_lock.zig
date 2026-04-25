const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const debug = zag.utils.sync.debug;

pub const SpinLock = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    class: [*:0]const u8 = "@unclassified",

    pub fn lock(self: *SpinLock) void {
        debug.acquire(self, self.class, 0, .{ .file = "?", .fn_name = "?", .line = 0, .column = 0, .module = "?" });
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        debug.release(self);
        std.debug.assert(self.state.load(.monotonic) == 1);
        self.state.store(0, .release);
    }

    pub fn lockIrqSave(self: *SpinLock) u64 {
        const state = arch.cpu.saveAndDisableInterrupts();
        self.lock();
        return state;
    }

    pub fn unlockIrqRestore(self: *SpinLock, state: u64) void {
        self.unlock();
        arch.cpu.restoreInterrupts(state);
    }
};

