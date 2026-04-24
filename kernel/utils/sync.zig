const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;

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

/// Address-ordered acquire of two locks of the same type. The
/// static analyzer (tools/check_gen_lock) flags same-type lock
/// nestings that don't go through this helper: two cores each
/// holding one and waiting on the other is a classic deadlock,
/// and sorting by pointer address before acquire breaks the cycle.
/// `a` and `b` must be distinct.
pub fn lockPair(a: anytype, b: @TypeOf(a)) void {
    std.debug.assert(a != b);
    const ai = @intFromPtr(a);
    const bi = @intFromPtr(b);
    const first = if (ai < bi) a else b;
    const second = if (ai < bi) b else a;
    first.lock();
    second.lock();
}

/// Symmetric partner for `lockPair`. Releases in the reverse
/// order of acquisition.
pub fn unlockPair(a: anytype, b: @TypeOf(a)) void {
    std.debug.assert(a != b);
    const ai = @intFromPtr(a);
    const bi = @intFromPtr(b);
    const first = if (ai < bi) a else b;
    const second = if (ai < bi) b else a;
    second.unlock();
    first.unlock();
}
