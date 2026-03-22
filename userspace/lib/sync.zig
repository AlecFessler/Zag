const std = @import("std");
const syscall = @import("syscall.zig");

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub const Mutex = struct {
    state: u64 align(8),

    pub const UNLOCKED: u64 = 0;
    pub const LOCKED: u64 = 1;
    pub const LOCKED_WAITERS: u64 = 2;

    pub fn init() Mutex {
        return .{ .state = UNLOCKED };
    }

    pub fn lock(self: *Mutex) void {
        const ptr = @as(*volatile u64, &self.state);
        if (@cmpxchgWeak(u64, &self.state, UNLOCKED, LOCKED, .acquire, .monotonic) == null) return;

        while (true) {
            const old = @cmpxchgWeak(u64, &self.state, UNLOCKED, LOCKED_WAITERS, .acquire, .monotonic);
            if (old == null) return;

            if (ptr.* != UNLOCKED) {
                ptr.* = LOCKED_WAITERS;
            }
            _ = syscall.futex_wait(@ptrCast(&self.state), LOCKED_WAITERS, MAX_TIMEOUT);
        }
    }

    pub fn unlock(self: *Mutex) void {
        const prev = @atomicRmw(u64, &self.state, .Xchg, UNLOCKED, .release);
        if (prev == LOCKED_WAITERS) {
            _ = syscall.futex_wake(@ptrCast(&self.state), 1);
        }
    }
};

pub const Condvar = struct {
    seq: u64 align(8),

    pub fn init() Condvar {
        return .{ .seq = 0 };
    }

    pub fn wait(self: *Condvar, mutex: *Mutex) void {
        const current_seq = @atomicLoad(u64, &self.seq, .acquire);
        mutex.unlock();
        _ = syscall.futex_wait(@ptrCast(&self.seq), current_seq, MAX_TIMEOUT);
        mutex.lock();
    }

    pub fn signal(self: *Condvar) void {
        _ = @atomicRmw(u64, &self.seq, .Add, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&self.seq), 1);
    }

    pub fn broadcast(self: *Condvar) void {
        _ = @atomicRmw(u64, &self.seq, .Add, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&self.seq), @as(u64, @bitCast(@as(i64, -1))));
    }
};

pub const Semaphore = struct {
    count: u64 align(8),

    pub fn init(initial: u64) Semaphore {
        return .{ .count = initial };
    }

    pub fn wait(self: *Semaphore) void {
        while (true) {
            const current = @atomicLoad(u64, &self.count, .acquire);
            if (current > 0) {
                if (@cmpxchgWeak(u64, &self.count, current, current - 1, .acquire, .monotonic) == null) return;
            } else {
                _ = syscall.futex_wait(@ptrCast(&self.count), 0, MAX_TIMEOUT);
            }
        }
    }

    pub fn post(self: *Semaphore) void {
        _ = @atomicRmw(u64, &self.count, .Add, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&self.count), 1);
    }
};
