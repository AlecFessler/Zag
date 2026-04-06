pub const Mutex = extern struct {
    state: u64 align(8),

    pub const UNLOCKED: u64 = 0;
    pub const LOCKED: u64 = 1;
    pub const LOCKED_WAITERS: u64 = 2;

    pub fn init() Mutex {
        return .{ .state = UNLOCKED };
    }

    pub fn lock(_: *Mutex) void {}
    pub fn unlock(_: *Mutex) void {}
};

pub const Seqlock = extern struct {
    gen: u64 align(8) = 0,

    pub fn init() Seqlock {
        return .{ .gen = 0 };
    }

    pub fn writeBegin(_: *Seqlock) void {}
    pub fn writeEnd(_: *Seqlock) void {}
    pub fn readBegin(_: *Seqlock) u64 {
        return 0;
    }
    pub fn readBeginNonblock(_: *Seqlock) u64 {
        return 0;
    }
    pub fn readRetry(_: *Seqlock, _: u64) bool {
        return false;
    }
};
