const lib = @import("lib");
const syscall = lib.syscall;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub const Mutex = extern struct {
    state: u64 align(8),

    pub const UNLOCKED: u64 = 0;
    pub const LOCKED: u64 = 1;
    pub const LOCKED_WAITERS: u64 = 2;

    pub fn init() Mutex {
        return .{ .state = UNLOCKED };
    }

    pub fn lock(self: *Mutex) void {
        if (@cmpxchgWeak(u64, &self.state, UNLOCKED, LOCKED, .acquire, .monotonic) == null) return;

        while (true) {
            const old = @cmpxchgWeak(u64, &self.state, UNLOCKED, LOCKED_WAITERS, .acquire, .monotonic);
            if (old == null) return;

            if (@atomicLoad(u64, &self.state, .monotonic) != UNLOCKED) {
                @atomicStore(u64, &self.state, LOCKED_WAITERS, .monotonic);
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

/// Lock-free sequence lock for protecting multi-word reads.
///
/// Writers increment the generation counter to odd (write in progress),
/// update fields, then increment to even (write complete). Readers
/// snapshot the generation before and after reading — if they differ
/// or the generation was odd, the read is retried.
///
/// Safe against check-then-block races: futex_wait returns E_AGAIN
/// immediately if the generation has already changed.
pub const Seqlock = extern struct {
    gen: u64 align(8) = 0,

    pub fn init() Seqlock {
        return .{ .gen = 0 };
    }

    /// Begin a write. Increments gen to odd (write in progress).
    pub fn writeBegin(self: *Seqlock) void {
        _ = @atomicRmw(u64, &self.gen, .Add, 1, .release);
    }

    /// End a write. Increments gen to even (write complete).
    /// Wakes one futex waiter so blocked readers can retry.
    pub fn writeEnd(self: *Seqlock) void {
        _ = @atomicRmw(u64, &self.gen, .Add, 1, .release);
        _ = syscall.futex_wake(@ptrCast(&self.gen), 1);
    }

    /// Begin a read. Blocks (with 1ms futex timeout) if a write is in
    /// progress. Returns the generation to pass to readRetry().
    pub fn readBegin(self: *Seqlock) u64 {
        while (true) {
            const g = @atomicLoad(u64, &self.gen, .acquire);
            if (g & 1 == 0) return g;
            _ = syscall.futex_wait(@ptrCast(&self.gen), g, 1_000_000);
        }
    }

    /// Non-blocking readBegin for latency-sensitive threads.
    /// Uses a 1us futex timeout instead of 1ms.
    pub fn readBeginNonblock(self: *Seqlock) u64 {
        while (true) {
            const g = @atomicLoad(u64, &self.gen, .acquire);
            if (g & 1 == 0) return g;
            _ = syscall.futex_wait(@ptrCast(&self.gen), g, 1_000);
        }
    }

    /// Check if a read was consistent. Returns true if the read must
    /// be retried (generation changed during the read).
    pub fn readRetry(self: *Seqlock, start_gen: u64) bool {
        return @atomicLoad(u64, &self.gen, .acquire) != start_gen;
    }
};
