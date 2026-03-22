const lib = @import("lib");
const std = @import("std");

const syscall = lib.syscall;
const t = lib.testing;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var thread_signal = std.atomic.Value(u64).init(0);

fn signalThread() void {
    thread_signal.store(1, .release);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("futex_wait + futex_wake + timeout (S2.7, S4)");
    testFutexMismatch();
    testFutexBadAlign();
    testFutexWakeNone();
    testFutexTimeoutZeroTryOnly();
    testFutexCrossThreadSignal();
}

fn testFutexMismatch() void {
    var val: u64 align(8) = 42;
    const rc = syscall.futex_wait(&val, 99, MAX_TIMEOUT);
    t.expectEqual("S4.futex_wait: *addr != expected returns E_AGAIN", -9, rc);
}

fn testFutexBadAlign() void {
    var buf: [16]u8 align(8) = undefined;
    const misaligned: *const u64 = @ptrFromInt(@intFromPtr(&buf) + 1);
    const rc = syscall.futex_wait(misaligned, 0, MAX_TIMEOUT);
    t.expectEqual("S4.futex_wait: non-8-byte-aligned returns E_INVAL", -1, rc);
}

fn testFutexWakeNone() void {
    var val: u64 align(8) = 0;
    const rc = syscall.futex_wake(&val, 10);
    t.expectEqual("S4.futex_wake: no waiters returns 0 woken", 0, rc);
}

fn testFutexTimeoutZeroTryOnly() void {
    var val: u64 align(8) = 0;
    const rc = syscall.futex_wait(&val, 0, 0);
    t.expectEqual("S4.futex_wait: timeout=0 is try-only, returns E_TIMEOUT", -8, rc);
}

fn testFutexCrossThreadSignal() void {
    thread_signal.store(0, .release);
    const rc = syscall.thread_create(&signalThread, 0, 4);
    if (rc != 0) { t.failWithVal("thread_create failed", 0, rc); return; }
    var spins: u32 = 0;
    while (thread_signal.load(.acquire) == 0 and spins < 500_000) : (spins += 1) {
        syscall.thread_yield();
    }
    if (thread_signal.load(.acquire) == 1) {
        t.pass("S2.7: cross-thread atomic signal observed by parent");
    } else {
        t.fail("S2.7: child thread never signaled");
    }
}
