const lib = @import("lib");
const std = @import("std");

const syscall = lib.syscall;
const t = lib.testing;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var thread_signal: u64 align(8) = 0;

fn signalThread() void {
    @as(*volatile u64, &thread_signal).* = 1;
    _ = syscall.futex_wake(&thread_signal, 1);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("futex_wait + futex_wake + timeout (S2.7, S4)");
    testFutexMismatch();
    testFutexBadAlign();
    testFutexWakeBadAlign();
    testFutexWakeNone();
    testFutexTimeoutZeroTryOnly();
    testFutexCrossThreadSignal();
    testFutexTimedWait();
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

fn testFutexWakeBadAlign() void {
    var buf: [16]u8 align(8) = undefined;
    const misaligned: *const u64 = @ptrFromInt(@intFromPtr(&buf) + 1);
    const rc = syscall.futex_wake(misaligned, 1);
    t.expectEqual("S4.futex_wake: non-8-byte-aligned returns E_INVAL", -1, rc);
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
    @as(*volatile u64, &thread_signal).* = 0;
    const rc = syscall.thread_create(&signalThread, 0, 4);
    if (rc != 0) {
        t.failWithVal("thread_create failed", 0, rc);
        return;
    }
    t.waitUntilNonZero(@as(*volatile u64, &thread_signal));
    t.pass("S2.5: cross-thread futex_wake unblocks futex_wait");
}

fn testFutexTimedWait() void {
    var val: u64 align(8) = 0;
    const timeout_ns: u64 = 50_000_000;
    const start: u64 = @bitCast(syscall.clock_gettime());
    const rc = syscall.futex_wait(&val, 0, timeout_ns);
    const end: u64 = @bitCast(syscall.clock_gettime());
    const elapsed = end -| start;
    if (rc != -8) {
        t.failWithVal("S4.futex_wait: timed wait should return E_TIMEOUT", -8, rc);
        return;
    }
    if (elapsed < timeout_ns / 2) {
        t.fail("S4.futex_wait: timed wait returned too quickly");
        return;
    }
    t.pass("S4.futex_wait: timed wait expires and returns E_TIMEOUT");
}

var timed_wake_val: u64 align(8) = 0;
var timed_wake_result: i64 = 0;
var timed_wake_done: u64 align(8) = 0;
var timed_wake_ready: u64 align(8) = 0;

fn timedWaitThread() void {
    @as(*volatile u64, &timed_wake_ready).* = 1;
    _ = syscall.futex_wake(&timed_wake_ready, 1);
    timed_wake_result = syscall.futex_wait(&timed_wake_val, 0, 5_000_000_000);
    @as(*volatile u64, &timed_wake_done).* = 1;
    syscall.thread_exit();
}

fn testFutexTimedWaitWokenBeforeTimeout() void {
    @as(*volatile u64, &timed_wake_val).* = 0;
    @as(*volatile u64, &timed_wake_done).* = 0;
    @as(*volatile u64, &timed_wake_ready).* = 0;
    timed_wake_result = 0;
    const rc = syscall.thread_create(&timedWaitThread, 0, 4);
    if (rc != 0) {
        t.failWithVal("thread_create failed", 0, rc);
        return;
    }

    t.waitUntilNonZero(@as(*volatile u64, &timed_wake_ready));

    var i: u32 = 0;
    while (i < 10) : (i += 1) syscall.thread_yield();

    _ = syscall.futex_wake(&timed_wake_val, 1);

    t.waitUntilNonZero(@as(*volatile u64, &timed_wake_done));
    t.expectEqual("S4.futex_wait: woken before timeout returns E_OK", 0, timed_wake_result);
}
