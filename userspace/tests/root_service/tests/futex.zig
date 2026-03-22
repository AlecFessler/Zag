const lib = @import("lib");
const std = @import("std");

const syscall = lib.syscall;
const t = lib.testing;

var thread_signal = std.atomic.Value(u64).init(0);

fn signalThread() void {
    thread_signal.store(1, .release);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("futex_wait + futex_wake");
    testFutexMismatch();
    testFutexBadAlign();
    testFutexWakeNone();
    testFutexSignalViaPolling();
}

fn testFutexMismatch() void {
    var val: u64 align(8) = 42;
    const rc = syscall.futex_wait(&val, 99);
    t.expectEqual("futex_wait: mismatch returns E_AGAIN", -9, rc);
}

fn testFutexBadAlign() void {
    var buf: [16]u8 align(8) = undefined;
    const misaligned: *const u64 = @ptrFromInt(@intFromPtr(&buf) + 1);
    const rc = syscall.futex_wait(misaligned, 0);
    t.expectEqual("futex_wait: bad alignment rejected", -1, rc);
}

fn testFutexWakeNone() void {
    var val: u64 align(8) = 0;
    const rc = syscall.futex_wake(&val, 10);
    t.expectEqual("futex_wake: no waiters returns 0", 0, rc);
}

fn testFutexSignalViaPolling() void {
    thread_signal.store(0, .release);

    const rc = syscall.thread_create(&signalThread, 0, 4);
    if (rc != 0) {
        t.failWithVal("futex_signal: thread_create failed", 0, rc);
        return;
    }

    var spins: u32 = 0;
    while (thread_signal.load(.acquire) == 0 and spins < 500_000) : (spins += 1) {
        syscall.thread_yield();
    }

    if (thread_signal.load(.acquire) == 1) {
        t.pass("futex_signal: thread signaled via atomic");
    } else {
        t.fail("futex_signal: thread did not signal");
    }
}
