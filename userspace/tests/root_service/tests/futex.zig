const std = @import("std");
const lib = @import("lib");
const syscall = lib.syscall;
const t = lib.testing;

var futex_val = std.atomic.Value(u64).init(0);
var producer_done = std.atomic.Value(bool).init(false);

fn producerThread() void {
    futex_val.store(1, .release);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
    producer_done.store(true, .release);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("futex_wait + futex_wake");
    testFutexMismatch();
    testFutexBadAlign();
    testFutexWakeNone();
    testFutexSignal();
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

fn testFutexSignal() void {
    futex_val.store(0, .release);
    producer_done.store(false, .release);

    const rc = syscall.thread_create(&producerThread, 0, 4);
    if (rc != 0) {
        t.fail("futex_signal: thread_create failed");
        return;
    }

    var spins: u32 = 0;
    while (!producer_done.load(.acquire) and spins < 100_000) : (spins += 1) {
        if (futex_val.load(.acquire) == 0) {
            _ = syscall.futex_wait(@ptrCast(&futex_val), 0);
        }
        syscall.thread_yield();
    }

    if (futex_val.load(.acquire) == 1) {
        t.pass("futex_signal: producer woke consumer");
    } else {
        t.fail("futex_signal: value not updated");
    }
}
