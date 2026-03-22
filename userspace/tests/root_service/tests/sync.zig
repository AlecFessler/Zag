const lib = @import("lib");
const std = @import("std");

const crc32 = lib.crc32;
const sync = lib.sync;
const syscall = lib.syscall;
const t = lib.testing;

var shared_counter: u64 align(8) = 0;
var mutex: sync.Mutex = sync.Mutex.init();
var done_flag: u64 align(8) = 0;

fn incrementThread() void {
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        mutex.lock();
        @as(*volatile u64, &shared_counter).* += 1;
        mutex.unlock();
    }
    _ = @atomicRmw(u64, &done_flag, .Add, 1, .release);
    _ = syscall.futex_wake(&done_flag, 10);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("sync primitives + crc32");
    testMutexBasic();
    testMutexContended();
    testSemaphoreBasic();
    testCrc32KnownVector();
}

fn testMutexBasic() void {
    var m = sync.Mutex.init();
    m.lock();
    m.unlock();
    t.pass("S5: mutex lock+unlock without contention");
}

fn testMutexContended() void {
    @as(*volatile u64, &shared_counter).* = 0;
    @as(*volatile u64, &done_flag).* = 0;

    const rc1 = syscall.thread_create(&incrementThread, 0, 4);
    const rc2 = syscall.thread_create(&incrementThread, 0, 4);
    if (rc1 != 0 or rc2 != 0) {
        t.fail("thread_create failed for mutex test");
        return;
    }

    while (@atomicLoad(u64, &done_flag, .acquire) < 2) {
        _ = syscall.futex_wait(&done_flag, @atomicLoad(u64, &done_flag, .acquire), @bitCast(@as(i64, -1)));
    }

    const val = @as(*volatile u64, &shared_counter).*;
    if (val == 200) {
        t.pass("S5: mutex protects shared counter across 2 threads (200 increments)");
    } else {
        t.failWithVal("S5: mutex contention: expected 200", 200, @as(i64, @bitCast(val)));
    }
}

fn testSemaphoreBasic() void {
    var sem = sync.Semaphore.init(1);
    sem.wait();
    sem.post();
    sem.post();
    sem.wait();
    sem.wait();
    t.pass("S5: semaphore post/wait sequence correct");
}

fn testCrc32KnownVector() void {
    const input = "123456789";
    const expected: u32 = 0xCBF43926;
    const result = crc32.compute(input);
    if (result == expected) {
        t.pass("S5: crc32(\"123456789\") = 0xCBF43926");
    } else {
        t.fail("S5: crc32 known vector mismatch");
    }
}
