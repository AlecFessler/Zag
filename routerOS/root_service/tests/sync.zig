const lib = @import("lib");
const std = @import("std");

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
        shared_counter += 1;
        mutex.unlock();
    }
    _ = @atomicRmw(u64, &done_flag, .Add, 1, .release);
    _ = syscall.futex_wake(&done_flag, 10);
    syscall.thread_exit();
}

var condvar_value: u64 align(8) = 0;
var condvar_mutex: sync.Mutex = sync.Mutex.init();
var condvar: sync.Condvar = sync.Condvar.init();
var condvar_done: u64 align(8) = 0;

fn condvarWaiterThread() void {
    condvar_mutex.lock();
    while (@atomicLoad(u64, &condvar_value, .acquire) == 0) {
        condvar.wait(&condvar_mutex);
    }
    condvar_mutex.unlock();
    _ = @atomicRmw(u64, &condvar_done, .Add, 1, .release);
    _ = syscall.futex_wake(&condvar_done, 10);
    syscall.thread_exit();
}

var sem: sync.Semaphore = sync.Semaphore.init(0);
var sem_received: u64 align(8) = 0;

fn semWaiterThread() void {
    sem.wait();
    @atomicStore(u64, &sem_received, 1, .release);
    _ = syscall.futex_wake(&sem_received, 1);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("sync primitives");
    testMutexUncontended();
    testMutexContended();
    testCondvarSignal();
    testSemaphoreBlocking();
    testSemaphoreCounting();
}

fn testMutexUncontended() void {
    var m = sync.Mutex.init();
    m.lock();
    m.unlock();
    m.lock();
    m.unlock();
    t.pass("mutex: lock+unlock twice without contention");
}

fn testMutexContended() void {
    @atomicStore(u64, &shared_counter, 0, .release);
    @atomicStore(u64, &done_flag, 0, .release);

    const rc1 = syscall.thread_create(&incrementThread, 0, 4);
    const rc2 = syscall.thread_create(&incrementThread, 0, 4);
    if (rc1 != 0 or rc2 != 0) {
        t.fail("mutex contended: thread_create failed");
        return;
    }

    while (@atomicLoad(u64, &done_flag, .acquire) < 2) {
        _ = syscall.futex_wait(&done_flag, @atomicLoad(u64, &done_flag, .acquire), @bitCast(@as(i64, -1)));
    }

    const val = @atomicLoad(u64, &shared_counter, .acquire);
    if (val == 200) {
        t.pass("mutex: 2 threads x 100 increments = 200 (no data race)");
    } else {
        t.failWithVal("mutex: contention produced wrong count", 200, @as(i64, @bitCast(val)));
    }
}

fn testCondvarSignal() void {
    @atomicStore(u64, &condvar_value, 0, .release);
    @atomicStore(u64, &condvar_done, 0, .release);
    condvar_mutex = sync.Mutex.init();
    condvar = sync.Condvar.init();

    const rc = syscall.thread_create(&condvarWaiterThread, 0, 4);
    if (rc != 0) {
        t.fail("condvar: thread_create failed");
        return;
    }

    syscall.thread_yield();
    syscall.thread_yield();

    condvar_mutex.lock();
    @atomicStore(u64, &condvar_value, 1, .release);
    condvar.signal();
    condvar_mutex.unlock();

    while (@atomicLoad(u64, &condvar_done, .acquire) == 0) {
        _ = syscall.futex_wait(&condvar_done, 0, @bitCast(@as(i64, -1)));
    }

    t.pass("condvar: signal woke blocked waiter thread");
}

fn testSemaphoreBlocking() void {
    sem = sync.Semaphore.init(0);
    @atomicStore(u64, &sem_received, 0, .release);

    const rc = syscall.thread_create(&semWaiterThread, 0, 4);
    if (rc != 0) {
        t.fail("semaphore blocking: thread_create failed");
        return;
    }

    syscall.thread_yield();
    syscall.thread_yield();

    sem.post();

    while (@atomicLoad(u64, &sem_received, .acquire) == 0) {
        _ = syscall.futex_wait(&sem_received, 0, @bitCast(@as(i64, -1)));
    }

    t.pass("semaphore: post unblocks waiting thread");
}

fn testSemaphoreCounting() void {
    var s = sync.Semaphore.init(3);
    s.wait();
    s.wait();
    s.wait();
    s.post();
    s.post();
    s.wait();
    s.wait();
    t.pass("semaphore: counting works (init 3, wait 3, post 2, wait 2)");
}
