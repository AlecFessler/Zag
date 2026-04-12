const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const containers = zag.containers;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const PriorityQueue = containers.priority_queue.PriorityQueue;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const E_AGAIN: i64 = -9;
pub const E_TIMEOUT: i64 = -8;
pub const E_NORES: i64 = -14;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;

const Bucket = struct {
    lock: SpinLock = .{},
    pq: PriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{};
var timed_waiters: [MAX_TIMED_WAITERS]?*Thread = [_]?*Thread{null} ** MAX_TIMED_WAITERS;

fn bucketIdx(paddr: PAddr) usize {
    return @intCast((paddr.addr >> 3) % BUCKET_COUNT);
}

fn pushWaiter(bucket: *Bucket, thread: *Thread) void {
    bucket.pq.enqueue(thread);
}

fn removeWaiter(bucket: *Bucket, target: *Thread) bool {
    return bucket.pq.remove(target);
}

fn addTimedWaiter(thread: *Thread) bool {
    const irq = timed_lock.lockIrqSave();
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = thread;
            return true;
        }
    }
    return false;
}

fn removeTimedWaiter(thread: *Thread) void {
    const irq = timed_lock.lockIrqSave();
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == thread) {
            slot.* = null;
            return;
        }
    }
}

/// Remove a killed thread from its futex wait bucket.
/// Called by Process.kill() for threads blocked on futex_wait.
pub fn removeBlockedThread(thread: *Thread) void {
    const bucket = &buckets[bucketIdx(thread.futex_paddr)];
    const irq = bucket.lock.lockIrqSave();
    _ = removeWaiter(bucket, thread);
    if (thread.futex_deadline_ns != 0) {
        thread.futex_deadline_ns = 0;
        removeTimedWaiter(thread);
    }
    bucket.lock.unlockIrqRestore(irq);
    thread.futex_paddr = PAddr.fromInt(0);
}

pub fn wait(paddr: PAddr, expected: u64, timeout_ns: u64, thread: *Thread) i64 {
    const bucket = &buckets[bucketIdx(paddr)];

    const vaddr = VAddr.fromPAddr(paddr, null);
    const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);

    const irq = bucket.lock.lockIrqSave();

    if (@atomicLoad(u64, value_ptr, .acquire) != expected) {
        bucket.lock.unlockIrqRestore(irq);
        return E_AGAIN;
    }

    if (timeout_ns == 0) {
        bucket.lock.unlockIrqRestore(irq);
        return E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    thread.futex_paddr = paddr;
    if (timeout_ns != max_timeout) {
        const now_ns = arch.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    thread.state = .blocked;
    pushWaiter(bucket, thread);

    bucket.lock.unlockIrqRestore(irq);

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            // All timed waiter slots are full. Undo the block.
            const irq2 = bucket.lock.lockIrqSave();
            _ = removeWaiter(bucket, thread);
            bucket.lock.unlockIrqRestore(irq2);
            thread.state = .running;
            thread.futex_paddr = PAddr.fromInt(0);
            thread.futex_deadline_ns = 0;
            return E_NORES;
        }
    }

    arch.enableInterrupts();
    sched.yield();

    const was_timeout: bool = thread.futex_deadline_ns == @as(u64, @bitCast(E_TIMEOUT));
    thread.futex_deadline_ns = 0;
    return if (was_timeout) E_TIMEOUT else 0;
}

pub fn wake(paddr: PAddr, count: u32) u64 {
    const bucket = &buckets[bucketIdx(paddr)];
    var woken: u32 = 0;

    const irq = bucket.lock.lockIrqSave();

    // Pop threads from the priority queue. Since multiple paddrs may hash to
    // the same bucket, we must check each thread's futex_paddr. Non-matching
    // threads are collected and re-enqueued after the wake loop.
    var requeue: PriorityQueue = .{};

    while (woken < count) {
        const thread = bucket.pq.dequeue() orelse break;
        if (thread.futex_paddr.addr == paddr.addr) {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            if (thread.futex_deadline_ns != 0) {
                thread.futex_deadline_ns = 0;
                removeTimedWaiter(thread);
            }
            thread.state = .ready;
            const target_core = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.coreID();
            sched.enqueueOnCore(target_core, thread);
            woken += 1;
        } else {
            requeue.enqueue(thread);
        }
    }

    // Re-enqueue non-matching threads back into the bucket
    while (requeue.dequeue()) |t| {
        bucket.pq.enqueue(t);
    }

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}

pub fn expireTimedWaiters() void {
    const now_ns = arch.getMonotonicClock().now();

    const irq = timed_lock.lockIrqSave();

    for (&timed_waiters) |*slot| {
        const thread = slot.* orelse continue;
        if (thread.futex_deadline_ns == 0 or now_ns < thread.futex_deadline_ns) continue;

        const bucket = &buckets[bucketIdx(thread.futex_paddr)];
        const birq = bucket.lock.lockIrqSave();
        const removed = removeWaiter(bucket, thread);
        bucket.lock.unlockIrqRestore(birq);

        if (removed) {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            thread.futex_deadline_ns = @bitCast(E_TIMEOUT);
            thread.state = .ready;
            const target = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.coreID();
            sched.enqueueOnCore(target, thread);
        }
        slot.* = null;
    }

    timed_lock.unlockIrqRestore(irq);
}
