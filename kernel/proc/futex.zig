const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const ThreadPriorityQueue = zag.sched.thread.ThreadPriorityQueue;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const E_AGAIN: i64 = -9;
pub const E_TIMEOUT: i64 = -8;
pub const E_NORES: i64 = -14;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;

/// `Bucket.lock` ordered_group. Multi-bucket waits and the wake-side
/// cross-bucket cleanup both hold two `Bucket.lock` instances at once;
/// `sortByBucket` (waits) and the `except_idx` skip in
/// `removeFromOtherBuckets` (wake) keep acquisition AB-BA-free.
const FUTEX_BUCKET_GROUP: u32 = 1;

const Bucket = struct {
    lock: SpinLock = .{ .class = "Bucket.lock" },
    pq: ThreadPriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{ .class = "futex.timed_lock" };
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
    const irq = timed_lock.lockIrqSave(@src());
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
    const irq = timed_lock.lockIrqSave(@src());
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == thread) {
            slot.* = null;
            return;
        }
    }
}

/// Remove a killed thread from its futex wait bucket(s).
/// Called by Process.kill() for threads blocked on futex_wait.
pub fn removeBlockedThread(thread: *Thread) void {
    if (thread.futex_bucket_count > 0) {
        // Multi-address wait: remove from all buckets
        for (thread.futex_paddrs[0..thread.futex_bucket_count]) |pa| {
            const bucket = &buckets[bucketIdx(pa)];
            const irq = bucket.lock.lockIrqSave(@src());
            _ = removeWaiter(bucket, thread);
            bucket.lock.unlockIrqRestore(irq);
        }
        thread.futex_bucket_count = 0;
    } else {
        const bucket = &buckets[bucketIdx(thread.futex_paddr)];
        const irq = bucket.lock.lockIrqSave(@src());
        _ = removeWaiter(bucket, thread);
        bucket.lock.unlockIrqRestore(irq);
    }
    if (thread.futex_deadline_ns != 0) {
        thread.futex_deadline_ns = 0;
        removeTimedWaiter(thread);
    }
    thread.futex_paddr = PAddr.fromInt(0);
}

pub fn wait(paddr: PAddr, expected: u64, timeout_ns: u64, thread: *Thread) i64 {
    const bucket = &buckets[bucketIdx(paddr)];

    const vaddr = VAddr.fromPAddr(paddr, null);
    const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);

    const irq = bucket.lock.lockIrqSave(@src());

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
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    thread.state = .blocked;
    pushWaiter(bucket, thread);

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            // All timed waiter slots are full. Undo while still holding lock
            // to avoid deadlock with concurrent wake() spinning on on_cpu.
            _ = removeWaiter(bucket, thread);
            bucket.lock.unlockIrqRestore(irq);
            thread.state = .running;
            thread.futex_paddr = PAddr.fromInt(0);
            thread.futex_deadline_ns = 0;
            return E_NORES;
        }
    }

    bucket.lock.unlockIrqRestore(irq);

    arch.cpu.enableInterrupts();
    sched.yield();

    const was_timeout: bool = thread.futex_deadline_ns == @as(u64, @bitCast(E_TIMEOUT));
    thread.futex_deadline_ns = 0;
    return if (was_timeout) E_TIMEOUT else 0;
}

pub fn wake(paddr: PAddr, count: u32) u64 {
    const bucket = &buckets[bucketIdx(paddr)];
    var woken: u32 = 0;

    const irq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);

    // Pop threads from the priority queue. Since multiple paddrs may hash to
    // the same bucket, we must check each thread's futex_paddr. Non-matching
    // threads are collected and re-enqueued after the wake loop.
    var requeue: ThreadPriorityQueue = .{};

    while (woken < count) {
        const thread = bucket.pq.dequeue() orelse break;

        // For multi-address waits, check if any of the thread's addresses match.
        if (thread.futex_bucket_count > 0) {
            var matched = false;
            for (thread.futex_paddrs[0..thread.futex_bucket_count], 0..) |pa, idx| {
                if (pa.addr == paddr.addr) {
                    thread.futex_wake_index = @intCast(idx);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                requeue.enqueue(thread);
                continue;
            }
            // Remove from all OTHER buckets
            removeFromOtherBuckets(thread, paddr);
        } else if (thread.futex_paddr.addr == paddr.addr) {
            thread.futex_wake_index = 0;
        } else {
            requeue.enqueue(thread);
            continue;
        }

        while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        if (thread.futex_deadline_ns != 0) {
            thread.futex_deadline_ns = 0;
            removeTimedWaiter(thread);
        }
        thread.futex_bucket_count = 0;
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask|
            @as(u64, @ctz(mask))
        else
            arch.smp.coreID();
        sched.enqueueOnCore(target_core, thread);
        woken += 1;
    }

    // Re-enqueue non-matching threads back into the bucket
    while (requeue.dequeue()) |t| {
        bucket.pq.enqueue(t);
    }

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}

/// Remove a thread from all futex buckets except the one matching `except_paddr`.
/// Called while the bucket for `except_paddr` is already locked.
fn removeFromOtherBuckets(thread: *Thread, except_paddr: PAddr) void {
    const except_idx = bucketIdx(except_paddr);
    for (thread.futex_paddrs[0..thread.futex_bucket_count]) |pa| {
        const idx = bucketIdx(pa);
        if (idx == except_idx) continue;
        const bucket = &buckets[idx];
        const birq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
        _ = removeWaiter(bucket, thread);
        bucket.lock.unlockIrqRestore(birq);
    }
}

/// Multi-address futex wait with expected values.
/// Returns:
///   0..count-1 = index of the first mismatched address (mismatch, no block), or
///   0..count-1 = index of the address that was woken (after blocking),
///   E_TIMEOUT if timeout expired, E_NORES if no timed waiter slot.
pub fn waitVal(addrs: []const PAddr, expected: []const u64, count: usize, timeout_ns: u64, thread: *Thread) i64 {
    // Sort bucket indices for consistent lock ordering to prevent deadlock.
    var sorted: [64]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    // Acquire all bucket locks in sorted order.
    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    // Check all addresses against expected values.
    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        if (@atomicLoad(u64, value_ptr, .acquire) != expected[i]) {
            releaseBucketLocks(&lock_state);
            return @intCast(i);
        }
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return E_TIMEOUT;
    }

    // Set up timeout.
    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    // Store addresses and enqueue in all buckets.
    thread.futex_bucket_count = @intCast(count);
    for (0..count) |i| {
        thread.futex_paddrs[i] = addrs[i];
    }
    // Also set futex_paddr to first addr for backwards compat.
    thread.futex_paddr = addrs[0];
    thread.state = .blocked;

    for (0..count) |i| {
        pushWaiter(&buckets[bucketIdx(addrs[i])], thread);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            // Undo while still holding bucket locks to avoid deadlock with
            // concurrent wake() spinning on on_cpu.
            for (0..count) |i| {
                _ = removeWaiter(&buckets[bucketIdx(addrs[i])], thread);
            }
            releaseBucketLocks(&lock_state);
            thread.state = .running;
            thread.futex_paddr = PAddr.fromInt(0);
            thread.futex_bucket_count = 0;
            thread.futex_deadline_ns = 0;
            return E_NORES;
        }
    }

    releaseBucketLocks(&lock_state);

    arch.cpu.enableInterrupts();
    sched.yield();

    const was_timeout: bool = thread.futex_deadline_ns == @as(u64, @bitCast(E_TIMEOUT));
    thread.futex_deadline_ns = 0;
    thread.futex_bucket_count = 0;
    if (was_timeout) return E_TIMEOUT;
    return @intCast(thread.futex_wake_index);
}

/// Multi-address futex wait that reads current values under lock.
/// Same as waitVal but uses current memory values as expected.
pub fn waitChange(addrs: []const PAddr, count: usize, timeout_ns: u64, thread: *Thread) i64 {
    // Sort bucket indices for consistent lock ordering.
    var sorted: [64]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    // Acquire all bucket locks in sorted order.
    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    // Read current values under locks.
    var current: [64]u64 = undefined;
    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        current[i] = @atomicLoad(u64, value_ptr, .acquire);
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return E_TIMEOUT;
    }

    // Set up timeout.
    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    // Store addresses and enqueue in all buckets.
    thread.futex_bucket_count = @intCast(count);
    for (0..count) |i| {
        thread.futex_paddrs[i] = addrs[i];
    }
    thread.futex_paddr = addrs[0];
    thread.state = .blocked;

    for (0..count) |i| {
        pushWaiter(&buckets[bucketIdx(addrs[i])], thread);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            // Undo while still holding bucket locks to avoid deadlock with
            // concurrent wake() spinning on on_cpu.
            for (0..count) |i| {
                _ = removeWaiter(&buckets[bucketIdx(addrs[i])], thread);
            }
            releaseBucketLocks(&lock_state);
            thread.state = .running;
            thread.futex_paddr = PAddr.fromInt(0);
            thread.futex_bucket_count = 0;
            thread.futex_deadline_ns = 0;
            return E_NORES;
        }
    }

    releaseBucketLocks(&lock_state);

    arch.cpu.enableInterrupts();
    sched.yield();

    const was_timeout: bool = thread.futex_deadline_ns == @as(u64, @bitCast(E_TIMEOUT));
    thread.futex_deadline_ns = 0;
    thread.futex_bucket_count = 0;
    if (was_timeout) return E_TIMEOUT;
    return @intCast(thread.futex_wake_index);
}

/// Holds lock state for multi-bucket acquisition.
const BucketLockState = struct {
    /// Unique bucket indices in sorted order.
    unique_indices: [64]usize = undefined,
    /// Saved IRQ state per unique bucket.
    irq_states: [64]u64 = undefined,
    /// Number of unique buckets locked.
    count: usize = 0,
};

/// Sort indices by bucket index for consistent lock acquisition order.
fn sortByBucket(indices: []u8, addrs: []const PAddr) void {
    // Simple insertion sort — count is at most 64.
    var i: usize = 1;
    while (i < indices.len) {
        var j = i;
        while (j > 0 and bucketIdx(addrs[indices[j]]) < bucketIdx(addrs[indices[j - 1]])) {
            const tmp = indices[j];
            indices[j] = indices[j - 1];
            indices[j - 1] = tmp;
            j -= 1;
        }
        i += 1;
    }
}

/// Acquire bucket locks in sorted order, skipping duplicates.
fn acquireBucketLocks(sorted: []const u8, addrs: []const PAddr) BucketLockState {
    var state = BucketLockState{};
    var prev_idx: usize = std.math.maxInt(usize);
    for (sorted) |si| {
        const idx = bucketIdx(addrs[si]);
        if (idx == prev_idx) continue;
        const irq = buckets[idx].lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
        state.unique_indices[state.count] = idx;
        state.irq_states[state.count] = irq;
        state.count += 1;
        prev_idx = idx;
    }
    return state;
}

/// Release bucket locks in reverse order.
fn releaseBucketLocks(lock_state: *const BucketLockState) void {
    var i: usize = lock_state.count;
    while (i > 0) {
        i -= 1;
        buckets[lock_state.unique_indices[i]].lock.unlockIrqRestore(lock_state.irq_states[i]);
    }
}

pub fn expireTimedWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    // Phase 1: snapshot expired threads + clear their slots, all under
    // timed_lock. Capturing the deadline lets phase 2 detect a thread that
    // was woken and re-registered as a fresh waiter between phases.
    //
    // The split is required by lock-order: wait() and wake() acquire
    // bucket.lock then timed_lock; if we held timed_lock here while
    // taking bucket.lock, that would form an AB-BA cycle.
    const Snapshot = struct { thread: *Thread, deadline: u64 };
    var expired: [MAX_TIMED_WAITERS]Snapshot = undefined;
    var expired_count: usize = 0;
    {
        const irq = timed_lock.lockIrqSave(@src());
        defer timed_lock.unlockIrqRestore(irq);
        for (&timed_waiters) |*slot| {
            const thread = slot.* orelse continue;
            if (thread.futex_deadline_ns == 0 or now_ns < thread.futex_deadline_ns) continue;
            expired[expired_count] = .{ .thread = thread, .deadline = thread.futex_deadline_ns };
            expired_count += 1;
            slot.* = null;
        }
    }

    // Phase 2: per-thread, take only bucket.lock (never timed_lock).
    for (expired[0..expired_count]) |entry| {
        const thread = entry.thread;
        // Re-check deadline. If wake() ran between phases, deadline is now
        // 0; if the thread was woken and made a new wait, deadline differs.
        // In both cases this snapshot is stale — skip.
        if (thread.futex_deadline_ns != entry.deadline) continue;

        var removed: bool = false;
        if (thread.futex_bucket_count > 0) {
            for (thread.futex_paddrs[0..thread.futex_bucket_count]) |pa| {
                const bucket = &buckets[bucketIdx(pa)];
                const birq = bucket.lock.lockIrqSave(@src());
                if (removeWaiter(bucket, thread)) removed = true;
                bucket.lock.unlockIrqRestore(birq);
            }
        } else {
            const bucket = &buckets[bucketIdx(thread.futex_paddr)];
            const birq = bucket.lock.lockIrqSave(@src());
            removed = removeWaiter(bucket, thread);
            bucket.lock.unlockIrqRestore(birq);
        }

        if (removed) {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            thread.futex_deadline_ns = @bitCast(E_TIMEOUT);
            thread.state = .ready;
            const target = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.smp.coreID();
            sched.enqueueOnCore(target, thread);
        }
    }
}
