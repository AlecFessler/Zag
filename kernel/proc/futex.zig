const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const Priority = zag.sched.thread.Priority;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const E_AGAIN: i64 = -9;
pub const E_TIMEOUT: i64 = -8;
pub const E_NORES: i64 = -14;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;
pub const MAX_FUTEX_ADDRS = 64;

/// Per-(thread, bucket) wait entry. Allocated on the waiting thread's
/// kernel stack — one per address in a multi-address wait — and threaded
/// into bucket queues via its own `next` field. This is what gives each
/// bucket its own intrusive link slot, so multi-address waits can't
/// cross-pollute the chains the way they did when every bucket shared
/// `Thread.next`.
pub const WaitNode = struct {
    thread: SlabRef(Thread),
    paddr: PAddr,
    next: ?*WaitNode = null,
    priority: Priority,
};

const WaitNodePriorityQueue = zag.utils.containers.priority_queue.PriorityQueue(
    WaitNode,
    "next",
    "priority",
    std.meta.fields(Priority).len,
);

/// `Bucket.lock` ordered_group. Multi-bucket waits and the wake-side
/// cross-bucket cleanup both hold two `Bucket.lock` instances at once;
/// `sortByBucket` (waits) and the `except_idx` skip in
/// `removeFromOtherBuckets` (wake) keep acquisition AB-BA-free.
const FUTEX_BUCKET_GROUP: u32 = 1;

const Bucket = struct {
    lock: SpinLock = .{ .class = "Bucket.lock" },
    pq: WaitNodePriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{ .class = "futex.timed_lock" };
var timed_waiters: [MAX_TIMED_WAITERS]?*Thread = [_]?*Thread{null} ** MAX_TIMED_WAITERS;

fn bucketIdx(paddr: PAddr) usize {
    return @intCast((paddr.addr >> 3) % BUCKET_COUNT);
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

/// Remove every node owned by `thread` from its bucket(s), without
/// touching the bucket whose lock the caller already holds (identified
/// by `held_idx`; pass an out-of-range value if none is held). Same-
/// bucket nodes other than `except_node` are removed under the held
/// lock without re-acquisition.
fn removeNodesExcept(thread: *Thread, except_node: *const WaitNode, held_idx: usize) void {
    const nodes = thread.futex_wait_nodes orelse return;
    const count: usize = thread.futex_bucket_count;
    var i: usize = 0;
    while (i < count) {
        const node = &nodes[i];
        if (node == except_node) {
            i += 1;
            continue;
        }
        const idx = bucketIdx(node.paddr);
        const bucket = &buckets[idx];
        if (idx == held_idx) {
            _ = bucket.pq.remove(node);
        } else {
            // Caller (wake) already holds buckets[held_idx].lock; this
            // is a second `Bucket.lock` acquisition in the same class.
            // The `idx == held_idx` skip above plus the strict
            // bucket-index ordering used by `acquireBucketLocks` keeps
            // the global acquisition graph AB-BA-free, so opt out of
            // the same-class overlap panic via FUTEX_BUCKET_GROUP.
            const birq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);
            _ = bucket.pq.remove(node);
            bucket.lock.unlockIrqRestore(birq);
        }
        i += 1;
    }
}

/// Remove a killed thread from any futex bucket(s) and the timed list.
/// Called by Process.kill / sysThreadKill / fault tear-down for threads
/// blocked on a futex.
pub fn removeBlockedThread(thread: *Thread) void {
    if (thread.futex_wait_nodes) |nodes| {
        const count: usize = thread.futex_bucket_count;
        var i: usize = 0;
        while (i < count) {
            const node = &nodes[i];
            const bucket = &buckets[bucketIdx(node.paddr)];
            const irq = bucket.lock.lockIrqSave(@src());
            _ = bucket.pq.remove(node);
            bucket.lock.unlockIrqRestore(irq);
            i += 1;
        }
        thread.futex_wait_nodes = null;
        thread.futex_bucket_count = 0;
    }
    if (thread.futex_deadline_ns != 0) {
        thread.futex_deadline_ns = 0;
        removeTimedWaiter(thread);
    }
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
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    var nodes: [1]WaitNode = .{.{
        .thread = SlabRef(Thread).init(thread, thread._gen_lock.currentGen()),
        .paddr = paddr,
        .priority = thread.priority,
    }};
    thread.futex_wait_nodes = &nodes;
    thread.futex_bucket_count = 1;
    thread.state = .blocked;
    bucket.pq.enqueue(&nodes[0]);

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            // All timed waiter slots are full. Undo while still holding
            // the bucket lock to keep wake() (which spins on on_cpu) out
            // of a deadlock.
            _ = bucket.pq.remove(&nodes[0]);
            bucket.lock.unlockIrqRestore(irq);
            thread.state = .running;
            thread.futex_wait_nodes = null;
            thread.futex_bucket_count = 0;
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
    const wake_idx = bucketIdx(paddr);
    const bucket = &buckets[wake_idx];
    var woken: u32 = 0;

    const irq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);

    // Multiple paddrs may hash to the same bucket, so a dequeued node
    // may not match the wake's paddr. Non-matching nodes are collected
    // and re-enqueued after the loop.
    var requeue: WaitNodePriorityQueue = .{};

    while (woken < count) {
        const node = bucket.pq.dequeue() orelse break;

        if (node.paddr.addr != paddr.addr) {
            requeue.enqueue(node);
            continue;
        }

        // self-alive: the node lives on the waiting thread's kernel
        // stack — the thread cannot have been freed while this node is
        // still in our bucket. The gen-locked SlabRef is for tooling
        // uniformity and the implicit liveness assertion.
        const thread = node.thread.lock(@src()) catch continue;
        node.thread.unlock();

        // wake_index is the offset of this node in the thread's
        // wait_nodes array — the index of the address in the original
        // multi-address wait that matched.
        const nodes = thread.futex_wait_nodes.?;
        const node_idx: usize = (@intFromPtr(node) - @intFromPtr(nodes)) / @sizeOf(WaitNode);
        thread.futex_wake_index = @intCast(node_idx);

        // Drop this thread's other nodes from every bucket they live
        // in (skipping the just-dequeued node and using the held lock
        // for any same-bucket sibling).
        removeNodesExcept(thread, node, wake_idx);

        while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        if (thread.futex_deadline_ns != 0) {
            thread.futex_deadline_ns = 0;
            removeTimedWaiter(thread);
        }
        thread.futex_bucket_count = 0;
        thread.futex_wait_nodes = null;
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask|
            @as(u64, @ctz(mask))
        else
            arch.smp.coreID();
        sched.enqueueOnCore(target_core, thread);
        woken += 1;
    }

    while (requeue.dequeue()) |n| bucket.pq.enqueue(n);

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}

/// Multi-address futex wait with expected values.
/// Returns:
///   0..count-1 = index of the first mismatched address (mismatch, no block), or
///   0..count-1 = index of the address that was woken (after blocking),
///   E_TIMEOUT if timeout expired, E_NORES if no timed waiter slot.
pub fn waitVal(addrs: []const PAddr, expected: []const u64, count: usize, timeout_ns: u64, thread: *Thread) i64 {
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

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

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    var nodes: [MAX_FUTEX_ADDRS]WaitNode = undefined;
    const thread_ref = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .thread = thread_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = thread.priority,
        };
    }
    thread.futex_wait_nodes = &nodes;
    thread.futex_bucket_count = @intCast(count);
    thread.state = .blocked;

    for (0..count) |i| {
        buckets[bucketIdx(addrs[i])].pq.enqueue(&nodes[i]);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            for (0..count) |i| {
                _ = buckets[bucketIdx(addrs[i])].pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            thread.state = .running;
            thread.futex_wait_nodes = null;
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
    if (was_timeout) return E_TIMEOUT;
    return @intCast(thread.futex_wake_index);
}

/// Multi-address futex wait that reads current values under lock.
/// Same as waitVal but uses current memory values as expected.
pub fn waitChange(addrs: []const PAddr, count: usize, timeout_ns: u64, thread: *Thread) i64 {
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    var current: [MAX_FUTEX_ADDRS]u64 = undefined;
    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        current[i] = @atomicLoad(u64, value_ptr, .acquire);
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        thread.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        thread.futex_deadline_ns = 0;
    }

    var nodes: [MAX_FUTEX_ADDRS]WaitNode = undefined;
    const thread_ref = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .thread = thread_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = thread.priority,
        };
    }
    thread.futex_wait_nodes = &nodes;
    thread.futex_bucket_count = @intCast(count);
    thread.state = .blocked;

    for (0..count) |i| {
        buckets[bucketIdx(addrs[i])].pq.enqueue(&nodes[i]);
    }

    if (thread.futex_deadline_ns != 0) {
        if (!addTimedWaiter(thread)) {
            for (0..count) |i| {
                _ = buckets[bucketIdx(addrs[i])].pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            thread.state = .running;
            thread.futex_wait_nodes = null;
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
    if (was_timeout) return E_TIMEOUT;
    return @intCast(thread.futex_wake_index);
}

/// Holds lock state for multi-bucket acquisition.
const BucketLockState = struct {
    /// Unique bucket indices in sorted order.
    unique_indices: [MAX_FUTEX_ADDRS]usize = undefined,
    /// Saved IRQ state per unique bucket.
    irq_states: [MAX_FUTEX_ADDRS]u64 = undefined,
    /// Number of unique buckets locked.
    count: usize = 0,
};

/// Sort indices by bucket index for consistent lock acquisition order.
fn sortByBucket(indices: []u8, addrs: []const PAddr) void {
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
    // timed_lock. Capturing the deadline lets phase 2 detect a thread
    // that was woken and re-registered as a fresh waiter between phases.
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
        // Re-check deadline. If wake() ran between phases, deadline is
        // now 0; if the thread was woken and made a new wait, deadline
        // differs. In both cases this snapshot is stale — skip.
        if (thread.futex_deadline_ns != entry.deadline) continue;

        const nodes = thread.futex_wait_nodes orelse continue;
        const count: usize = thread.futex_bucket_count;
        var removed: bool = false;
        var i: usize = 0;
        while (i < count) {
            const node = &nodes[i];
            const bucket = &buckets[bucketIdx(node.paddr)];
            const birq = bucket.lock.lockIrqSave(@src());
            if (bucket.pq.remove(node)) removed = true;
            bucket.lock.unlockIrqRestore(birq);
            i += 1;
        }

        if (removed) {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            thread.futex_deadline_ns = @bitCast(E_TIMEOUT);
            thread.futex_bucket_count = 0;
            thread.futex_wait_nodes = null;
            thread.state = .ready;
            const target = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.smp.coreID();
            sched.enqueueOnCore(target, thread);
        }
    }
}
