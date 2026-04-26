//! Futex — physical-address-keyed user-space synchronization primitive.
//! Spec §[futex].
//!
//! The kernel hashes the watched physical address into one of
//! `BUCKET_COUNT` buckets, each holding a priority-ordered intrusive
//! queue of `WaitNode`s. A multi-address wait allocates one `WaitNode`
//! per watched address on the EC's own kernel stack, so the EC
//! simultaneously occupies N independent bucket chains without aliasing
//! a shared link — the per-bucket queues cannot cross-pollute the way
//! they would if every bucket reached for the same EC link slot.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const sched = zag.sched.scheduler;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PAddr = zag.memory.address.PAddr;
const Priority = zag.sched.execution_context.Priority;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

const BUCKET_COUNT = 256;
const MAX_TIMED_WAITERS = 64;
pub const MAX_FUTEX_ADDRS = 63;

/// Per-(EC, bucket) wait entry. Allocated on the waiting EC's kernel
/// stack — one per address in a multi-address wait — and threaded into
/// bucket queues via its own `next` field. Each node carries its own
/// link slot so multi-address waits cannot cross-pollute the chains.
pub const WaitNode = struct {
    ec: SlabRef(ExecutionContext),
    paddr: PAddr,
    next: ?*WaitNode = null,
    priority: Priority,
};

const WaitNodePriorityQueue = zag.utils.containers.priority_queue.PriorityQueue(
    WaitNode,
    "next",
    "priority",
    @typeInfo(Priority).@"enum".fields.len,
);

/// `Bucket.lock` ordered_group. Multi-bucket waits and the wake-side
/// cross-bucket cleanup both hold two `Bucket.lock` instances at once;
/// `sortByBucket` (waits) and the `except_idx` skip in
/// `removeNodesExcept` (wake) keep acquisition AB-BA-free.
const FUTEX_BUCKET_GROUP: u32 = 1;

const Bucket = struct {
    lock: SpinLock = .{ .class = "Bucket.lock" },
    pq: WaitNodePriorityQueue = .{},
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

var timed_lock: SpinLock = .{ .class = "futex.timed_lock" };
var timed_waiters: [MAX_TIMED_WAITERS]?*ExecutionContext = [_]?*ExecutionContext{null} ** MAX_TIMED_WAITERS;

/// Returned by `wakeFromIrq`: count of woken ECs plus the mask of cores
/// that need an explicit wake IPI follow-up. The IRQ path can't ride
/// `enqueueOnCore`'s normal IPI emission because the caller wants to
/// batch IPIs across the entire device handle list.
pub const WakeResult = struct {
    woken: u32 = 0,
    idle_core_mask: u64 = 0,
};

fn bucketIdx(paddr: PAddr) usize {
    return @intCast((paddr.addr >> 3) % BUCKET_COUNT);
}

fn addTimedWaiter(ec: *ExecutionContext) bool {
    const irq = timed_lock.lockIrqSave(@src());
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == null) {
            slot.* = ec;
            return true;
        }
    }
    return false;
}

fn removeTimedWaiter(ec: *ExecutionContext) void {
    const irq = timed_lock.lockIrqSave(@src());
    defer timed_lock.unlockIrqRestore(irq);
    for (&timed_waiters) |*slot| {
        if (slot.* == ec) {
            slot.* = null;
            return;
        }
    }
}

/// Remove every node owned by `ec` from its bucket(s), without
/// touching the bucket whose lock the caller already holds (identified
/// by `held_idx`; pass an out-of-range value if none is held). Same-
/// bucket nodes other than `except_node` are removed under the held
/// lock without re-acquisition.
fn removeNodesExcept(ec: *ExecutionContext, except_node: *const WaitNode, held_idx: usize) void {
    const nodes = ec.futex_wait_nodes orelse return;
    const count: usize = ec.futex_bucket_count;
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

/// Pick the destination core for a wakeup, honoring `ec.affinity`.
/// `affinity == 0` is the spec-defined "any core" sentinel; we fall
/// back to the local core in that case to keep cache locality.
fn pickCoreForEc(ec: *ExecutionContext) u64 {
    if (ec.affinity == 0) return arch.smp.coreID();
    return @ctz(ec.affinity);
}

/// Drop a torn-down EC from any futex bucket(s) and the timed list.
/// Called by `terminate` and event tear-down for ECs blocked on a futex.
pub fn removeBlockedEc(ec: *ExecutionContext) void {
    if (ec.futex_wait_nodes) |nodes| {
        const count: usize = ec.futex_bucket_count;
        var i: usize = 0;
        while (i < count) {
            const node = &nodes[i];
            const bucket = &buckets[bucketIdx(node.paddr)];
            const irq = bucket.lock.lockIrqSave(@src());
            _ = bucket.pq.remove(node);
            bucket.lock.unlockIrqRestore(irq);
            i += 1;
        }
        ec.futex_wait_nodes = null;
        ec.futex_bucket_count = 0;
    }
    if (ec.futex_deadline_ns != 0) {
        ec.futex_deadline_ns = 0;
        removeTimedWaiter(ec);
    }
}

/// Single-address futex wait. Equivalent to `waitVal` with N=1; kept
/// as a thin entry point for callers that don't want to materialize a
/// one-element slice.
pub fn wait(paddr: PAddr, expected: u64, timeout_ns: u64, ec: *ExecutionContext) i64 {
    const bucket = &buckets[bucketIdx(paddr)];

    const vaddr = VAddr.fromPAddr(paddr, null);
    const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);

    const irq = bucket.lock.lockIrqSave(@src());

    if (@atomicLoad(u64, value_ptr, .acquire) != expected) {
        bucket.lock.unlockIrqRestore(irq);
        return errors.E_AGAIN;
    }

    if (timeout_ns == 0) {
        bucket.lock.unlockIrqRestore(irq);
        return errors.E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        ec.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        ec.futex_deadline_ns = 0;
    }

    var nodes: [1]WaitNode = .{.{
        .ec = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen()),
        .paddr = paddr,
        .priority = ec.priority,
    }};
    ec.futex_wait_nodes = &nodes;
    ec.futex_bucket_count = 1;
    ec.state = .futex_wait;
    bucket.pq.enqueue(&nodes[0]);

    if (ec.futex_deadline_ns != 0) {
        if (!addTimedWaiter(ec)) {
            // All timed waiter slots are full. Undo while still holding
            // the bucket lock to keep wake() (which spins on on_cpu) out
            // of a deadlock.
            _ = bucket.pq.remove(&nodes[0]);
            bucket.lock.unlockIrqRestore(irq);
            ec.state = .running;
            ec.futex_wait_nodes = null;
            ec.futex_bucket_count = 0;
            ec.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    bucket.lock.unlockIrqRestore(irq);

    arch.cpu.enableInterrupts();
    sched.yieldTo(null);

    const was_timeout: bool = ec.futex_deadline_ns == @as(u64, @bitCast(errors.E_TIMEOUT));
    ec.futex_deadline_ns = 0;
    return if (was_timeout) errors.E_TIMEOUT else 0;
}

/// `futex_wake` — wake up to `count` ECs blocked on `paddr`.
/// Spec §[futex].futex_wake. Wake order is priority-ordered (highest
/// first; FIFO within a priority).
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

        // self-alive: the node lives on the waiting EC's kernel stack
        // — the EC cannot have been freed while this node is still in
        // our bucket. The gen-locked SlabRef is for tooling uniformity
        // and the implicit liveness assertion.
        const ec = node.ec.lock(@src()) catch continue;
        node.ec.unlock();

        // wake_index is the offset of this node in the EC's
        // wait_nodes array — the index of the address in the original
        // multi-address wait that matched.
        const nodes = ec.futex_wait_nodes.?;
        const node_idx: usize = (@intFromPtr(node) - @intFromPtr(nodes)) / @sizeOf(WaitNode);
        ec.futex_wake_index = @intCast(node_idx);

        // Drop this EC's other nodes from every bucket they live in
        // (skipping the just-dequeued node and using the held lock
        // for any same-bucket sibling).
        removeNodesExcept(ec, node, wake_idx);

        while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        if (ec.futex_deadline_ns != 0) {
            ec.futex_deadline_ns = 0;
            removeTimedWaiter(ec);
        }
        ec.futex_bucket_count = 0;
        ec.futex_wait_nodes = null;
        ec.state = .ready;
        sched.enqueueOnCore(@intCast(pickCoreForEc(ec)), ec);
        woken += 1;
    }

    while (requeue.dequeue()) |n| bucket.pq.enqueue(n);

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}

/// Device IRQ entry point — wake every EC blocked on `paddr` (no count
/// cap) and return the set of cores that need an explicit wake IPI
/// follow-up. Called by `devices/device_region.propagateIrqAndWake`
/// after it bumps `field1.irq_count` for each domain-local handle copy.
/// Spec §[device_irq] step 3.
///
/// The IRQ caller batches IPIs across the entire device handle list,
/// so this function returns the mask instead of emitting IPIs inline.
pub fn wakeFromIrq(paddr: PAddr) WakeResult {
    var result: WakeResult = .{};
    const wake_idx = bucketIdx(paddr);
    const bucket = &buckets[wake_idx];

    const irq = bucket.lock.lockIrqSaveOrdered(@src(), FUTEX_BUCKET_GROUP);

    var requeue: WaitNodePriorityQueue = .{};

    while (true) {
        const node = bucket.pq.dequeue() orelse break;

        if (node.paddr.addr != paddr.addr) {
            requeue.enqueue(node);
            continue;
        }

        const ec = node.ec.lock(@src()) catch continue;
        node.ec.unlock();

        const nodes = ec.futex_wait_nodes.?;
        const node_idx: usize = (@intFromPtr(node) - @intFromPtr(nodes)) / @sizeOf(WaitNode);
        ec.futex_wake_index = @intCast(node_idx);

        removeNodesExcept(ec, node, wake_idx);

        while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        if (ec.futex_deadline_ns != 0) {
            ec.futex_deadline_ns = 0;
            removeTimedWaiter(ec);
        }
        ec.futex_bucket_count = 0;
        ec.futex_wait_nodes = null;
        ec.state = .ready;

        const target_core = pickCoreForEc(ec);
        sched.enqueueOnCore(@intCast(target_core), ec);
        result.idle_core_mask |= @as(u64, 1) << @intCast(target_core);
        result.woken += 1;
    }

    while (requeue.dequeue()) |n| bucket.pq.enqueue(n);

    bucket.lock.unlockIrqRestore(irq);
    return result;
}

/// `futex_wait_val` — block while every `(addrs[i], expected[i])`
/// satisfies `*addr == expected`. Spec §[futex].futex_wait_val.
///
/// Returns:
///   0..count-1 = index of the first mismatched address (mismatch, no block), or
///   0..count-1 = index of the address that was woken (after blocking),
///   E_TIMEOUT if timeout expired, E_NOMEM if no timed waiter slot.
pub fn waitVal(addrs: []const PAddr, expected: []const u64, count: usize, timeout_ns: u64, ec: *ExecutionContext) i64 {
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
        return errors.E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        ec.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        ec.futex_deadline_ns = 0;
    }

    var nodes: [MAX_FUTEX_ADDRS]WaitNode = undefined;
    const ec_ref = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .ec = ec_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = ec.priority,
        };
    }
    ec.futex_wait_nodes = &nodes;
    ec.futex_bucket_count = @intCast(count);
    ec.state = .futex_wait;

    for (0..count) |i| {
        buckets[bucketIdx(addrs[i])].pq.enqueue(&nodes[i]);
    }

    if (ec.futex_deadline_ns != 0) {
        if (!addTimedWaiter(ec)) {
            for (0..count) |i| {
                _ = buckets[bucketIdx(addrs[i])].pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            ec.state = .running;
            ec.futex_wait_nodes = null;
            ec.futex_bucket_count = 0;
            ec.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    arch.cpu.enableInterrupts();
    sched.yieldTo(null);

    const was_timeout: bool = ec.futex_deadline_ns == @as(u64, @bitCast(errors.E_TIMEOUT));
    ec.futex_deadline_ns = 0;
    if (was_timeout) return errors.E_TIMEOUT;
    return @intCast(ec.futex_wake_index);
}

/// `futex_wait_change` — block while every `(addrs[i], targets[i])`
/// satisfies `*addr != target`. Spec §[futex].futex_wait_change.
///
/// Returns:
///   0..count-1 = index of the first matched address (already at target, no block), or
///   0..count-1 = index of the address that was woken (after blocking),
///   E_TIMEOUT if timeout expired, E_NOMEM if no timed waiter slot.
pub fn waitChange(addrs: []const PAddr, targets: []const u64, count: usize, timeout_ns: u64, ec: *ExecutionContext) i64 {
    var sorted: [MAX_FUTEX_ADDRS]u8 = undefined;
    for (0..count) |i| sorted[i] = @intCast(i);
    sortByBucket(sorted[0..count], addrs);

    const lock_state = acquireBucketLocks(sorted[0..count], addrs);

    for (0..count) |i| {
        const vaddr = VAddr.fromPAddr(addrs[i], null);
        const value_ptr: *const u64 = @ptrFromInt(vaddr.addr);
        if (@atomicLoad(u64, value_ptr, .acquire) == targets[i]) {
            releaseBucketLocks(&lock_state);
            return @intCast(i);
        }
    }

    if (timeout_ns == 0) {
        releaseBucketLocks(&lock_state);
        return errors.E_TIMEOUT;
    }

    const max_timeout: u64 = @bitCast(@as(i64, -1));
    if (timeout_ns != max_timeout) {
        const now_ns = arch.time.getMonotonicClock().now();
        ec.futex_deadline_ns = now_ns +| timeout_ns;
    } else {
        ec.futex_deadline_ns = 0;
    }

    var nodes: [MAX_FUTEX_ADDRS]WaitNode = undefined;
    const ec_ref = SlabRef(ExecutionContext).init(ec, ec._gen_lock.currentGen());
    for (0..count) |i| {
        nodes[i] = .{
            .ec = ec_ref,
            .paddr = addrs[i],
            .next = null,
            .priority = ec.priority,
        };
    }
    ec.futex_wait_nodes = &nodes;
    ec.futex_bucket_count = @intCast(count);
    ec.state = .futex_wait;

    for (0..count) |i| {
        buckets[bucketIdx(addrs[i])].pq.enqueue(&nodes[i]);
    }

    if (ec.futex_deadline_ns != 0) {
        if (!addTimedWaiter(ec)) {
            for (0..count) |i| {
                _ = buckets[bucketIdx(addrs[i])].pq.remove(&nodes[i]);
            }
            releaseBucketLocks(&lock_state);
            ec.state = .running;
            ec.futex_wait_nodes = null;
            ec.futex_bucket_count = 0;
            ec.futex_deadline_ns = 0;
            return errors.E_NOMEM;
        }
    }

    releaseBucketLocks(&lock_state);

    arch.cpu.enableInterrupts();
    sched.yieldTo(null);

    const was_timeout: bool = ec.futex_deadline_ns == @as(u64, @bitCast(errors.E_TIMEOUT));
    ec.futex_deadline_ns = 0;
    if (was_timeout) return errors.E_TIMEOUT;
    return @intCast(ec.futex_wake_index);
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

/// Walk the timed-waiter list, wake each EC whose deadline has passed.
/// Called from the per-core timer tick.
pub fn expireTimedWaiters() void {
    const now_ns = arch.time.getMonotonicClock().now();

    // Phase 1: snapshot expired ECs + clear their slots, all under
    // timed_lock. Capturing the deadline lets phase 2 detect an EC
    // that was woken and re-registered as a fresh waiter between phases.
    //
    // The split is required by lock-order: wait() and wake() acquire
    // bucket.lock then timed_lock; if we held timed_lock here while
    // taking bucket.lock, that would form an AB-BA cycle.
    const Snapshot = struct { ec: *ExecutionContext, deadline: u64 };
    var expired: [MAX_TIMED_WAITERS]Snapshot = undefined;
    var expired_count: usize = 0;
    {
        const irq = timed_lock.lockIrqSave(@src());
        defer timed_lock.unlockIrqRestore(irq);
        for (&timed_waiters) |*slot| {
            const ec = slot.* orelse continue;
            if (ec.futex_deadline_ns == 0 or now_ns < ec.futex_deadline_ns) continue;
            expired[expired_count] = .{ .ec = ec, .deadline = ec.futex_deadline_ns };
            expired_count += 1;
            slot.* = null;
        }
    }

    // Phase 2: per-EC, take only bucket.lock (never timed_lock).
    for (expired[0..expired_count]) |entry| {
        const ec = entry.ec;
        // Re-check deadline. If wake() ran between phases, deadline is
        // now 0; if the EC was woken and made a new wait, deadline
        // differs. In both cases this snapshot is stale — skip.
        if (ec.futex_deadline_ns != entry.deadline) continue;

        const nodes = ec.futex_wait_nodes orelse continue;
        const count: usize = ec.futex_bucket_count;
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
            while (ec.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            ec.futex_deadline_ns = @bitCast(errors.E_TIMEOUT);
            ec.futex_bucket_count = 0;
            ec.futex_wait_nodes = null;
            ec.state = .ready;
            sched.enqueueOnCore(@intCast(pickCoreForEc(ec)), ec);
        }
    }
}
