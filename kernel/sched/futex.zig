const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const E_AGAIN: i64 = -9;
pub const E_TIMEOUT: i64 = -8;

const BUCKET_COUNT = 256;

const Bucket = struct {
    lock: SpinLock = .{},
    head: ?*Thread = null,
};

var buckets: [BUCKET_COUNT]Bucket = [_]Bucket{.{}} ** BUCKET_COUNT;

fn bucketIdx(paddr: PAddr) usize {
    return @intCast((paddr.addr >> 3) % BUCKET_COUNT);
}

fn pushWaiter(bucket: *Bucket, thread: *Thread) void {
    thread.next = bucket.head;
    bucket.head = thread;
}

fn popWaiter(bucket: *Bucket) ?*Thread {
    const thread = bucket.head orelse return null;
    bucket.head = thread.next;
    thread.next = null;
    return thread;
}

fn removeWaiter(bucket: *Bucket, target: *Thread) bool {
    var prev: ?*Thread = null;
    var current = bucket.head;
    while (current) |t| {
        if (t == target) {
            if (prev) |p| {
                p.next = t.next;
            } else {
                bucket.head = t.next;
            }
            t.next = null;
            return true;
        }
        prev = t;
        current = t.next;
    }
    return false;
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

    thread.state = .blocked;
    pushWaiter(bucket, thread);

    bucket.lock.unlockIrqRestore(irq);

    arch.enableInterrupts();
    sched.yield();
    return 0;
}

pub fn wake(paddr: PAddr, count: u32) u64 {
    const bucket = &buckets[bucketIdx(paddr)];
    var woken: u32 = 0;

    const irq = bucket.lock.lockIrqSave();

    while (woken < count) {
        const thread = popWaiter(bucket) orelse break;
        while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        thread.state = .ready;
        const target = if (thread.core_affinity) |mask|
            @as(u64, @ctz(mask))
        else
            arch.coreID();
        sched.enqueueOnCore(target, thread);
        woken += 1;
    }

    bucket.lock.unlockIrqRestore(irq);
    return woken;
}
