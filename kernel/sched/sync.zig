const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const sched = zag.sched.scheduler;

const Thread = zag.sched.thread.Thread;

pub const SpinLock = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        std.debug.assert(self.state.load(.monotonic) == 1);
        self.state.store(0, .release);
    }

    pub fn lockIrqSave(self: *SpinLock) u64 {
        const state = arch.saveAndDisableInterrupts();
        self.lock();
        return state;
    }

    pub fn unlockIrqRestore(self: *SpinLock, state: u64) void {
        self.unlock();
        arch.restoreInterrupts(state);
    }
};

pub const WaitQueue = struct {
    lock: SpinLock = .{},
    head: ?*Thread = null,
    tail: ?*Thread = null,

    pub fn wait(self: *WaitQueue, held_lock: *SpinLock, irq_state: u64) void {
        const thread = sched.currentThread().?;

        self.lock.lock();
        thread.state = .blocked;
        self.enqueueThread(thread);
        self.lock.unlock();

        held_lock.unlockIrqRestore(irq_state);

        sched.yield();
    }

    pub fn wakeOne(self: *WaitQueue) ?*Thread {
        const irq_state = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq_state);
        const thread = self.dequeueThread() orelse return null;
        while (thread.on_cpu.load(.acquire)) {
            std.atomic.spinLoopHint();
        }
        thread.state = .ready;
        const target = thread.core_affinity orelse arch.coreID();
        sched.enqueueOnCore(target, thread);
        return thread;
    }

    pub fn wakeAll(self: *WaitQueue) u64 {
        const irq_state = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq_state);
        var count: u64 = 0;
        while (self.dequeueThread()) |thread| {
            while (thread.on_cpu.load(.acquire)) {
                std.atomic.spinLoopHint();
            }
            thread.state = .ready;
            const target = thread.core_affinity orelse arch.coreID();
            sched.enqueueOnCore(target, thread);
            count += 1;
        }
        return count;
    }

    fn enqueueThread(self: *WaitQueue, thread: *Thread) void {
        thread.next = null;
        if (self.tail) |t| {
            t.next = thread;
        } else {
            self.head = thread;
        }
        self.tail = thread;
    }

    fn dequeueThread(self: *WaitQueue) ?*Thread {
        const thread = self.head orelse return null;
        self.head = thread.next;
        if (self.head == null) self.tail = null;
        thread.next = null;
        return thread;
    }
};
