const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const futex_mod = zag.proc.futex;
const sched = zag.sched.scheduler;

const ThreadPriorityQueue = zag.sched.thread.ThreadPriorityQueue;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;

const E_TIMEOUT: i64 = -8;
const E_AGAIN: i64 = -9;
const E_NOENT: i64 = -10;

/// Per-process IRQ notification box.
/// Accumulates device interrupt notifications via atomic OR on the `word`
/// field. Threads waiting via `notify_wait` block on the `waiters` queue
/// and are woken when `signal` fires.
///
/// Spec §2.18; systems.md §irq-delivery.
pub const NotificationBox = struct {
    word: u64 = 0,
    waiters: ThreadPriorityQueue = .{},
    lock: SpinLock = .{},

    /// Called from the IRQ handler path (interrupts disabled).
    /// Atomically ORs the badge bit into the notification word,
    /// then drains all waiters and wakes them.
    pub fn signal(self: *NotificationBox, badge_bit: u6) void {
        _ = @atomicRmw(u64, &self.word, .Or, @as(u64, 1) << badge_bit, .monotonic);

        self.lock.lock();
        while (self.waiters.dequeue()) |thread| {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            thread.state = .ready;
            const target_core = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.smp.coreID();
            sched.enqueueOnCore(target_core, thread);
        }
        self.lock.unlock();
    }

    /// Called from the `notify_wait` syscall handler.
    /// Returns the notification bitmask (positive i64) on success,
    /// E_AGAIN for non-blocking with no notifications,
    /// E_TIMEOUT if the timeout expires.
    pub fn wait(self: *NotificationBox, thread: *Thread, timeout_ns: u64) i64 {
        const irq = self.lock.lockIrqSave();

        // Fast path: word is already non-zero.
        const w = @atomicLoad(u64, &self.word, .monotonic);
        if (w != 0) {
            @atomicStore(u64, &self.word, 0, .monotonic);
            self.lock.unlockIrqRestore(irq);
            return @bitCast(w);
        }

        // Non-blocking: return E_AGAIN.
        if (timeout_ns == 0) {
            self.lock.unlockIrqRestore(irq);
            return E_AGAIN;
        }

        // Block the thread.
        thread.state = .blocked;

        // Set up timeout if finite.
        if (timeout_ns != std.math.maxInt(u64)) {
            const now_ns = arch.time.getMonotonicClock().now();
            thread.futex_deadline_ns = now_ns + timeout_ns;
            thread.notification_waiter = true;
            // Use the futex timed-waiter infrastructure.
            if (!futex_mod.addTimedWaiterPublic(thread)) {
                // No timed waiter slots available; wake immediately with timeout.
                thread.state = .ready;
                thread.notification_waiter = false;
                self.lock.unlockIrqRestore(irq);
                return E_TIMEOUT;
            }
        }

        self.waiters.enqueue(thread);
        self.lock.unlockIrqRestore(irq);

        // Yield to scheduler.
        arch.interrupts.enableInterrupts();
        sched.yield();

        // On wake: check if we were woken by cleanup (E_NOENT sentinel),
        // timeout, or signal.
        thread.notification_waiter = false;
        const deadline = thread.futex_deadline_ns;
        const noent_sentinel: u64 = @bitCast(E_NOENT);
        if (deadline == noent_sentinel) {
            thread.futex_deadline_ns = 0;
            return E_NOENT;
        }
        if (deadline != 0) {
            thread.futex_deadline_ns = 0;
            futex_mod.removeTimedWaiterPublic(thread);
        }

        // Re-read and clear the notification word.
        const irq2 = self.lock.lockIrqSave();
        const w2 = @atomicLoad(u64, &self.word, .monotonic);
        if (w2 != 0) {
            @atomicStore(u64, &self.word, 0, .monotonic);
            self.lock.unlockIrqRestore(irq2);
            return @bitCast(w2);
        }
        self.lock.unlockIrqRestore(irq2);

        // If word is still zero, we were woken by timeout.
        return E_TIMEOUT;
    }

    /// Called from cleanupPhase1 when a process dies.
    /// Drains all waiters, waking each with E_NOENT.
    pub fn cleanupOnDeath(self: *NotificationBox) void {
        const irq = self.lock.lockIrqSave();
        while (self.waiters.dequeue()) |thread| {
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            // Store E_NOENT in the thread's deadline field so the waker
            // can distinguish timeout from cleanup. The notification wait
            // path checks the word; if zero after wake, it returns E_TIMEOUT.
            // For cleanup, we want E_NOENT, so we set the word to a sentinel.
            thread.futex_deadline_ns = @bitCast(E_NOENT);
            thread.state = .ready;
            const target_core = if (thread.core_affinity) |mask|
                @as(u64, @ctz(mask))
            else
                arch.smp.coreID();
            sched.enqueueOnCore(target_core, thread);
        }
        @atomicStore(u64, &self.word, 0, .monotonic);
        self.lock.unlockIrqRestore(irq);
    }
};
