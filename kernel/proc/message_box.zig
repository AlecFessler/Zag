const std = @import("std");
const zag = @import("zag");

const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const ThreadPriorityQueue = zag.sched.thread.ThreadPriorityQueue;

/// A unified message box used for both IPC message passing and fault delivery.
///
/// The state machine is identical for both uses:
///   idle           — no receiver, no pending reply, no senders queued
///   receiving      — a thread is blocked on `recv` waiting for a sender
///   pending_reply  — a sender's message has been delivered (or dequeued)
///                    and the receiver owes the sender a reply
///
/// The queued unit is `*Thread` in both cases. For IPC, the queued thread
/// is the calling thread of `ipc_call` whose payload lives in its saved
/// `ctx.regs`. For faults, the queued thread is the faulted thread itself,
/// whose payload lives in `thread.fault_reason / fault_addr / fault_rip`
/// and `thread.ctx.regs` (the snapshot taken at exception entry). The
/// linkage uses the existing `thread.next` field — a thread is in at most
/// one of {run queue, IPC waiters, fault box queue} at a time, so the
/// pointer is never aliased.
///
/// MessageBox is intentionally payload-agnostic. It owns the state machine,
/// the queue, and the lock. Callers (sysIpcSend/Call/Recv/Reply,
/// faultBlock/sysFaultRecv/sysFaultReply) do payload extraction between
/// state transitions.
pub const MessageBox = struct {
    state: State = .idle,
    waiters: ThreadPriorityQueue = .{},
    /// Thread blocked on `recv`, valid iff `state == .receiving`.
    receiver: ?SlabRef(Thread) = null,
    /// Sender thread that owns the currently-pending message; valid iff
    /// `state == .pending_reply`. For IPC this is the caller of `ipc_call`
    /// (null if the message came from `ipc_send`, which has nothing to
    /// reply to). For faults this is always the faulted thread.
    pending_thread: ?SlabRef(Thread) = null,
    lock: SpinLock = .{},

    pub const State = enum(u8) { idle, receiving, pending_reply };

    /// Append `sender` to the wait queue. Caller must hold `self.lock`.
    /// Used when no receiver is currently blocked on `recv`.
    pub fn enqueueLocked(self: *MessageBox, sender: *Thread) void {
        self.waiters.enqueue(sender);
    }

    /// Pop the head of the wait queue, if any. Caller must hold `self.lock`.
    /// Does NOT touch state — caller decides whether to transition to
    /// `pending_reply` (normal recv path) or stay in current state (drain
    /// during cleanup).
    pub fn dequeueLocked(self: *MessageBox) ?*Thread {
        return self.waiters.dequeue();
    }

    /// Remove a specific thread from the wait queue if present. Returns
    /// true if removed. Caller must hold `self.lock`. Used when a queued
    /// caller dies before its message is delivered.
    pub fn removeLocked(self: *MessageBox, target: *Thread) bool {
        return self.waiters.remove(target);
    }

    /// Insert at the front of the thread's priority level in the wait
    /// queue. Used when a dequeued waiter must be put back without
    /// losing its place (e.g. IPC cap-transfer failure rollback).
    /// Caller must hold `self.lock`.
    pub fn enqueueFrontLocked(self: *MessageBox, sender: *Thread) void {
        self.waiters.enqueueFront(sender);
    }

    /// Remove all threads belonging to `proc` from the wait queue.
    /// Caller must hold `self.lock`.
    pub fn drainByProcessLocked(self: *MessageBox, proc: anytype) void {
        for (&self.waiters.levels) |*level| {
            var prev: ?*Thread = null;
            var cur = level.head;
            while (cur) |c| {
                // self-alive: a waiter is kept alive by the queue that
                // owns it; both `c.next` and `c.process` resolve to
                // live slots until we unlink.
                const next_ptr: ?*Thread = if (c.next) |r| r.ptr else null;
                if (c.process.ptr == proc) {
                    if (prev) |p| {
                        p.next = if (next_ptr) |np| SlabRef(Thread).init(np, np._gen_lock.currentGen()) else null;
                    } else {
                        level.head = next_ptr;
                    }
                    if (level.tail == c) {
                        level.tail = prev;
                    }
                    c.next = null;
                } else {
                    prev = c;
                }
                cur = next_ptr;
            }
        }
    }

    /// Transition to `receiving` state with `thread` as the blocked
    /// receiver. Caller must hold `self.lock` and must have already
    /// verified `state == .idle` and the wait queue is empty.
    pub fn beginReceivingLocked(self: *MessageBox, thread: *Thread) void {
        std.debug.assert(self.state == .idle);
        std.debug.assert(self.waiters.isEmpty());
        std.debug.assert(self.receiver == null);
        self.state = .receiving;
        self.receiver = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    }

    /// Transition out of `receiving` back to `idle`. Returns the previously
    /// blocked receiver as a `SlabRef(Thread)` — caller must `lock()` it
    /// before touching the thread (unless they only need identity compare).
    /// Caller must hold `self.lock` and must have already verified
    /// `state == .receiving`. Used when a sender takes the receiver's
    /// place via direct delivery.
    pub fn takeReceiverLocked(self: *MessageBox) SlabRef(Thread) {
        std.debug.assert(self.state == .receiving);
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .idle;
        return r;
    }

    /// Transition to `pending_reply` state with `sender` as the message
    /// owner (may be null for IPC send-with-no-caller). Caller must hold
    /// `self.lock` and must have already verified `state != .pending_reply`.
    pub fn beginPendingReplyLocked(self: *MessageBox, sender: ?*Thread) void {
        std.debug.assert(self.state != .pending_reply);
        self.state = .pending_reply;
        self.pending_thread = if (sender) |s|
            SlabRef(Thread).init(s, s._gen_lock.currentGen())
        else
            null;
    }

    /// Transition out of `pending_reply` back to `idle`. Returns the
    /// pending sender as a `SlabRef(Thread)` (if any) — caller must
    /// `lock()` it before touching the thread. Caller must hold
    /// `self.lock` and must have already verified `state == .pending_reply`.
    pub fn endPendingReplyLocked(self: *MessageBox) ?SlabRef(Thread) {
        std.debug.assert(self.state == .pending_reply);
        const t = self.pending_thread;
        self.pending_thread = null;
        self.state = .idle;
        return t;
    }

    /// True if the box currently owes a reply.
    pub fn isPendingReply(self: *const MessageBox) bool {
        return self.state == .pending_reply;
    }

    /// True if a thread is blocked on `recv`.
    pub fn isReceiving(self: *const MessageBox) bool {
        return self.state == .receiving;
    }
};
