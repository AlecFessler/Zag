const std = @import("std");
const zag = @import("zag");

const Priority = zag.sched.thread.Priority;
const Thread = zag.sched.thread.Thread;

const num_levels = std.meta.fields(Priority).len;

const Level = struct {
    head: ?*Thread = null,
    tail: ?*Thread = null,
};

pub const PriorityQueue = struct {
    levels: [num_levels]Level = [_]Level{.{}} ** num_levels,

    pub fn enqueue(self: *PriorityQueue, thread: *Thread) void {
        std.debug.assert(thread.next == null);
        const idx = @intFromEnum(thread.priority);
        const level = &self.levels[idx];
        if (level.tail) |tail| {
            tail.next = thread;
        } else {
            level.head = thread;
        }
        level.tail = thread;
        thread.next = null;
    }

    pub fn dequeue(self: *PriorityQueue) ?*Thread {
        var idx: usize = num_levels;
        while (idx > 0) {
            idx -= 1;
            const level = &self.levels[idx];
            const head = level.head orelse continue;
            level.head = head.next;
            if (level.head == null) {
                level.tail = null;
            }
            head.next = null;
            return head;
        }
        return null;
    }

    pub fn remove(self: *PriorityQueue, target: *Thread) bool {
        for (&self.levels) |*level| {
            var prev: ?*Thread = null;
            var cur = level.head;
            while (cur) |c| {
                if (c == target) {
                    if (prev) |p| {
                        p.next = c.next;
                    } else {
                        level.head = c.next;
                    }
                    if (level.tail == c) {
                        level.tail = prev;
                    }
                    c.next = null;
                    return true;
                }
                prev = c;
                cur = c.next;
            }
        }
        return false;
    }

    pub fn peekHighestStealable(self: *const PriorityQueue, core_id: u6) ?*Thread {
        const core_bit = @as(u64, 1) << core_id;
        var idx: usize = num_levels;
        while (idx > 0) {
            idx -= 1;
            if (idx == @intFromEnum(Priority.pinned)) continue;
            var cur = self.levels[idx].head;
            while (cur) |c| {
                if (c.core_affinity) |aff| {
                    if (aff & core_bit != 0) return c;
                } else {
                    return c;
                }
                cur = c.next;
            }
        }
        return null;
    }

    /// Insert at the front of the thread's priority level. Used when a
    /// dequeued waiter must be re-queued without losing its place (e.g.
    /// IPC cap-transfer failure rollback).
    pub fn enqueueFront(self: *PriorityQueue, thread: *Thread) void {
        std.debug.assert(thread.next == null);
        const idx = @intFromEnum(thread.priority);
        const level = &self.levels[idx];
        thread.next = level.head;
        level.head = thread;
        if (level.tail == null) {
            level.tail = thread;
        }
    }

    /// Remove all threads belonging to `proc` from the queue.
    /// Returns the number of threads removed.
    pub fn removeByProcess(self: *PriorityQueue, proc: anytype) u32 {
        var count: u32 = 0;
        for (&self.levels) |*level| {
            var prev: ?*Thread = null;
            var cur = level.head;
            while (cur) |c| {
                const next = c.next;
                if (c.process == proc) {
                    if (prev) |p| {
                        p.next = next;
                    } else {
                        level.head = next;
                    }
                    if (level.tail == c) {
                        level.tail = prev;
                    }
                    c.next = null;
                    count += 1;
                } else {
                    prev = c;
                }
                cur = next;
            }
        }
        return count;
    }

    pub fn isEmpty(self: *const PriorityQueue) bool {
        for (self.levels) |level| {
            if (level.head != null) return false;
        }
        return true;
    }
};
