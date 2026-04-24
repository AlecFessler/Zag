const std = @import("std");
const zag = @import("zag");

const SlabRef = zag.memory.allocators.secure_slab.SlabRef;

pub fn PriorityQueue(
    comptime T: type,
    comptime next_field: []const u8,
    comptime priority_field: []const u8,
    comptime num_levels: comptime_int,
) type {
    // The linked-list `next` field on `T` may be stored as either a
    // bare `?*T` or a `?SlabRef(T)` (for slab-backed T where all stored
    // pointers are fat references). The queue itself always operates
    // on `*T` — items sitting in a run queue / wait queue are live by
    // construction, since the queue owns them across yields — so we
    // just need two comptime adapters: one to turn the stored slot
    // into `?*T`, one to go back.
    const next_is_slabref = comptime blk: {
        const SentinelT = @FieldType(T, next_field);
        break :blk @typeInfo(SentinelT) == .optional and
            @typeInfo(@typeInfo(SentinelT).optional.child) == .@"struct";
    };

    const Helpers = struct {
        inline fn getNext(item: *T) ?*T {
            if (comptime next_is_slabref) {
                const maybe = @field(item, next_field);
                if (maybe) |r| {
                    // self-alive: the run/wait queue owns its nodes
                    // until dequeue/remove; the SlabRef cannot go
                    // stale while the node is linked.
                    return r.ptr;
                }
                return null;
            } else {
                return @field(item, next_field);
            }
        }

        inline fn setNext(item: *T, next: ?*T) void {
            if (comptime next_is_slabref) {
                if (next) |n| {
                    @field(item, next_field) = SlabRef(T).init(n, n._gen_lock.currentGen());
                } else {
                    @field(item, next_field) = null;
                }
            } else {
                @field(item, next_field) = next;
            }
        }

        inline fn isNull(item: *T) bool {
            return @field(item, next_field) == null;
        }
    };

    return struct {
        const Self = @This();

        const Level = struct {
            head: ?*T = null,
            tail: ?*T = null,
        };

        levels: [num_levels]Level = [_]Level{.{}} ** num_levels,

        pub fn enqueue(self: *Self, item: *T) void {
            std.debug.assert(Helpers.isNull(item));
            const idx = @intFromEnum(@field(item, priority_field));
            const level = &self.levels[idx];
            if (level.tail) |tail| {
                Helpers.setNext(tail, item);
            } else {
                level.head = item;
            }
            level.tail = item;
            Helpers.setNext(item, null);
        }

        pub fn dequeue(self: *Self) ?*T {
            var idx: usize = num_levels;
            while (idx > 0) {
                idx -= 1;
                const level = &self.levels[idx];
                const head = level.head orelse continue;
                level.head = Helpers.getNext(head);
                if (level.head == null) {
                    level.tail = null;
                }
                Helpers.setNext(head, null);
                return head;
            }
            return null;
        }

        pub fn remove(self: *Self, target: *T) bool {
            for (&self.levels) |*level| {
                var prev: ?*T = null;
                var cur = level.head;
                while (cur) |c| {
                    if (c == target) {
                        if (prev) |p| {
                            Helpers.setNext(p, Helpers.getNext(c));
                        } else {
                            level.head = Helpers.getNext(c);
                        }
                        if (level.tail == c) {
                            level.tail = prev;
                        }
                        Helpers.setNext(c, null);
                        return true;
                    }
                    prev = c;
                    cur = Helpers.getNext(c);
                }
            }
            return false;
        }

        /// Insert at the front of the item's priority level. Used when a
        /// dequeued waiter must be re-queued without losing its place (e.g.
        /// IPC cap-transfer failure rollback).
        pub fn enqueueFront(self: *Self, item: *T) void {
            std.debug.assert(Helpers.isNull(item));
            const idx = @intFromEnum(@field(item, priority_field));
            const level = &self.levels[idx];
            Helpers.setNext(item, level.head);
            level.head = item;
            if (level.tail == null) {
                level.tail = item;
            }
        }

        pub fn isEmpty(self: *const Self) bool {
            for (self.levels) |level| {
                if (level.head != null) return false;
            }
            return true;
        }
    };
}
