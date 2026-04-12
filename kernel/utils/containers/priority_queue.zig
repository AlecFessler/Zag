const std = @import("std");

pub fn PriorityQueue(
    comptime T: type,
    comptime next_field: []const u8,
    comptime priority_field: []const u8,
    comptime num_levels: comptime_int,
) type {
    return struct {
        const Self = @This();

        const Level = struct {
            head: ?*T = null,
            tail: ?*T = null,
        };

        levels: [num_levels]Level = [_]Level{.{}} ** num_levels,

        pub fn enqueue(self: *Self, item: *T) void {
            std.debug.assert(@field(item, next_field) == null);
            const idx = @intFromEnum(@field(item, priority_field));
            const level = &self.levels[idx];
            if (level.tail) |tail| {
                @field(tail, next_field) = item;
            } else {
                level.head = item;
            }
            level.tail = item;
            @field(item, next_field) = null;
        }

        pub fn dequeue(self: *Self) ?*T {
            var idx: usize = num_levels;
            while (idx > 0) {
                idx -= 1;
                const level = &self.levels[idx];
                const head = level.head orelse continue;
                level.head = @field(head, next_field);
                if (level.head == null) {
                    level.tail = null;
                }
                @field(head, next_field) = null;
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
                            @field(p, next_field) = @field(c, next_field);
                        } else {
                            level.head = @field(c, next_field);
                        }
                        if (level.tail == c) {
                            level.tail = prev;
                        }
                        @field(c, next_field) = null;
                        return true;
                    }
                    prev = c;
                    cur = @field(c, next_field);
                }
            }
            return false;
        }

        /// Insert at the front of the item's priority level. Used when a
        /// dequeued waiter must be re-queued without losing its place (e.g.
        /// IPC cap-transfer failure rollback).
        pub fn enqueueFront(self: *Self, item: *T) void {
            std.debug.assert(@field(item, next_field) == null);
            const idx = @intFromEnum(@field(item, priority_field));
            const level = &self.levels[idx];
            @field(item, next_field) = level.head;
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
