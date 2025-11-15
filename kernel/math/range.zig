const std = @import("std");

pub const Range = struct {
    start: u64,
    end: u64,

    pub fn overlapsWith(
        self: *const Range,
        other: Range,
    ) bool {
        return self.start < other.end and self.end > other.start;
    }

    pub fn removeOverlap(
        self: *const Range,
        other: Range,
    ) Range {
        std.debug.assert(self.overlapsWith(other));
        std.debug.assert(!(other.start > self.start and other.end < self.end));

        if (other.start <= self.start and other.end < self.end) {
            return .{
                .start = other.end,
                .end = self.end,
            };
        }

        if (other.end >= self.end and other.start > self.start) {
            return .{
                .start = self.start,
                .end = other.start,
            };
        }

        unreachable;
    }
};
