//! Half-open range utilities for address and memory interval logic.
//!
//! Defines a simple `[start, end)` range type with helpers for overlap testing
//! and removing a single-sided overlap (where `other` clips exactly one edge).

const std = @import("std");

/// Half-open range `[start, end)`. `end` must be >= `start`.
pub const Range = struct {
    start: u64,
    end: u64,

    /// Returns `true` if two half-open ranges overlap by at least one byte.
    ///
    /// Arguments:
    /// - `self`: left-hand range.
    /// - `other`: right-hand range.
    ///
    /// Returns:
    /// - `true` when `self.start < other.end && self.end > other.start`.
    pub fn overlapsWith(
        self: *const Range,
        other: Range,
    ) bool {
        return self.start < other.end and self.end > other.start;
    }

    /// Removes a single-sided overlap with `other` and returns the remaining slice.
    ///
    /// Preconditions:
    /// - The ranges must overlap: `self.overlapsWith(other) == true`.
    /// - `other` must not be fully contained inside `self` (it must clip either
    ///   the left or right edge, but not both).
    ///
    /// Arguments:
    /// - `self`: base range to clip.
    /// - `other`: overlapping range that trims one side of `self`.
    ///
    /// Returns:
    /// - A new `Range` equal to `self` with the overlapped edge removed.
    ///
    /// Panics:
    /// - Triggers an assertion if ranges do not overlap or if `other` is
    ///   strictly contained within `self`.
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
