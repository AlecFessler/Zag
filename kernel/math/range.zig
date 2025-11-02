//! Half-open `[start, end)` range utilities used throughout the kernel.
//!
//! Provides a minimal range type for representing memory and address intervals,
//! along with helpers for overlap checking and removing a single-sided overlap.
//!
//! # Directory
//!
//! ## Type Definitions
//! - Range – half-open interval with `start <= end`.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - Range.overlapsWith – test whether two ranges overlap.
//! - Range.removeOverlap – remove a single-side overlap from a range.

const std = @import("std");

/// Half-open range `[start, end)`. Invariant: `end >= start`.
pub const Range = struct {
    start: u64,
    end: u64,

    /// Summary:
    /// Returns whether two half-open ranges overlap by at least one byte.
    ///
    /// Arguments:
    /// - self: The base range.
    /// - other: The range tested for overlap.
    ///
    /// Returns:
    /// - `bool`: `true` if `self.start < other.end && self.end > other.start`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn overlapsWith(
        self: *const Range,
        other: Range,
    ) bool {
        return self.start < other.end and self.end > other.start;
    }

    /// Summary:
    /// Removes a single-sided overlap between `self` and `other`, returning the
    /// resulting clipped range. Used when `other` trims exactly one side of `self`.
    ///
    /// Arguments:
    /// - self: The source range to clip.
    /// - other: The overlapping range that clips one boundary of `self`.
    ///
    /// Returns:
    /// - `Range`: A new range representing `self` after removing the overlapped side.
    ///
    /// Errors:
    /// - None (overlap conditions must be satisfied before calling).
    ///
    /// Panics:
    /// - If the ranges do not overlap.
    /// - If `other` is strictly contained within `self` (i.e. clips both sides),
    ///   as this routine is only defined for single-boundary trimming.
    pub fn removeOverlap(
        self: *const Range,
        other: Range,
    ) Range {
        std.debug.assert(self.overlapsWith(other));
        std.debug.assert(!(other.start > self.start and other.end < self.end));

        // Clip the left edge.
        if (other.start <= self.start and other.end < self.end) {
            return .{
                .start = other.end,
                .end = self.end,
            };
        }

        // Clip the right edge.
        if (other.end >= self.end and other.start > self.start) {
            return .{
                .start = self.start,
                .end = other.start,
            };
        }

        unreachable;
    }
};
