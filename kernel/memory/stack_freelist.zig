//! Stack-based freelist for fixed-capacity slices.
//!
//! Simple LIFO pool backed by a caller-provided slice of `T`. Useful on very
//! hot paths where you want predictable O(1) push/pop with no allocation.
//!
//! Notes:
//! - Capacity is fixed by the provided slice length.
//! - `top` starts at `-1` (empty), grows toward `stack.len - 1`.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `StackFreeList(T).Self` — concrete freelist type for element type `T`.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `StackFreeList` — factory returning a freelist type specialized for `T`.
//! - `StackFreeList(T).init` — construct an empty freelist over a backing slice.
//! - `StackFreeList(T).pop` — pop the most recently pushed item (LIFO).
//! - `StackFreeList(T).push` — push an item if capacity remains.

const std = @import("std");

/// Summary:
/// Factory that returns a freelist type specialized for `T`.
///
/// Arguments:
/// - `T`: Element type stored in the freelist.
///
/// Returns:
/// - `type`: A struct type `StackFreeList(T).Self` implementing LIFO push/pop over a fixed slice.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn StackFreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Backing storage and current top index (`-1` when empty).
        stack: []T,
        top: isize,

        /// Function: `StackFreeList(T).init`
        ///
        /// Summary:
        /// Initialize the freelist over `slice`, starting empty (`top = -1`).
        ///
        /// Arguments:
        /// - `slice`: Backing storage; its length fixes maximum capacity.
        ///
        /// Returns:
        /// - `Self`: Newly initialized freelist.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn init(slice: []T) Self {
            return .{
                .stack = slice,
                .top = -1,
            };
        }

        /// Function: `StackFreeList(T).pop`
        ///
        /// Summary:
        /// Pop the most-recently pushed item (LIFO) if present.
        ///
        /// Arguments:
        /// - `self`: Freelist instance.
        ///
        /// Returns:
        /// - `?T`: Popped value on success, or `null` if empty.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn pop(self: *Self) ?T {
            std.debug.assert(self.top < self.stack.len);
            if (self.top == -1) return null;

            const addr = self.stack[@intCast(self.top)];
            self.top -= 1;

            return addr;
        }

        /// Function: `StackFreeList(T).push`
        ///
        /// Summary:
        /// Push an item onto the stack if capacity remains.
        ///
        /// Arguments:
        /// - `self`: Freelist instance.
        /// - `addr`: Value to push.
        ///
        /// Returns:
        /// - `void`.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        ///
        /// Notes:
        /// - When at capacity, the top index is not advanced.
        pub fn push(self: *Self, addr: T) void {
            std.debug.assert(self.top >= -1);
            if (self.top + 1 < self.stack.len) {
                self.top += 1;
            }

            self.stack[@intCast(self.top)] = addr;
        }
    };
}

test "pop returns null when empty" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);

    try std.testing.expect(freelist.pop() == null);
}

test "push pop returns original" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);

    const value = 42;

    freelist.push(value);
    const result = freelist.pop().?;

    try std.testing.expect(result == value);
    try std.testing.expect(freelist.pop() == null);
}

test "push push pop pop returns LIFO order" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 2);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);

    const value1 = 1;
    const value2 = 2;

    freelist.push(value1);
    freelist.push(value2);

    const first = freelist.pop().?;
    const second = freelist.pop().?;

    try std.testing.expect(first == value2);
    try std.testing.expect(second == value1);
    try std.testing.expect(freelist.pop() == null);
}

test "mixed push pop operations" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 5);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);

    const values: [5]usize = .{ 10, 20, 30, 40, 50 };

    freelist.push(values[0]);
    freelist.push(values[1]);
    freelist.push(values[2]);

    try std.testing.expect(freelist.pop().? == values[2]);
    try std.testing.expect(freelist.pop().? == values[1]);

    freelist.push(values[3]);
    freelist.push(values[4]);

    try std.testing.expect(freelist.pop().? == values[4]);
    try std.testing.expect(freelist.pop().? == values[3]);
    try std.testing.expect(freelist.pop().? == values[0]);
    try std.testing.expect(freelist.pop() == null);
}
