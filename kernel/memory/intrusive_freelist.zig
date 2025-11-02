//! Intrusive singly/doubly-linked freelist with optional base back-pointer.
//!
//! Provides an intrusive LIFO freelist where the list node lives **inside**
//! each freed object. Configurable at compile time to support O(1) removal of
//! known nodes (`popSpecific`) via a maintained `prev` link, and/or to embed a
//! back-pointer to the owning list (`base`) for validation/auditing.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `IntrusiveFreeList(T, using_popSpecific, link_to_base)` — factory returning
//!   a concrete freelist `type` with `head` field, nested `FreeNode`, and methods.
//!
//! ## Constants
//! - `DBG` — compile-mode flag enabling debug assertions and tags.
//! - `DBG_MAGIC` — magic value written into nodes while they reside on the list.
//!
//! ## Variables
//! - None at module scope. The returned `type` contains a `head` field.
//!
//! ## Functions
//! - `IntrusiveFreeList` — factory that builds a freelist `type` specialized to `T`.

const builtin = @import("builtin");
const std = @import("std");

/// Compile-mode flag enabling debug-time assertions and node tagging.
const DBG = builtin.mode == .Debug;

/// Magic value written into `dbg_magic` while a node resides on the freelist.
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

/// Summary:
/// Factory for an intrusive freelist over elements of pointer type `T`.
///
/// Arguments:
/// - `T`: Pointer-to-element type; the element storage must fit/align for `FreeNode`.
/// - `using_popSpecific`: When `true`, enables O(1) `popSpecific()` by tracking `prev`.
/// - `link_to_base`: When `true`, embeds a `base: *Self` back-pointer in each node.
///
/// Returns:
/// - A concrete freelist `type` exposing:
///   - field `head: ?*FreeNode`
///   - nested `FreeNode` node layout
///   - methods `push`, `pop`, `popSpecific` (when enabled), and private `zeroItem`.
///
/// Errors:
/// - None at runtime. May emit `@compileError` if misused at compile time (e.g., calling
///   `popSpecific` without `using_popSpecific=true`).
///
/// Panics:
/// - None.
pub fn IntrusiveFreeList(
    comptime T: type,
    comptime using_popSpecific: bool,
    comptime link_to_base: bool,
) type {

    // intrusive freelist expects writeable pointers
    std.debug.assert(@typeInfo(T) == .pointer);
    const ValType = std.meta.Child(T);

    return struct {
        const Self = @This();

        /// Head of the LIFO freelist (null when empty).
        head: ?*FreeNode = null,

        /// Node layout embedded into each freed element.
        ///
        /// Fields:
        /// - `dbg_magic` (Debug only): tag set on insertion, asserted on removal.
        /// - `next`: forward link.
        /// - `prev` (when `using_popSpecific`): back link for O(1) removal.
        /// - `base` (when `link_to_base`): owning list pointer.
        pub const FreeNode = struct {
            /// Debug tag set while the node is on the list to catch UAF in Debug builds.
            dbg_magic: if (DBG) u64 else void,
            /// Forward link to the next node in the freelist.
            next: ?*FreeNode = null,
            /// Back link for O(1) removal; only present when `using_popSpecific=true`.
            prev: if (using_popSpecific) ?*FreeNode else void = if (using_popSpecific) null,
            /// Back-pointer to the owning list; only present when `link_to_base=true`.
            base: if (link_to_base) *Self else void,
        };

        comptime {
            // Element must be large/aligned enough to host the node inline.
            std.debug.assert(@sizeOf(ValType) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(ValType) >= @alignOf(FreeNode));
        }

        /// Summary:
        /// Push an element onto the freelist (LIFO).
        ///
        /// Arguments:
        /// - `self`: List instance.
        /// - `addr`: Pointer to an element of type `T`.
        ///
        /// Returns:
        /// - None (void).
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn push(self: *Self, addr: T) void {
            zeroItem(@ptrCast(addr));
            const node: *FreeNode = @alignCast(@ptrCast(addr));

            if (DBG) node.dbg_magic = DBG_MAGIC;
            if (using_popSpecific) {
                if (self.head) |head| {
                    head.prev = node;
                }
                node.prev = null;
            }
            if (link_to_base) {
                node.base = self;
            }

            node.next = self.head;
            self.head = node;
        }

        /// Summary:
        /// Pop the most recently pushed element.
        ///
        /// Arguments:
        /// - `self`: List instance.
        ///
        /// Returns:
        /// - `?T` — the popped element pointer on success or `null` if empty.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - Panics in Debug builds if `dbg_magic` is corrupted (use-after-free indicator).
        pub fn pop(self: *Self) ?T {
            const addr = self.head orelse {
                return null;
            };

            if (DBG) std.debug.assert(addr.dbg_magic == DBG_MAGIC);

            self.head = addr.next;

            if (using_popSpecific) {
                if (self.head) |h| {
                    h.prev = null;
                }
            }

            zeroItem(@ptrCast(addr));
            return @alignCast(@ptrCast(addr));
        }

        /// Summary:
        /// Remove a specific element from anywhere in the list in O(1).
        ///
        /// Requires:
        /// - Constructed with `using_popSpecific=true`.
        ///
        /// Arguments:
        /// - `self`: List instance.
        /// - `addr`: Pointer to an element that is currently on `self`.
        ///
        /// Returns:
        /// - `?T` — the removed element pointer on success, or if the element was
        ///   at the head this may delegate to `pop()` and return that result; `null`
        ///   only if the list was empty at head and fell back to `pop()`.
        ///
        /// Errors:
        /// - None at runtime. If `using_popSpecific=false`, emits a compile-time error.
        ///
        /// Panics:
        /// - Panics in Debug builds if `dbg_magic` is corrupted (use-after-free indicator).
        pub fn popSpecific(self: *Self, addr: T) ?T {
            if (!using_popSpecific) @compileError("must set using_popSpecific flag on the IntrusiveFreelist type to call popSpecific()");

            const node: *FreeNode = @alignCast(@ptrCast(addr));
            if (link_to_base) {
                _ = node.base;
            }

            if (DBG) std.debug.assert(node.dbg_magic == DBG_MAGIC);

            const at_middle = node.prev != null and node.next != null;
            const at_start = node.prev == null and node.next != null;
            const at_end = node.prev != null and node.next == null;
            const only_one = node.prev == null and node.next == null;

            if (at_middle) {
                const prev = node.prev.?;
                const next = node.next.?;
                prev.next = next;
                next.prev = prev;
            } else if (at_start) {
                return self.pop();
            } else if (at_end) {
                const prev = node.prev.?;
                prev.next = null;
            } else if (only_one) {
                std.debug.assert(self.head == node);
                self.head = null;
            }

            zeroItem(@ptrCast(node));
            return @alignCast(@ptrCast(node));
        }

        /// Summary:
        /// Zero the inlined freelist node inside the element payload.
        ///
        /// Arguments:
        /// - `item`: Byte pointer to the start of the element payload.
        ///
        /// Returns:
        /// - None (void).
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        fn zeroItem(item: [*]u8) void {
            const len = @sizeOf(FreeNode);
            @memset(item[0..len], 0);
        }
    };
}

const TestType = struct {
    pad1: usize,
    pad2: usize,
    pad3: usize,
};

test "mixed push pop operations with prev validation" {
    const using_popSpecific = false;
    const link_to_base = false;
    const FreeList = IntrusiveFreeList(
        *TestType,
        using_popSpecific,
        link_to_base,
    );
    var freelist = FreeList{};
    var values: [5]TestType = .{
        .{ .pad1 = 10, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 20, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 30, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 40, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 50, .pad2 = 0, .pad3 = 0 },
    };

    freelist.push(&values[0]);
    freelist.push(&values[1]);
    freelist.push(&values[2]);

    try std.testing.expect(freelist.pop().? == &values[2]);
    try std.testing.expect(freelist.pop().? == &values[1]);

    freelist.push(&values[3]);
    freelist.push(&values[4]);

    try std.testing.expect(freelist.pop().? == &values[4]);
    try std.testing.expect(freelist.pop().? == &values[3]);
    try std.testing.expect(freelist.pop().? == &values[0]);
    try std.testing.expect(freelist.pop() == null);
}

test "popSpecific() works for start, middle, and end" {
    const using_popSpecific = true;
    const link_to_base = false;
    const FreeList = IntrusiveFreeList(
        *TestType,
        using_popSpecific,
        link_to_base,
    );
    const FreeNode = FreeList.FreeNode;
    var freelist = FreeList{};

    var a = TestType{ .pad1 = 1, .pad2 = 0, .pad3 = 0 };
    var b = TestType{ .pad1 = 2, .pad2 = 0, .pad3 = 0 };
    var c = TestType{ .pad1 = 3, .pad2 = 0, .pad3 = 0 };

    freelist.push(&a);
    freelist.push(&b);
    freelist.push(&c);

    try std.testing.expect(freelist.popSpecific(&b).? == &b);

    const node_c: *FreeNode = @alignCast(@ptrCast(&c));
    const node_a: *FreeNode = @alignCast(@ptrCast(&a));
    try std.testing.expect(node_c.next == node_a);
    try std.testing.expect(node_c.next.?.prev == node_c);

    try std.testing.expect(freelist.popSpecific(&a).? == &a);
    try std.testing.expect(node_c.next == null);

    try std.testing.expect(freelist.popSpecific(&c).? == &c);
}
