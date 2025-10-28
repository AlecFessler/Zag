//! Intrusive singly/doubly-linked freelist with optional base back-pointer.
//!
//! Design:
//! - T must be a **writable pointer type**; the pointed-to storage must
//!   be large/aligned enough to host `FreeNode`. We store the list node
//!   **inside** the freed object (intrusive).
//! - `using_popSpecific=true` enables O(1) removal of a known node via
//!   stored `prev` links (otherwise only LIFO `pop()` is available).
//! - `link_to_base=true` stores a back-pointer to the owning list in
//!   each node (`node.base = self`), useful for validation/auditing.
//!
//! Safety:
//! - In Debug builds, a `dbg_magic` tag is written while the node is on
//!   the freelist and asserted on removal to catch use-after-free.
//!
//! Complexity:
//! - `push`: O(1)
//! - `pop`: O(1)
//! - `popSpecific`: O(1) when enabled

const builtin = @import("builtin");
const std = @import("std");

const DBG = builtin.mode == .Debug;
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

/// Factory for an intrusive freelist over elements of pointer type `T`.
///
/// Compile-time parameters:
/// - `T`: pointer-to-element type (must be a pointer; element must fit `FreeNode`).
/// - `using_popSpecific`: when true, enables O(1) `popSpecific()` by keeping `prev`.
/// - `link_to_base`: when true, embeds a `base: *Self` back-pointer in nodes.
///
/// Returns:
/// - A concrete freelist `type` with `push`, `pop`, and optional `popSpecific`.
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
            /// dbg magic helps detect use after free in the assertion in pop()
            /// by ensuring that nodes are not written to while in the free list
            dbg_magic: if (DBG) u64 else void,
            next: ?*FreeNode = null,
            prev: if (using_popSpecific) ?*FreeNode else void = if (using_popSpecific) null,
            base: if (link_to_base) *Self else void,
        };

        comptime {
            // Element must be large/aligned enough to host the node inline.
            std.debug.assert(@sizeOf(ValType) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(ValType) >= @alignOf(FreeNode));
        }

        /// Push an element onto the freelist (LIFO).
        ///
        /// Arguments:
        /// - `self`: list instance.
        /// - `addr`: pointer to an element of type `T`.
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

        /// Pop the most recently pushed element.
        ///
        /// Arguments:
        /// - `self`: list instance.
        ///
        /// Returns:
        /// - `T` on success, or `null` if the list is empty.
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

        /// Remove a specific element from anywhere in the list in O(1).
        ///
        /// Requires:
        /// - `using_popSpecific=true` at type construction time.
        ///
        /// Arguments:
        /// - `self`: list instance.
        /// - `addr`: pointer to an element that is currently on `self`.
        ///
        /// Returns:
        /// - `T` on success, or `null` if the list was empty at head and fell back to `pop()`.
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

        /// Zero the inlined freelist node inside the element.
        ///
        /// Arguments:
        /// - `item`: byte pointer to the start of the element payload.
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
