const std = @import("std");
const builtin = @import("builtin");

const DBG = builtin.mode == .Debug;
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

pub fn Intrusive2WayFreeList(comptime T: type) type {

    // intrusive 2way freelist expects writeable pointers
    std.debug.assert(@typeInfo(T) == .pointer);
    const ValType = std.meta.Child(T);

    return struct {
        const Self = @This();

        head: ?*FreeNode = null,

        const FreeNode = struct {
            /// dbg magic helps detect use after free in the assertion in pop()
            /// by ensuring that nodes are not written to while in the free list
            dbg_magic: if (DBG) u64 else void,
            next: ?*FreeNode = null,
            prev: ?*FreeNode = null,
        };

        comptime {
            std.debug.assert(@sizeOf(ValType) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(ValType) >= @alignOf(FreeNode));
        }

        pub fn push(self: *Self, addr: T) void {
            zeroItem(@ptrCast(addr));
            const node: *FreeNode = @alignCast(@ptrCast(addr));
            if (DBG) node.dbg_magic = DBG_MAGIC;
            if (self.head) |head| head.prev = node;
            node.next = self.head;
            node.prev = null;
            self.head = node;
        }

        pub fn pop(self: *Self) ?T {
            const addr = self.head orelse return null;
            if (DBG) std.debug.assert(addr.dbg_magic == DBG_MAGIC);
            self.head = addr.next;
            addr.prev = null;
            zeroItem(@ptrCast(addr));
            return @alignCast(@ptrCast(addr));
        }

        /// This function primarily exists for use by the buddy allocator
        /// when it computes the address of a buddy it knows is available.
        /// This enables O(1) popping of arbitrary elements from the freelist.
        /// Trying to pop a node that isn't in the list will blow up in debug
        /// builds, but is undefined behavior in release builds.
        pub fn pop_specific(self: *Self, addr: T) ?T {
            const node: *FreeNode = @alignCast(@ptrCast(addr));
            if (DBG) std.debug.assert(node.dbg_magic == DBG_MAGIC);

            const at_middle = node.prev != null and node.next != null;
            const at_start = node.prev == null and node.next != null;
            const at_end = node.prev != null and node.next == null;

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
            }

            zeroItem(@ptrCast(node));
            return @ptrCast(node);
        }

        fn zeroItem(item: [*]u8) void {
            const len = @sizeOf(ValType);
            @memset(item[0..len], 0);
        }
    };
}

const TestType = struct {
    pad1: u64,
    pad2: u64,
    pad3: usize,
};

test "pop returns null when empty" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    var freelist = FreeList{};
    try std.testing.expect(freelist.pop() == null);
}

test "push pop returns original" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    var freelist = FreeList{};
    var value = TestType{ .pad1 = 42, .pad2 = 0, .pad3 = 0 };

    freelist.push(&value);
    const result = freelist.pop().?;
    try std.testing.expect(result == &value);
    try std.testing.expect(freelist.pop() == null);
}

test "push push pop pop returns LIFO order with correct prev pointers" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    const FreeNode = FreeList.FreeNode;
    var freelist = FreeList{};
    var value1 = TestType{ .pad1 = 1, .pad2 = 0, .pad3 = 0 };
    var value2 = TestType{ .pad1 = 2, .pad2 = 0, .pad3 = 0 };

    freelist.push(&value1);
    freelist.push(&value2);

    const head: *FreeNode = @alignCast(@ptrCast(&value2));
    const next = head.next.?;

    try std.testing.expect(next.prev == head);

    const first = freelist.pop().?;
    const second = freelist.pop().?;
    try std.testing.expect(first == &value2);
    try std.testing.expect(second == &value1);
    try std.testing.expect(freelist.pop() == null);
}

test "works with larger types and correct prev linkage" {
    const LargeType = struct {
        data: [16]u8,
        pad: u64,
    };

    const FreeList = Intrusive2WayFreeList(*LargeType);
    const FreeNode = FreeList.FreeNode;
    var freelist = FreeList{};
    var item1 = LargeType{ .data = [_]u8{1} ** 16, .pad = 0 };
    var item2 = LargeType{ .data = [_]u8{2} ** 16, .pad = 0 };

    freelist.push(&item1);
    freelist.push(&item2);

    const head: *FreeNode = @alignCast(@ptrCast(&item2));
    const next = head.next.?;

    try std.testing.expect(next.prev == head);

    try std.testing.expect(freelist.pop() == &item2);
    try std.testing.expect(freelist.pop() == &item1);
    try std.testing.expect(freelist.pop() == null);
}

test "mixed push pop operations with prev validation" {
    const FreeList = Intrusive2WayFreeList(*TestType);
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

test "pop_specific works for start, middle, and end" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    const FreeNode = FreeList.FreeNode;
    var freelist = FreeList{};

    var a = TestType{ .pad1 = 1, .pad2 = 0, .pad3 = 0 };
    var b = TestType{ .pad1 = 2, .pad2 = 0, .pad3 = 0 };
    var c = TestType{ .pad1 = 3, .pad2 = 0, .pad3 = 0 };

    freelist.push(&a);
    freelist.push(&b);
    freelist.push(&c);

    try std.testing.expect(freelist.pop_specific(&b).? == &b);

    const node_c: *FreeNode = @alignCast(@ptrCast(&c));
    const node_a: *FreeNode = @alignCast(@ptrCast(&a));
    try std.testing.expect(node_c.next == node_a);
    try std.testing.expect(node_c.next.?.prev == node_c);

    try std.testing.expect(freelist.pop_specific(&a).? == &a);
    try std.testing.expect(node_c.next == null);

    try std.testing.expect(freelist.pop_specific(&c).? == &c);
}

test "push with debug canary validated in walk" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    var freelist = FreeList{};
    var values: [5]TestType = .{
        .{ .pad1 = 1, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 2, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 3, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 4, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 5, .pad2 = 0, .pad3 = 0 },
    };

    inline for (0..5) |i| {
        freelist.push(&values[i]);

        if (DBG) {
            var node = freelist.head;
            while (node) |n| {
                std.debug.assert(n.dbg_magic == DBG_MAGIC);
                node = n.next;
            }
        }
    }
}

test "interleaved stack and heap push/pop" {
    const FreeList = Intrusive2WayFreeList(*TestType);
    var freelist = FreeList{};

    var stack_items: [2]TestType = .{
        .{ .pad1 = 1, .pad2 = 0, .pad3 = 0 },
        .{ .pad1 = 2, .pad2 = 0, .pad3 = 0 },
    };

    const allocator = std.testing.allocator;
    const heap_item1 = try allocator.create(TestType);
    const heap_item2 = try allocator.create(TestType);
    heap_item1.* = .{ .pad1 = 3, .pad2 = 0, .pad3 = 0 };
    heap_item2.* = .{ .pad1 = 4, .pad2 = 0, .pad3 = 0 };

    freelist.push(&stack_items[0]);
    freelist.push(heap_item1);
    freelist.push(&stack_items[1]);
    freelist.push(heap_item2);

    try std.testing.expect(freelist.pop().? == heap_item2);
    try std.testing.expect(freelist.pop().? == &stack_items[1]);
    try std.testing.expect(freelist.pop().? == heap_item1);
    try std.testing.expect(freelist.pop().? == &stack_items[0]);
    try std.testing.expect(freelist.pop() == null);

    allocator.destroy(heap_item1);
    allocator.destroy(heap_item2);
}
