const std = @import("std");
const builtin = @import("builtin");

const DBG = builtin.mode == .Debug;
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

pub fn StackFreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        next: ?*FreeNode = null,

        const FreeNode = struct {
            /// dbg magic helps detect use after free in the assertion in pop()
            /// by ensuring that nodes are not written to while in the free list
            dbg_magic: if (DBG) u64 else void,
            next: ?*FreeNode align(@alignOf(T)),
        };

        comptime {
            std.debug.assert(@sizeOf(T) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(T) == @alignOf(FreeNode));
            if (!DBG) std.debug.assert(@sizeOf(FreeNode) == @sizeOf(?*FreeNode));
        }

        pub fn push(self: *Self, item: *T) void {
            zeroItem(@ptrCast(item));
            const node: *FreeNode = @alignCast(@ptrCast(item));
            if (DBG) node.dbg_magic = DBG_MAGIC;
            node.next = self.next;
            self.next = node;
        }

        pub fn pop(self: *Self) ?*T {
            const item = self.next orelse return null;
            if (DBG) std.debug.assert(item.dbg_magic == DBG_MAGIC);
            self.next = item.next;
            zeroItem(@ptrCast(item));
            return @ptrCast(item);
        }

        fn zeroItem(item: *T) void {
            const raw: [*]u8 = @ptrCast(item);
            const len = @sizeOf(T);
            @memset(raw[0..len], 0);
        }
    };
}

const TestType = struct { data: u64, pad: u64 };

test "pop returns null when empty" {
    var freelist = StackFreeList(TestType){};
    try std.testing.expect(freelist.pop() == null);
}

test "push pop returns original" {
    var freelist = StackFreeList(TestType){};
    var value = TestType{ .data = 42, .pad = 0 };

    freelist.push(&value);
    const result = freelist.pop();

    try std.testing.expect(result == &value);
    try std.testing.expect(freelist.pop() == null);
}

test "push push pop pop returns LIFO order" {
    var freelist = StackFreeList(TestType){};
    var value1 = TestType{ .data = 1, .pad = 0 };
    var value2 = TestType{ .data = 2, .pad = 0 };

    freelist.push(&value1);
    freelist.push(&value2);

    const first = freelist.pop();
    const second = freelist.pop();

    try std.testing.expect(first == &value2);
    try std.testing.expect(second == &value1);
    try std.testing.expect(freelist.pop() == null);
}

test "works with larger types" {
    const LargeType = struct {
        data: [16]u8,
        pad: u64,
    };

    var freelist = StackFreeList(LargeType){};
    var item1 = LargeType{ .data = [_]u8{1} ** 16, .pad = 0 };
    var item2 = LargeType{ .data = [_]u8{2} ** 16, .pad = 0 };

    freelist.push(&item1);
    freelist.push(&item2);

    try std.testing.expect(freelist.pop() == &item2);
    try std.testing.expect(freelist.pop() == &item1);
    try std.testing.expect(freelist.pop() == null);
}

test "mixed push pop operations" {
    var freelist = StackFreeList(TestType){};
    var values: [5]TestType = .{
        .{ .data = 10, .pad = 0 },
        .{ .data = 20, .pad = 0 },
        .{ .data = 30, .pad = 0 },
        .{ .data = 40, .pad = 0 },
        .{ .data = 50, .pad = 0 },
    };

    freelist.push(&values[0]);
    freelist.push(&values[1]);
    freelist.push(&values[2]);

    try std.testing.expect(freelist.pop() == &values[2]);
    try std.testing.expect(freelist.pop() == &values[1]);

    freelist.push(&values[3]);
    freelist.push(&values[4]);

    try std.testing.expect(freelist.pop() == &values[4]);
    try std.testing.expect(freelist.pop() == &values[3]);
    try std.testing.expect(freelist.pop() == &values[0]);
    try std.testing.expect(freelist.pop() == null);
}

test "push with debug canary validated in walk" {
    var freelist = StackFreeList(TestType){};
    var values: [5]TestType = .{
        .{ .data = 1, .pad = 0 },
        .{ .data = 2, .pad = 0 },
        .{ .data = 3, .pad = 0 },
        .{ .data = 4, .pad = 0 },
        .{ .data = 5, .pad = 0 },
    };

    inline for (0..5) |i| {
        freelist.push(&values[i]);

        if (builtin.mode == .Debug) {
            var node = freelist.next;
            while (node) |n| {
                std.debug.assert(n.dbg_magic == DBG_MAGIC);
                node = n.next;
            }
        }
    }
}

test "interleaved stack and heap push/pop" {
    var freelist = StackFreeList(TestType){};
    var stack_items: [2]TestType = .{
        .{ .data = 1, .pad = 0 },
        .{ .data = 2, .pad = 0 },
    };

    const allocator = std.testing.allocator;
    const heap_item1 = try allocator.create(TestType);
    const heap_item2 = try allocator.create(TestType);
    heap_item1.* = .{ .data = 3, .pad = 0 };
    heap_item2.* = .{ .data = 4, .pad = 0 };

    freelist.push(&stack_items[0]);
    freelist.push(heap_item1);
    freelist.push(&stack_items[1]);
    freelist.push(heap_item2);

    try std.testing.expect(freelist.pop() == heap_item2);
    try std.testing.expect(freelist.pop() == &stack_items[1]);
    try std.testing.expect(freelist.pop() == heap_item1);
    try std.testing.expect(freelist.pop() == &stack_items[0]);
    try std.testing.expect(freelist.pop() == null);

    allocator.destroy(heap_item1);
    allocator.destroy(heap_item2);
}
