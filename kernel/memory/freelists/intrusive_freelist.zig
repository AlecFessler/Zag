const std = @import("std");
const builtin = @import("builtin");

const fl = @import("freelist.zig");

const DBG = builtin.mode == .Debug;
const DBG_MAGIC = 0x0DEAD2A6DEAD2A60;

pub fn IntrusiveFreeList(comptime T: type) type {

    // intrusive freelist expects writeable pointers
    std.debug.assert(@typeInfo(T) == .pointer);
    const ValType = std.meta.Child(T);

    return struct {
        const Self = @This();
        const FreeList = fl.FreeList(T);

        next: ?*FreeNode = null,

        const FreeNode = struct {
            /// dbg magic helps detect use after free in the assertion in pop()
            /// by ensuring that nodes are not written to while in the free list
            dbg_magic: if (DBG) u64 else void,
            next: ?*FreeNode align(@alignOf(ValType)),
        };

        comptime {
            std.debug.assert(@sizeOf(ValType) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(ValType) == @alignOf(FreeNode));
        }

        pub fn freelist(self: *Self) FreeList {
            return .{
                .ptr = self,
                .vtable = &.{
                    .getNextFree = pop,
                    .setFree = push,
                    .isFree = isFree,
                },
            };
        }

        fn pop(ptr: *anyopaque) ?[*]u8 {
            var self: *Self = @alignCast(@ptrCast(ptr));
            const addr = self.next orelse return null;
            if (DBG) std.debug.assert(addr.dbg_magic == DBG_MAGIC);
            self.next = addr.next;
            zeroItem(@ptrCast(addr));
            return @ptrCast(addr);
        }

        fn push(ptr: *anyopaque, addr: [*]u8) void {
            var self: *Self = @alignCast(@ptrCast(ptr));
            zeroItem(@ptrCast(addr));
            const node: *FreeNode = @alignCast(@ptrCast(addr));
            if (DBG) node.dbg_magic = DBG_MAGIC;
            node.next = self.next;
            self.next = node;
        }

        fn isFree(ptr: *anyopaque, addr: [*]u8) bool {
            // this is not implemeneted because it's an O(n) operation to search
            // if you need to do this operation, consider the bitmap freelist
            _ = ptr;
            _ = addr;
            unreachable;
        }

        fn zeroItem(item: [*]u8) void {
            const len = @sizeOf(ValType);
            @memset(item[0..len], 0);
        }
    };
}

const TestType = struct { data: u64, pad: u64 };

test "pop returns null when empty" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    try std.testing.expect(free_list.getNextFree() == null);
}

test "push pop returns original" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    var value = TestType{ .data = 42, .pad = 0 };

    free_list.setFree(&value);
    const result = free_list.getNextFree().?;

    try std.testing.expect(result == &value);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "push push pop pop returns LIFO order" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    var value1 = TestType{ .data = 1, .pad = 0 };
    var value2 = TestType{ .data = 2, .pad = 0 };

    free_list.setFree(&value1);
    free_list.setFree(&value2);

    const first = free_list.getNextFree().?;
    const second = free_list.getNextFree().?;

    try std.testing.expect(first == &value2);
    try std.testing.expect(second == &value1);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "works with larger types" {
    const LargeType = struct {
        data: [16]u8,
        pad: u64,
    };

    var stack = IntrusiveFreeList(*LargeType){};
    var free_list = stack.freelist();

    var item1 = LargeType{ .data = [_]u8{1} ** 16, .pad = 0 };
    var item2 = LargeType{ .data = [_]u8{2} ** 16, .pad = 0 };

    free_list.setFree(&item1);
    free_list.setFree(&item2);

    try std.testing.expect(free_list.getNextFree() == &item2);
    try std.testing.expect(free_list.getNextFree() == &item1);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "mixed push pop operations" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    var values: [5]TestType = .{
        .{ .data = 10, .pad = 0 },
        .{ .data = 20, .pad = 0 },
        .{ .data = 30, .pad = 0 },
        .{ .data = 40, .pad = 0 },
        .{ .data = 50, .pad = 0 },
    };

    free_list.setFree(&values[0]);
    free_list.setFree(&values[1]);
    free_list.setFree(&values[2]);

    try std.testing.expect(free_list.getNextFree().? == &values[2]);
    try std.testing.expect(free_list.getNextFree().? == &values[1]);

    free_list.setFree(&values[3]);
    free_list.setFree(&values[4]);

    try std.testing.expect(free_list.getNextFree().? == &values[4]);
    try std.testing.expect(free_list.getNextFree().? == &values[3]);
    try std.testing.expect(free_list.getNextFree().? == &values[0]);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "push with debug canary validated in walk" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    var values: [5]TestType = .{
        .{ .data = 1, .pad = 0 },
        .{ .data = 2, .pad = 0 },
        .{ .data = 3, .pad = 0 },
        .{ .data = 4, .pad = 0 },
        .{ .data = 5, .pad = 0 },
    };

    inline for (0..5) |i| {
        free_list.setFree(&values[i]);

        if (@import("builtin").mode == .Debug) {
            var node = stack.next;
            while (node) |n| {
                std.debug.assert(n.dbg_magic == 0x0DEAD2A6DEAD2A60);
                node = n.next;
            }
        }
    }
}

test "interleaved stack and heap push/pop" {
    var stack = IntrusiveFreeList(*TestType){};
    var free_list = stack.freelist();

    var stack_items: [2]TestType = .{
        .{ .data = 1, .pad = 0 },
        .{ .data = 2, .pad = 0 },
    };

    const allocator = std.testing.allocator;
    const heap_item1 = try allocator.create(TestType);
    const heap_item2 = try allocator.create(TestType);
    heap_item1.* = .{ .data = 3, .pad = 0 };
    heap_item2.* = .{ .data = 4, .pad = 0 };

    free_list.setFree(&stack_items[0]);
    free_list.setFree(heap_item1);
    free_list.setFree(&stack_items[1]);
    free_list.setFree(heap_item2);

    try std.testing.expect(free_list.getNextFree() == heap_item2);
    try std.testing.expect(free_list.getNextFree() == &stack_items[1]);
    try std.testing.expect(free_list.getNextFree() == heap_item1);
    try std.testing.expect(free_list.getNextFree() == &stack_items[0]);
    try std.testing.expect(free_list.getNextFree() == null);

    allocator.destroy(heap_item1);
    allocator.destroy(heap_item2);
}
