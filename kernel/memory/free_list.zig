const std = @import("std");

pub fn FreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        next: ?*FreeNode = null,

        const FreeNode = struct {
            next: ?*FreeNode align(@alignOf(T)),
        };

        comptime {
            std.debug.assert(@sizeOf(T) >= @sizeOf(FreeNode));
            std.debug.assert(@alignOf(T) == @alignOf(FreeNode));
        }

        pub fn push(self: *Self, item: *T) void {
            const node: *FreeNode = @alignCast(@ptrCast(item));
            node.next = self.next;
            self.next = node;
        }

        pub fn pop(self: *Self) ?*T {
            const next = self.next orelse return null;
            self.next = next.next;
            return @ptrCast(next);
        }
    };
}

test "pop returns null when empty" {
    var freelist = FreeList(usize){};
    try std.testing.expect(freelist.pop() == null);
}

test "push pop returns original" {
    var freelist = FreeList(usize){};
    var value: usize = 42;

    freelist.push(&value);
    const result = freelist.pop();

    try std.testing.expect(result == &value);
    try std.testing.expect(freelist.pop() == null);
}

test "push push pop pop returns LIFO order" {
    var freelist = FreeList(usize){};
    var value1: usize = 1;
    var value2: usize = 2;

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
    };

    var freelist = FreeList(LargeType){};
    var item1 = LargeType{ .data = [_]u8{1} ** 16 };
    var item2 = LargeType{ .data = [_]u8{2} ** 16 };

    freelist.push(&item1);
    freelist.push(&item2);

    try std.testing.expect(freelist.pop() == &item2);
    try std.testing.expect(freelist.pop() == &item1);
    try std.testing.expect(freelist.pop() == null);
}

test "mixed push pop operations" {
    var freelist = FreeList(usize){};
    var values: [5]usize = .{ 10, 20, 30, 40, 50 };

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
