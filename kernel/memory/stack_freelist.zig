const std = @import("std");

pub fn StackFreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        stack: []T,
        top: isize,

        pub fn init(slice: []T) Self {
            return .{
                .stack = slice,
                .top = -1,
            };
        }

        fn pop(self: *Self) ?T {
            std.debug.assert(self.top < self.stack.len);
            if (self.top == -1) return null;

            const addr = self.stack[@intCast(self.top)];
            self.top -= 1;

            return addr;
        }

        fn push(self: *Self, addr: T) void {
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
