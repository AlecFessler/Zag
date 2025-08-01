const std = @import("std");

pub fn ArrayFreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        /// array in the computer science way, not the zig type
        array: []T,
        top: isize,

        pub fn init(slice: []T) Self {
            return .{
                .array = slice,
                .top = -1,
            };
        }

        pub fn push(self: *Self, item: T) void {
            std.debug.assert(self.top >= -1);
            if (self.top + 1 < self.array.len) {
                self.top += 1;
            }

            // casting a negative isize to usize would overflow the slice
            // and it's assumed to always be greater than 0 here
            std.debug.assert(self.top >= 0);
            self.array[@intCast(self.top)] = item;
        }

        pub fn pop(self: *Self) ?T {
            std.debug.assert(self.top < self.array.len);
            if (self.top == -1) return null;

            // casting a negative isize to usize would overflow the slice
            // and it's assumed to always be greater than 0 here
            std.debug.assert(self.top >= 0);
            const item = self.array[@intCast(self.top)];
            self.top -= 1;
            return item;
        }

        pub fn peek(self: *Self) ?T {
            std.debug.assert(self.top < self.array.len);
            if (self.top == -1) return null;

            // casting a negative isize to usize would overflow the slice
            // and it's assumed to always be greater than 0 here
            std.debug.assert(self.top >= 0);
            return self.array[@intCast(self.top)];
        }
    };
}

test "pop returns null when empty" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = ArrayFreeList(usize).init(slice);

    try std.testing.expect(freelist.pop() == null);
}

test "push pop returns original" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = ArrayFreeList(usize).init(slice);

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
    var freelist = ArrayFreeList(usize).init(slice);

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
    var freelist = ArrayFreeList(usize).init(slice);

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

test "peek returns top element without popping" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 2);
    defer allocator.free(slice);
    var freelist = ArrayFreeList(usize).init(slice);

    try std.testing.expect(freelist.peek() == null);

    freelist.push(123);
    try std.testing.expect(freelist.peek().? == 123);
    try std.testing.expect(freelist.peek().? == 123);

    freelist.push(456);
    try std.testing.expect(freelist.peek().? == 456);

    try std.testing.expect(freelist.pop().? == 456);
    try std.testing.expect(freelist.peek().? == 123);

    _ = freelist.pop();
    try std.testing.expect(freelist.peek() == null);
}
