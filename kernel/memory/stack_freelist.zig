const std = @import("std");

const fl = @import("freelist.zig");

pub fn StackFreeList(comptime T: type) type {
    return struct {
        const Self = @This();
        const FreeList = fl.FreeList(T);

        stack: []T,
        top: isize,

        pub fn init(slice: []T) Self {
            return .{
                .stack = slice,
                .top = -1,
            };
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

            std.debug.assert(self.top < self.stack.len);
            if (self.top == -1) return null;

            const addr = self.stack[@intCast(self.top)];
            self.top -= 1;

            switch (@typeInfo(T)) {
                .int => return @ptrFromInt(addr),
                .pointer => return @ptrCast(addr),
                else => @compileError("Freelist expects integer or pointer types only"),
            }
        }

        fn push(ptr: *anyopaque, addr: [*]u8) void {
            var self: *Self = @alignCast(@ptrCast(ptr));

            std.debug.assert(self.top >= -1);
            if (self.top + 1 < self.stack.len) {
                self.top += 1;
            }

            switch (@typeInfo(T)) {
                .int => self.stack[@intCast(self.top)] = @intFromPtr(addr),
                .pointer => self.stack[@intCast(self.top)] = @alignCast(@ptrCast(addr)),
                else => @compileError("Freelist expects integer or pointer types only"),
            }
        }

        fn isFree(ptr: *anyopaque, addr: [*]u8) bool {
            // this is not implemeneted because it's an O(n) operation to search
            // if you need to do this operation, consider the bitmap freelist
            _ = ptr;
            _ = addr;
            unreachable;
        }
    };
}

test "pop returns null when empty" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);
    var free_list = freelist.freelist();

    try std.testing.expect(free_list.getNextFree() == null);
}

test "push pop returns original" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 1);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);
    var free_list = freelist.freelist();

    const value = 42;

    free_list.setFree(value);
    const result = free_list.getNextFree().?;

    try std.testing.expect(result == value);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "push push pop pop returns LIFO order" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 2);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);
    var free_list = freelist.freelist();

    const value1 = 1;
    const value2 = 2;

    free_list.setFree(value1);
    free_list.setFree(value2);

    const first = free_list.getNextFree().?;
    const second = free_list.getNextFree().?;

    try std.testing.expect(first == value2);
    try std.testing.expect(second == value1);
    try std.testing.expect(free_list.getNextFree() == null);
}

test "mixed push pop operations" {
    const allocator = std.testing.allocator;
    const slice = try allocator.alloc(usize, 5);
    defer allocator.free(slice);
    var freelist = StackFreeList(usize).init(slice);
    var free_list = freelist.freelist();

    const values: [5]usize = .{ 10, 20, 30, 40, 50 };

    free_list.setFree(values[0]);
    free_list.setFree(values[1]);
    free_list.setFree(values[2]);

    try std.testing.expect(free_list.getNextFree().? == values[2]);
    try std.testing.expect(free_list.getNextFree().? == values[1]);

    free_list.setFree(values[3]);
    free_list.setFree(values[4]);

    try std.testing.expect(free_list.getNextFree().? == values[4]);
    try std.testing.expect(free_list.getNextFree().? == values[3]);
    try std.testing.expect(free_list.getNextFree().? == values[0]);
    try std.testing.expect(free_list.getNextFree() == null);
}
