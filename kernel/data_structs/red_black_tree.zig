const std = @import("std");

pub const DataStructError = error{
    Duplicate,
    NotFound,
};

pub fn RedBlackTree(
    comptime T: type,
    comptime cmpFn: fn (T, T) std.math.Order,
    comptime duplicateIsError: bool,
) type {
    return struct {
        const Self = @This();

        allocator: *std.mem.Allocator,
        root: ?*Node,

        const Color = enum {
            Red,
            Black,

            fn flip(c: Color) Color {
                return switch (c) {
                    .Red => .Black,
                    .Black => .Red,
                };
            }
        };

        const Direction = enum {
            left,
            right,

            fn flip(d: Direction) Direction {
                return @enumFromInt(1 - @intFromEnum(d));
            }
        };

        const Node = struct {
            color: Color,
            child: [2]?*Node,
            data: T,

            fn create(allocator: *std.mem.Allocator, data: T) !*Node {
                const ptr = allocator.create(Node);
                ptr.* = .{
                    .color = .Red,
                    .child = .{
                        null,
                        null,
                    },
                    .data = data,
                };
                return ptr;
            }

            fn destroy(self: *Node, allocator: *std.mem.Allocator) void {
                allocator.destroy(self);
            }
        };

        pub fn init(allocator: *std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .root = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.deinitRecursive(self.root);
        }

        fn deinitRecursive(self: *Self, node: ?*Node) void {
            if (node) |n| {
                self.deinitRecursive(n.child[.left]);
                self.deinitRecursive(n.child[.right]);
                n.destroy(self.allocator);
            }
        }

        pub fn contains(self: *Self, data: T) bool {
            return containsRecursive(self.root, data);
        }

        fn containsRecursive(node: ?*Node, data: T) bool {
            if (node) |n| {
                switch (cmpFn(data, n.data)) {
                    .lt => return containsRecursive(n.child[.left], data),
                    .gt => return containsRecursive(n.child[.right], data),
                    .eq => return true,
                }
            }
            return false;
        }

        pub fn insert(self: *Self, data: T) !void {
            self.root = try self.insertRecursive(self.root, data);
            self.root.color = .Black;
        }

        fn insertRecursive(self: *Self, node: ?*Node, data: T) !*Node {
            if (node) |n| {
                var d: Direction = undefined;
                switch (cmpFn(data, n.data)) {
                    .lt => d = .left,
                    .gt => d = .right,
                    .eq => {
                        if (duplicateIsError) return DataStructError.Duplicate;
                        d = .left;
                    },
                }
                n.child[d] = try insertRecursive(n.child[d], data);

                return insertFix(n, d);
            }

            return try Node.create(self.allocator, data);
        }

        fn insertFix(node: *Node, d: Direction) *Node {
            const child = node.child[d];
            const sibling = node.child[d.flip()];

            const child_red = child != null and child.?.color == .Red;
            const sibling_red = sibling != null and sibling.?.color == .Red;

            if (child_red) {
                if (sibling_red) {
                    const straight = child.?.child[d];
                    const zigzag = child.?.child[d.flip()];

                    const straight_red = straight != null and straight.?.color == .Red;
                    const zigzag_red = zigzag != null and zigzag.?.color == .Red;

                    if (straight_red or zigzag_red) node.color = node.color.flip();
                } else {
                    const straight = child.?.child[d];
                    const zigzag = child.?.child[d.flip()];

                    const straight_red = straight != null and straight.?.color == .Red;
                    const zigzag_red = zigzag != null and zigzag.?.color == .Red;

                    if (straight_red) {
                        node = rotate(node, d.flip());
                    } else if (zigzag_red) {
                        node = doubleRotate(node, d.flip());
                    }
                }
            }

            return node;
        }

        pub fn remove(self: *Self, data: T) !void {
            const fixed = false;
            self.root = removeRecursive(self.root, data, &fixed);
            if (self.root) |r| r.color = .Black;
        }

        fn removeRecursive(node: ?*Node, data: T, fixed: *bool) *Node {
            // TODO:
        }

        fn removeFix(node: *Node, d: Direction, fixed: *bool) *Node {
            // TODO:
        }

        fn rotate(pivot: *Node, d: Direction) *Node {
            const temp = pivot.child[d.flip()];
            pivot.child[d.flip()] = temp.child[d];
            temp.child[d] = pivot;

            temp.color = pivot.color;
            pivot.color = .Red;

            return temp;
        }

        fn doubleRotate(node: *Node, d: Direction) *Node {
            const flipped = d.flip();
            node.child[flipped] = rotate(node.child[flipped], flipped);
            return rotate(node, d);
        }
    };
}
