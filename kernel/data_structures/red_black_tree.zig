const std = @import("std");

const Color = enum {
    Red,
    Black,
};

pub fn RedBlackTree(
    comptime T: type,
    comptime compareFn: fn (T, T) std.math.Order,
) type {
    return struct {
        const Self = @This();

        allocator: *std.mem.Allocator,
        root: ?*Node,

        const Node = struct {
            color: Color,
            left: ?*Node,
            right: ?*Node,
            parent: ?*Node,
            data: T,

            fn create(allocator: *std.mem.Allocator, data: T) !*Node {
                const ptr = allocator.create(Node);
                ptr.* = .{
                    .color = .Red,
                    .left = null,
                    .right = null,
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            fn destroy(self: *Node, allocator: *std.mem.Allocator) void {
                allocator.destroy(self);
            }

            fn sibling(self: *Node) ?*Node {
                if (self.p) |p| {
                    return if (self == p.left) p.right else p.left;
                }
                return null;
            }

            fn uncle(self: *Node) ?*Node {
                if (self.parent) |p| {
                    return p.sibling();
                }
                return null;
            }

            fn grandparent(self: *Node) ?*Node {
                if (self.parent) |p| {
                    if (p.parent) |gp| {
                        return gp;
                    }
                }
                return null;
            }
        };

        pub fn init(allocator: *std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .root = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.destroySubtree(self.root);
        }

        fn destroySubtree(self: *Self, node: ?*Node) void {
            if (node) |n| {
                self.destroySubtree(n.left);
                self.destroySubtree(n.right);
                n.destroy(self.allocator);
            }
        }

        pub fn contains(self: *Self, data: T) bool {
            var current = self.root;

            while (current) |node| {
                switch (compareFn(data, node.data)) {
                    .eq => return true,
                    .lt => current = node.left,
                    .gt => current = node.right,
                }
            }

            return false;
        }

        pub fn insert(self: *Self, data: T) !void {
            // standard bst insert
            // insertFix()
        }

        fn insertFix(self: *Self, node: *Node) void {}

        pub fn remove(self: *Self, data: T) bool {
            // standard bst remove
            // removeFix()
        }

        fn removeFix(self: *Self, node: ?*Node, parent: ?*Node) void {}

        fn rotateLeft(self: *Self, pivot: *Node) void {}

        fn rotateRight(self: *Self, pivot: *Node) void {}
    };
}
