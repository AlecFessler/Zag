const std = @import("std");

const allocator_interface = @import("../memory/allocator.zig");
const Allocator = allocator_interface.Allocator;

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

        allocator: *Allocator,
        root: ?*Node,

        const Node = struct {
            color: Color,
            left: ?*Node,
            right: ?*Node,
            parent: ?*Node,
            data: T,

            fn create(allocator: *Allocator, data: T) !*Node {
                const ptr: *Node = @ptrCast(try allocator.alloc(
                    @sizeOf(Node),
                    @alignOf(Node),
                ));
                ptr.* = .{
                    .color = .Red,
                    .left = null,
                    .right = null,
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            fn destroy(self: *Node, allocator: *Allocator) void {
                allocator.free(@intFromPtr(self));
            }
        };

        pub fn init(allocator: *Allocator) Self {
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
            const new_node = try Node.create(self.allocator, data);

            if (self.root == null) {
                self.root = new_node;
                new_node.color = .Black;
                return;
            }

            var current = self.root.?;
            while (true) {
                switch (compareFn(data, current.data)) {
                    .eq => {
                        new_node.destroy(self.allocator);
                        return;
                    },
                    .lt => {
                        if (current.left == null) {
                            current.left = new_node;
                            new_node.parent = current;
                            break;
                        }
                        current = current.left.?;
                    },
                    .gt => {
                        if (current.right == null) {
                            current.right = new_node;
                            new_node.parent = current;
                            break;
                        }
                        current = current.right.?;
                    },
                }
            }

            self.insertFixup(new_node);
        }

        fn insertFixup(self: *Self, node: *Node) void {
            var current = node;

            // Continue while current is red and has a red parent
            while (current.parent != null and current.parent.?.color == .Red) {
                const parent = current.parent.?;
                const grandparent = parent.parent.?; // Must exist since parent is red (not root)

                if (parent == grandparent.left) {
                    const uncle = grandparent.right;

                    if (uncle != null and uncle.?.color == .Red) {
                        // Case 1: Uncle is red - recolor
                        parent.color = .Black;
                        uncle.?.color = .Black;
                        grandparent.color = .Red;
                        current = grandparent;
                    } else {
                        // Uncle is black or null
                        if (current == parent.right) {
                            // Case 2: Current is right child - left rotate
                            current = parent;
                            self.rotateLeft(current);
                        }
                        // Case 3: Current is left child - recolor and right rotate
                        current.parent.?.color = .Black;
                        current.parent.?.parent.?.color = .Red;
                        self.rotateRight(current.parent.?.parent.?);
                    }
                } else {
                    // Mirror cases for right subtree
                    const uncle = grandparent.left;

                    if (uncle != null and uncle.?.color == .Red) {
                        parent.color = .Black;
                        uncle.?.color = .Black;
                        grandparent.color = .Red;
                        current = grandparent;
                    } else {
                        if (current == parent.left) {
                            current = parent;
                            self.rotateRight(current);
                        }
                        current.parent.?.color = .Black;
                        current.parent.?.parent.?.color = .Red;
                        self.rotateLeft(current.parent.?.parent.?);
                    }
                }
            }

            // Root must always be black
            self.root.?.color = .Black;
        }

        pub fn remove(self: *Self, data: T) bool {
            const node_to_remove = self.findNode(data) orelse return false;

            var y = node_to_remove;
            var y_original_color = y.color;
            var x: ?*Node = null;
            var x_parent: ?*Node = null;

            if (node_to_remove.left == null) {
                x = node_to_remove.right;
                x_parent = node_to_remove.parent;
                self.transplant(node_to_remove, node_to_remove.right);
            } else if (node_to_remove.right == null) {
                x = node_to_remove.left;
                x_parent = node_to_remove.parent;
                self.transplant(node_to_remove, node_to_remove.left);
            } else {
                // Node has two children - find successor
                y = self.minimum(node_to_remove.right.?);
                y_original_color = y.color;
                x = y.right;

                if (y.parent == node_to_remove) {
                    x_parent = y;
                } else {
                    x_parent = y.parent;
                    self.transplant(y, y.right);
                    y.right = node_to_remove.right;
                    y.right.?.parent = y;
                }

                self.transplant(node_to_remove, y);
                y.left = node_to_remove.left;
                y.left.?.parent = y;
                y.color = node_to_remove.color;
            }

            node_to_remove.destroy(self.allocator);

            // Fix red-black violations if we removed a black node
            if (y_original_color == .Black) {
                self.deleteFixup(x, x_parent);
            }

            return true;
        }

        fn findNode(self: *Self, data: T) ?*Node {
            var current = self.root;

            while (current) |node| {
                switch (compareFn(data, node.data)) {
                    .eq => return node,
                    .lt => current = node.left,
                    .gt => current = node.right,
                }
            }

            return null;
        }

        fn minimum(self: *Self, node: *Node) *Node {
            _ = self;
            var current = node;
            while (current.left) |left| {
                current = left;
            }
            return current;
        }

        fn transplant(self: *Self, u: *Node, v: ?*Node) void {
            if (u.parent == null) {
                self.root = v;
            } else if (u == u.parent.?.left) {
                u.parent.?.left = v;
            } else {
                u.parent.?.right = v;
            }

            if (v) |node| {
                node.parent = u.parent;
            }
        }

        fn deleteFixup(self: *Self, node: ?*Node, node_parent: ?*Node) void {
            var x = node;
            var x_parent = node_parent;

            while (x != self.root and (x == null or x.?.color == .Black)) {
                if (x == x_parent.?.left) {
                    var w = x_parent.?.right.?; // Sibling must exist

                    if (w.color == .Red) {
                        w.color = .Black;
                        x_parent.?.color = .Red;
                        self.rotateLeft(x_parent.?);
                        w = x_parent.?.right.?;
                    }

                    if ((w.left == null or w.left.?.color == .Black) and
                        (w.right == null or w.right.?.color == .Black))
                    {
                        w.color = .Red;
                        x = x_parent;
                        x_parent = x.?.parent;
                    } else {
                        if (w.right == null or w.right.?.color == .Black) {
                            w.left.?.color = .Black;
                            w.color = .Red;
                            self.rotateRight(w);
                            w = x_parent.?.right.?;
                        }

                        w.color = x_parent.?.color;
                        x_parent.?.color = .Black;
                        w.right.?.color = .Black;
                        self.rotateLeft(x_parent.?);
                        x = self.root;
                        break;
                    }
                } else {
                    var w = x_parent.?.left.?;

                    if (w.color == .Red) {
                        w.color = .Black;
                        x_parent.?.color = .Red;
                        self.rotateRight(x_parent.?);
                        w = x_parent.?.left.?;
                    }

                    if ((w.right == null or w.right.?.color == .Black) and
                        (w.left == null or w.left.?.color == .Black))
                    {
                        w.color = .Red;
                        x = x_parent;
                        x_parent = x.?.parent;
                    } else {
                        if (w.left == null or w.left.?.color == .Black) {
                            w.right.?.color = .Black;
                            w.color = .Red;
                            self.rotateLeft(w);
                            w = x_parent.?.left.?;
                        }

                        w.color = x_parent.?.color;
                        x_parent.?.color = .Black;
                        w.left.?.color = .Black;
                        self.rotateRight(x_parent.?);
                        x = self.root;
                        break;
                    }
                }
            }

            if (x) |new_root| {
                new_root.color = .Black;
            }
        }

        fn rotateLeft(self: *Self, x: *Node) void {
            const y = x.right.?;

            x.right = y.left;
            if (y.left) |left| {
                left.parent = x;
            }

            y.parent = x.parent;
            if (x.parent == null) {
                self.root = y;
            } else if (x == x.parent.?.left) {
                x.parent.?.left = y;
            } else {
                x.parent.?.right = y;
            }

            y.left = x;
            x.parent = y;
        }

        fn rotateRight(self: *Self, x: *Node) void {
            const y = x.left.?;

            x.left = y.right;
            if (y.right) |right| {
                right.parent = x;
            }

            y.parent = x.parent;
            if (x.parent == null) {
                self.root = y;
            } else if (x == x.parent.?.right) {
                x.parent.?.right = y;
            } else {
                x.parent.?.left = y;
            }

            y.right = x;
            x.parent = y;
        }
    };
}
