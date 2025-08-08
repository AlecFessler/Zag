const std = @import("std");

pub const ContainerError = error{
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

        allocator: std.mem.Allocator,
        root: ?*Node,

        const Color = enum {
            Red,
            Black,

            fn flip(c: Color) Color {
                return switch (c) {
                    Color.Red => Color.Black,
                    Color.Black => Color.Red,
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

        pub const Node = struct {
            color: Color,
            children: [2]?*Node,
            parent: ?*Node,
            data: T,

            fn create(allocator: std.mem.Allocator, data: T) !*Node {
                const ptr = try allocator.create(Node);
                ptr.* = .{
                    .color = Color.Red,
                    .children = .{
                        null,
                        null,
                    },
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            fn destroy(self: *Node, allocator: std.mem.Allocator) void {
                allocator.destroy(self);
            }

            fn getChild(self: *Node, d: Direction) ?*Node {
                return self.children[@intFromEnum(d)];
            }

            fn setChild(self: *Node, child: ?*Node, d: Direction) void {
                self.children[@intFromEnum(d)] = child;
            }

            fn getSibling(self: *Node) ?*Node {
                if (self.parent) |p| {
                    std.debug.assert(p.getChild(.left) == self or p.getChild(.right) == self);

                    return if (self == p.getChild(Direction.left)) p.getChild(Direction.right) else p.getChild(Direction.left);
                }
                return null;
            }

            fn getUncle(self: *Node) ?*Node {
                if (self.parent) |p| {
                    return p.getSibling();
                }
                return null;
            }

            fn getGrandparent(self: *Node) ?*Node {
                if (self.parent) |p| {
                    if (p.parent) |gp| {
                        std.debug.assert(gp.getChild(.left) == p or gp.getChild(.right) == p);
                        std.debug.assert(p.getChild(.left) == self or p.getChild(.right) == self);

                        return gp;
                    }
                }
                return null;
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .root = null,
            };
        }

        pub fn deinit(self: *Self) void {
            var current = self.root;

            while (current) |c| {
                if (c.getChild(Direction.left)) |left| {
                    current = left;
                } else if (c.getChild(Direction.right)) |right| {
                    current = right;
                } else {
                    const parent = c.parent;

                    if (parent) |p| {
                        if (p.getChild(Direction.left) == c) {
                            p.setChild(null, Direction.left);
                        } else {
                            p.setChild(null, Direction.right);
                        }
                    }

                    c.destroy(self.allocator);
                    current = parent;
                }
            }

            self.root = null;
        }

        pub fn contains(self: *Self, data: T) bool {
            var current = self.root;

            while (current) |node| {
                switch (cmpFn(data, node.data)) {
                    .eq => return true,
                    .lt => current = node.getChild(Direction.left),
                    .gt => current = node.getChild(Direction.right),
                }
            }

            return false;
        }

        pub fn insert(self: *Self, data: T) !void {
            if (self.root) |root| {
                var current: ?*Node = root;
                var parent: ?*Node = null;

                while (current) |c| {
                    parent = c;
                    switch (cmpFn(data, c.data)) {
                        .lt => current = c.getChild(Direction.left),
                        .gt => current = c.getChild(Direction.right),
                        .eq => {
                            if (duplicateIsError) return ContainerError.Duplicate;
                            current = c.getChild(Direction.left);
                        },
                    }
                }

                const node = try Node.create(self.allocator, data);
                if (parent) |p| {
                    node.parent = p;
                    if (cmpFn(data, p.data) == .lt) {
                        p.setChild(node, Direction.left);
                    } else {
                        p.setChild(node, Direction.right);
                    }

                    if (p.color == Color.Red) {
                        self.insertFix(node);
                    }
                }
            } else {
                const node = try Node.create(self.allocator, data);
                node.color = Color.Black;
                self.root = node;
            }
        }

        fn insertFix(self: *Self, node: *Node) void {
            var current = node;
            while (current.parent) |p| {
                if (p.color == Color.Black) break;

                var gp = current.getGrandparent() orelse break;
                const uncle = current.getUncle();
                const d = if (p == gp.getChild(Direction.left)) Direction.left else Direction.right;

                if (uncle) |u| {
                    if (u.color == Color.Red) {
                        p.color = Color.Black;
                        u.color = Color.Black;
                        gp.color = Color.Red;
                        current = gp;
                    } else {
                        if (current == p.getChild(d.flip())) {
                            self.rotate(p, d);
                            current = p;
                            current.parent.?.color = Color.Black;
                        } else {
                            p.color = Color.Black;
                        }
                        gp.color = Color.Red;
                        self.rotate(gp, d.flip());
                        break;
                    }
                } else {
                    if (current == p.getChild(d.flip())) {
                        self.rotate(p, d);
                        current = p;
                        current.parent.?.color = Color.Black;
                    } else {
                        p.color = Color.Black;
                    }
                    gp.color = Color.Red;
                    self.rotate(gp, d.flip());
                    break;
                }
            }

            self.root.?.color = Color.Black;
        }

        pub fn remove(self: *Self, data: T) !T {
            var parent: ?*Node = null;
            var current: ?*Node = self.root orelse return ContainerError.NotFound;

            while (current) |c| {
                switch (cmpFn(data, c.data)) {
                    .lt => current = c.getChild(Direction.left),
                    .gt => current = c.getChild(Direction.right),
                    .eq => break,
                }
                parent = c;
            }

            if (current == null) return ContainerError.NotFound;
            var target = current.?;
            const removed = target.data;

            const one_child_at_most = target.getChild(Direction.left) == null or target.getChild(Direction.right) == null;
            if (one_child_at_most) {
                const non_null_child = if (target.getChild(Direction.left) == null) Direction.right else Direction.left;
                const replacement = target.getChild(non_null_child);

                if (target == self.root) {
                    self.root = replacement;
                } else {
                    const dir_from_parent = if (target == parent.?.getChild(Direction.left)) Direction.left else Direction.right;
                    parent.?.setChild(replacement, dir_from_parent);
                    if (replacement) |r| r.parent = parent;
                }

                if (target.color == Color.Black) {
                    if (replacement) |r| {
                        if (r.color == Color.Red) r.color = Color.Black;
                    } else if (parent != null) {
                        self.removeFix(parent.?);
                    }
                }

                target.destroy(self.allocator);
            } else {
                parent = null;
                var successor: *Node = target.getChild(Direction.right).?;

                while (successor.getChild(Direction.left)) |left| {
                    parent = successor;
                    successor = left;
                }

                const replacement = successor.getChild(Direction.right);

                if (parent) |p| {
                    p.setChild(replacement, Direction.left);
                } else {
                    target.setChild(replacement, Direction.right);
                }

                if (replacement) |right| {
                    right.parent = parent orelse target;
                }

                if (successor.color == Color.Black) {
                    if (replacement) |r| {
                        if (r.color == Color.Red) r.color = Color.Black;
                    } else {
                        self.removeFix(parent orelse target);
                    }
                }

                target.data = successor.data;
                successor.destroy(self.allocator);
            }

            return removed;
        }

        fn removeFix(
            self: *Self,
            node: *Node,
        ) void {
            var current = node;
            while (current != self.root) {
                const sibling_opt = current.getSibling();
                if (sibling_opt == null) break;

                const sibling = sibling_opt.?;
                const parent = current.parent;
                const which_child: Direction = if (current == parent.?.getChild(Direction.left)) Direction.left else Direction.right;

                if (sibling.color == Color.Red) {
                    self.rotate(parent.?, which_child);
                    sibling.color = Color.Black;
                    parent.?.color = Color.Red;
                    continue;
                } else {
                    const near = sibling.getChild(which_child);
                    const far = sibling.getChild(which_child.flip());
                    const both_present = near != null and far != null;
                    const far_red = if (far) |f| f.color == Color.Red else false;
                    const near_red = if (near) |n| n.color == Color.Red else false;

                    if (both_present) {
                        const both_black = near.?.color == Color.Black and far.?.color == Color.Black;
                        if (both_black) {
                            sibling.color = Color.Red;
                            if (parent.?.color == Color.Red) {
                                parent.?.color = Color.Black;
                                break;
                            }
                            current = current.parent orelse break;
                            continue;
                        }
                    } else if (far_red) {
                        if (near_red) {
                            sibling.color = Color.Red;
                            near.?.color = Color.Black;
                            self.rotate(sibling, which_child.flip());
                        }
                        sibling.color = parent.?.color;
                        parent.?.color = Color.Black;
                        far.?.color = Color.Black;
                        self.rotate(parent.?, which_child);
                        break;
                    } else if (near_red) {
                        sibling.color = Color.Red;
                        near.?.color = Color.Black;
                        self.rotate(sibling, which_child.flip());
                        break;
                    } else {
                        sibling.color = Color.Red;
                        if (parent.?.color == Color.Red) {
                            parent.?.color = Color.Black;
                            break;
                        }
                        current = current.parent orelse break;
                        continue;
                    }
                }
            }

            if (self.root) |r| r.color = Color.Black;
        }

        fn rotate(
            self: *Self,
            pivot: *Node,
            d: Direction,
        ) void {
            const new_parent = pivot.getChild(d.flip()).?;

            pivot.setChild(new_parent.getChild(d), d.flip());
            if (new_parent.getChild(d)) |subtree| {
                subtree.parent = pivot;
            }
            new_parent.parent = pivot.parent;

            if (pivot.parent) |p| {
                std.debug.assert(p.getChild(.left) == pivot or p.getChild(.right) == pivot);

                const pivot_direction = if (p.getChild(Direction.left) == pivot) Direction.left else Direction.right;
                p.setChild(new_parent, pivot_direction);
            } else {
                self.root = new_parent;
            }

            new_parent.setChild(pivot, d);
            pivot.parent = new_parent;
        }

        pub fn findNeighbors(self: *Self, data: T) struct {
            lower: ?T,
            upper: ?T,
        } {
            var current = self.root;
            var lower: ?T = null;
            var upper: ?T = null;

            while (current) |node| {
                switch (cmpFn(data, node.data)) {
                    .lt => {
                        upper = node.data;
                        current = node.getChild(.left);
                    },
                    .gt => {
                        lower = node.data;
                        current = node.getChild(.right);
                    },
                    .eq => {
                        lower = node.data;
                        upper = node.data;
                        break;
                    },
                }
            }

            return .{ .lower = lower, .upper = upper };
        }

        /// helper function so that test cases can access T typed Node
        fn expectSameTree(a: ?*Node, b: ?*Node) !void {
            if (a == null or b == null) {
                try std.testing.expect(a == b);
                return;
            }
            try std.testing.expectEqual(a.?.data, b.?.data);
            try std.testing.expectEqual(a.?.color, b.?.color);
            try expectSameTree(a.?.getChild(.left), b.?.getChild(.left));
            try expectSameTree(a.?.getChild(.right), b.?.getChild(.right));
        }

        /// helper function so that test cases can create T typed Node
        fn testCreateNode(allocator: std.mem.Allocator) !*Node {
            return Node.create(allocator, 0);
        }

        /// helper function so that test cases can destroy T typed node
        fn testDestroyNode(node: *Node, allocator: std.mem.Allocator) void {
            Node.destroy(node, allocator);
        }

        /// helper function to validate red black tree invariants
        fn validateRedBlackTree(
            node: ?*Node,
            min_val: ?i32,
            max_val: ?i32,
        ) struct {
            valid: bool,
            black_height: i32,
        } {
            if (node == null) {
                return .{
                    .valid = true,
                    .black_height = 1,
                };
            }
            const n = node.?;

            // Invariant 2: BST property - left child < parent < right child
            if (min_val) |min| {
                if (n.data <= min) return .{
                    .valid = false,
                    .black_height = 0,
                };
            }
            if (max_val) |max| {
                if (n.data >= max) return .{
                    .valid = false,
                    .black_height = 0,
                };
            }

            // Invariant 3: All leaves (NIL nodes) are black
            // (This is implicitly satisfied since our null nodes are considered black)

            // Invariant 4: Red nodes have black children (no two red nodes adjacent)
            if (n.color == .Red) {
                if (n.getChild(.left)) |left| {
                    if (left.color == .Red) {
                        return .{
                            .valid = false,
                            .black_height = 0,
                        };
                    }
                }
                if (n.getChild(.right)) |right| {
                    if (right.color == .Red) {
                        return .{
                            .valid = false,
                            .black_height = 0,
                        };
                    }
                }
            }

            const left_result = validateRedBlackTree(
                n.getChild(.left),
                min_val,
                n.data,
            );
            const right_result = validateRedBlackTree(
                n.getChild(.right),
                n.data,
                max_val,
            );
            if (!left_result.valid or !right_result.valid) {
                return .{
                    .valid = false,
                    .black_height = 0,
                };
            }

            // Invariant 5: All paths from any node to its descendant leaves contain
            // the same number of black nodes (black height property)
            if (left_result.black_height != right_result.black_height) {
                return .{
                    .valid = false,
                    .black_height = 0,
                };
            }

            const black_contribution: i32 = if (n.color == .Black) 1 else 0;
            return .{
                .valid = true,
                .black_height = left_result.black_height + black_contribution,
            };
        }
    };
}

// test case comparator
fn i32Order(a: i32, b: i32) std.math.Order {
    return std.math.order(a, b);
}

test "insert and contains" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    try tree.insert(42);
    try std.testing.expect(tree.contains(42));
}

test "insert then remove and not contains" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    try tree.insert(7);
    try std.testing.expect(tree.contains(7));
    _ = try tree.remove(7);
    try std.testing.expect(!tree.contains(7));
}

test "insert duplicate returns error if configured" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, true).init(allocator);
    defer tree.deinit();

    try tree.insert(99);
    const err = tree.insert(99);
    try std.testing.expectError(error.Duplicate, err);
}

test "remove nonexistent value returns error" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    const err = tree.remove(1234);
    try std.testing.expectError(error.NotFound, err);
}

test "insert many and deinit without leaks" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    for (0..1000) |i| {
        try tree.insert(@intCast(i));
    }
}

test "insertFix case 1: recoloring when uncle is red" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const gp = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(gp, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const uncle = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(uncle, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const gp_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(gp_expected, allocator);
    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const uncle_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(uncle_expected, allocator);
    const new_node_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node_expected, allocator);

    gp.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ parent, uncle },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .Red,
        .children = .{ new_node, null },
        .parent = gp,
    };
    uncle.* = .{
        .data = 15,
        .color = .Red,
        .children = .{ null, null },
        .parent = gp,
    };
    new_node.* = .{
        .data = 2,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent,
    };

    gp_expected.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ parent_expected, uncle_expected },
        .parent = null,
    };
    parent_expected.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ new_node_expected, null },
        .parent = gp_expected,
    };
    uncle_expected.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ null, null },
        .parent = gp_expected,
    };
    new_node_expected.* = .{
        .data = 2,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = gp;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, gp_expected);
}

test "insertFix case 2a: triangle (rotate parent)" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const grand = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const grand_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    grand.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ parent, null },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .Red,
        .children = .{ null, new_node },
        .parent = grand,
    };
    new_node.* = .{
        .data = 7,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent,
    };

    grand_expected.* = .{
        .data = 7,
        .color = .Black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 5,
        .color = .Red,
        .children = .{ null, null },
        .parent = grand_expected,
    };
    right_expected.* = .{
        .data = 10,
        .color = .Red,
        .children = .{ null, null },
        .parent = grand_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = grand;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, grand_expected);
}

test "insertFix case 2b: line (rotate grandparent)" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const grand = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const root_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(root_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    grand.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ parent, null },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .Red,
        .children = .{ new_node, null },
        .parent = grand,
    };
    new_node.* = .{
        .data = 2,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent,
    };

    root_expected.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 2,
        .color = .Red,
        .children = .{ null, null },
        .parent = root_expected,
    };
    right_expected.* = .{
        .data = 10,
        .color = .Red,
        .children = .{ null, null },
        .parent = root_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = grand;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, root_expected);
}

test "removeFix case 1: red sibling" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const new_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_root, allocator);
    const left_of_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_of_root, allocator);
    const left_of_left = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_of_left, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node, sibling },
        .parent = null,
    };
    node.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent,
    };
    sibling.* = .{
        .data = 15,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent,
    };

    new_root.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ left_of_root, null },
        .parent = null,
    };
    left_of_root.* = .{
        .data = 10,
        .color = .Red,
        .children = .{ left_of_left, null },
        .parent = new_root,
    };
    left_of_left.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = left_of_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(node);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 2: black sibling, red far child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);
    const far = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(far, allocator);

    const new_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_root, allocator);
    const left = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left, allocator);
    const far_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(far_expected, allocator);
    const node_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node, sibling },
        .parent = null,
    };
    node.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent,
    };
    sibling.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ null, far },
        .parent = parent,
    };
    far.* = .{
        .data = 20,
        .color = .Red,
        .children = .{ null, null },
        .parent = sibling,
    };

    new_root.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ left, far_expected },
        .parent = null,
    };
    left.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node_expected, null },
        .parent = new_root,
    };
    node_expected.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = left,
    };
    far_expected.* = .{
        .data = 20,
        .color = .Black,
        .children = .{ null, null },
        .parent = new_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(node);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 3: black sibling, red near child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);
    const near = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(near, allocator);

    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const node_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node_expected, allocator);
    const near_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(near_expected, allocator);
    const sibling_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node, sibling },
        .parent = null,
    };
    node.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent,
    };
    sibling.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ near, null },
        .parent = parent,
    };
    near.* = .{
        .data = 12,
        .color = .Red,
        .children = .{ null, null },
        .parent = sibling,
    };

    parent_expected.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node_expected, near_expected },
        .parent = null,
    };
    node_expected.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent_expected,
    };
    near_expected.* = .{
        .data = 12,
        .color = .Black,
        .children = .{ null, sibling_expected },
        .parent = parent_expected,
    };
    sibling_expected.* = .{
        .data = 15,
        .color = .Red,
        .children = .{ null, null },
        .parent = near_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(node);

    try Tree.expectSameTree(tree.root, parent_expected);
}

test "removeFix case 4: black sibling, black children" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const node_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(node_expected, allocator);
    const sibling_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node, sibling },
        .parent = null,
    };
    node.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent,
    };
    sibling.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent,
    };

    parent_expected.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ node_expected, sibling_expected },
        .parent = null,
    };
    node_expected.* = .{
        .data = 5,
        .color = .Black,
        .children = .{ null, null },
        .parent = parent_expected,
    };
    sibling_expected.* = .{
        .data = 15,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(node);

    try Tree.expectSameTree(tree.root, parent_expected);
}

test "insert remove insert cycles maintain red-black tree invariants" {
    const allocator = std.testing.allocator;

    const Tree = RedBlackTree(i32, i32Order, false);

    var tree = Tree.init(allocator);
    defer tree.deinit();

    const initial_values = [_]i32{ 10, 5, 15, 3, 7, 12, 18, 1, 4, 6, 8, 11, 13, 16, 20 };
    for (initial_values) |val| {
        try tree.insert(val);
    }

    const to_remove_1 = [_]i32{ 3, 15, 8, 1 };
    for (to_remove_1) |val| {
        _ = try tree.remove(val);
    }

    const to_insert_2 = [_]i32{ 2, 9, 14, 17, 25, 30 };
    for (to_insert_2) |val| {
        try tree.insert(val);
    }

    const to_remove_2 = [_]i32{ 7, 12, 20, 2 };
    for (to_remove_2) |val| {
        _ = try tree.remove(val);
    }

    const to_insert_3 = [_]i32{ 22, 26, 35, 40, 45 };
    for (to_insert_3) |val| {
        try tree.insert(val);
    }

    // Validate red-black tree invariants
    if (tree.root) |root| {
        // Invariant 1: Root is black
        try std.testing.expect(root.color == .Black);

        // Validate all invariants
        const result = Tree.validateRedBlackTree(
            root,
            null,
            null,
        );
        try std.testing.expect(result.valid);
    }

    const expected_present = [_]i32{ 10, 5, 4, 6, 11, 13, 16, 18, 9, 14, 17, 25, 30, 26, 22, 35, 40, 45 };
    for (expected_present) |val| {
        try std.testing.expect(tree.contains(val));
    }

    const expected_absent = [_]i32{ 3, 15, 8, 1, 7, 12, 20, 2 };
    for (expected_absent) |val| {
        try std.testing.expect(!tree.contains(val));
    }
}

test "findNeighbors returns correct lower and upper" {
    const allocator = std.testing.allocator;
    const Tree = RedBlackTree(i32, i32Order, false);
    var tree = Tree.init(allocator);
    defer tree.deinit();

    try tree.insert(10);
    try tree.insert(20);
    try tree.insert(40);
    try tree.insert(50);

    const neighbors = tree.findNeighbors(30);

    try std.testing.expectEqual(@as(?i32, 20), neighbors.lower);
    try std.testing.expectEqual(@as(?i32, 40), neighbors.upper);
}
