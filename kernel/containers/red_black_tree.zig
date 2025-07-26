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
            children: [2]?*Node,
            parent: ?*Node,
            data: T,

            fn create(allocator: *std.mem.Allocator, data: T) !*Node {
                const ptr = allocator.create(Node);
                ptr.* = .{
                    .color = .Red,
                    .children = .{
                        null,
                        null,
                    },
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            fn destroy(self: *Node, allocator: *std.mem.Allocator) void {
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
                    return if (self == p.getChild(.left)) p.getChild(.right) else p.getChild(.left);
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

        fn deinit(self: *Self) void {
            var current = self.root;
            var prev: ?*Node = null;
            var next: ?*Node = null;
            while (current) : ({
                prev = current;
                current = next;
            }) {
                const prevIsParent = current.parent != null and prev == current.parent;
                const prevIsLeft = current.getChild(.left) != null and prev == current.getChild(.left);

                if (prevIsParent) {
                    if (current.getChild(.left)) |left| {
                        next = left;
                        continue;
                    } else if (current.getChild(.right)) |right| {
                        next = right;
                        continue;
                    }
                } else if (prevIsLeft) {
                    if (current.getChild(.right)) |right| {
                        next = right;
                        continue;
                    }
                }

                next = current.parent;
                current.destroy(self.allocator);
            }
        }

        pub fn contains(self: *Self, data: T) bool {
            var current = self.root;

            while (current) |node| {
                switch (cmpFn(data, node.data)) {
                    .eq => return true,
                    .lt => current = node.getChild(.left),
                    .gt => current = node.getChild(.right),
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
                        .lt => current = c.getChild(.left),
                        .gt => current = c.getChild(.right),
                        .eq => {
                            if (duplicateIsError) return ContainerError.Duplicate;
                            current = c.getChild(.left);
                        },
                    }
                }

                const node = try Node.create(self.allocator, data);
                if (parent) |p| {
                    node.parent = p;
                    if (cmpFn(data, p.data) == .lt) {
                        p.setChild(node, .left);
                    } else {
                        p.setChild(node, .right);
                    }

                    if (p.color == .Red) {
                        self.insertFix(node);
                    }
                }
            } else {
                const node = try Node.create(self.allocator, data);
                node.color = .Black;
                self.root = node;
            }
        }

        fn insertFix(self: *Self, node: *Node) void {
            while (node.parent) |p| {
                if (p.color == .Black) break;

                var gp = node.getGrandparent() orelse unreachable;
                const uncle = node.getUncle();

                const d = if (p == gp.getChild(.left)) .left else .right;
                if (uncle) |u| {
                    if (u.color == .Black) break;
                    p.color = .Black;
                    u.color = .Black;
                    gp.color = .Red;
                    node = gp;
                } else {
                    if (node == p.getChild(d.flip())) {
                        self.rotate(p, d);
                        node = p;
                        p = node.parent.?; // rotation means we are not the root
                    }
                    p.color = .Black;
                    gp.color = .Red;
                    self.rotate(gp, d.flip());
                }
            }

            self.root.?.color = .Black;
        }

        pub fn remove(self: *Self, data: T) !void {
            var parent: ?*Node = null;
            var current: ?*Node = self.root orelse return ContainerError.NotFound;

            while (current) |c| {
                switch (cmpFn(data, c.data)) {
                    .lt => current = c.getChild(.left),
                    .gt => current = c.getChild(.right),
                    .eq => break,
                }
                parent = c;
            }

            if (current == null) return ContainerError.NotFound;
            var target = current.?;

            const one_child_at_most = target.getChild(.left) == null or target.getChild(.right) == null;
            if (one_child_at_most) {
                const non_null_child = if (target.getChild(.left) == null) .right else .left;
                const replacement = target.getChild(non_null_child);

                if (target == self.root) {
                    self.root = replacement;
                } else {
                    const dir_from_parent = if (target == parent.getChild(.left)) .left else .right;
                    parent.setChild(replacement, dir_from_parent);
                    if (replacement) |r| r.parent = parent;
                }

                if (target.color == .Black) {
                    if (replacement) |r| {
                        if (r.color == .Red) r.color = .Black;
                    } else {
                        self.removeFix(parent);
                    }
                }

                target.destroy(self.allocator);
            } else {
                parent = null;
                var successor: *Node = target.getChild(.right).?;

                while (successor.getChild(.left)) |left| {
                    parent = successor;
                    successor = left;
                }

                const replacement = successor.getChild(.right);

                if (parent) |p| {
                    p.setChild(replacement, .left);
                } else {
                    target.setChild(replacement, .right);
                }

                if (replacement) |right| {
                    right.parent = parent orelse target;
                }

                if (successor.color == .Black) {
                    if (replacement) |r| {
                        if (r.color == .Red) r.color = .Black;
                    } else {
                        self.removeFix(parent orelse target);
                    }
                }

                target.data = successor.data;
                successor.destroy(self.allocator);
            }
        }

        fn removeFix(
            self: *Self,
            node: *Node,
        ) void {
            while (node != self.root) {
                const sibling_opt = node.getSibling();
                if (sibling_opt == null) break;

                const sibling = sibling_opt.?;
                const parent = node.parent;
                const which_child: Direction = if (node == parent.getChild(.left)) .left else .right;

                if (sibling.color == .Red) {
                    self.rotate(node, which_child);
                    sibling.color = .Black;
                    parent.color = .Red;
                    continue;
                } else {
                    const near = sibling.getChild(which_child);
                    const far = sibling.getChild(which_child.flip());
                    const both_present = near != null and far != null;
                    const far_red = if (far) |f| f.color == .Red else false;
                    const near_red = if (near) |n| n.color == .Red else false;

                    if (both_present) {
                        const both_black = near.?.color == .Black and far.?.color == .Black;
                        if (both_black) {
                            sibling.color = .Red;
                            if (parent.color == .Red) {
                                parent.color = .Black;
                                break;
                            }
                            node = node.parent;
                            continue;
                        }
                    } else if (far_red) {
                        if (near_red) {
                            sibling.color = .Red;
                            near.?.color = .Black;
                            self.rotate(sibling, which_child.flip());
                            continue;
                        }
                        sibling.color = parent.color;
                        parent.color = .Black;
                        far.?.color = .Black;
                        self.rotate(parent, which_child);
                        break;
                    }
                }
            }

            if (self.root) |r| r.color = .Black;
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
                p.setChild(new_parent, d);
            } else {
                self.root = new_parent;
            }

            new_parent.setChild(pivot, d);
            pivot.parent = new_parent;
        }
    };
}
