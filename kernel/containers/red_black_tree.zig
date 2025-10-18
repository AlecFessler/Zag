//! Generic red-black tree container.
//!
//! Provides an intrusive-style, allocator-backed red-black tree storing values of
//! type `T` by value. Ordering is defined by a caller-supplied comparator returning
//! `std.math.Order`. Duplicate handling is configurable at compile time.
//!
//! Operations: insert/remove/contains, neighbor search, and validation helpers.

const std = @import("std");

/// Errors returned by container operations.
pub const ContainerError = error{
    /// Insertion encountered an equal key when `duplicateIsError = true`.
    Duplicate,
    /// Element not found for removal.
    NotFound,
};

/// Factory that produces a red-black tree type specialized for:
/// - `T`: element type (stored by value)
/// - `cmpFn`: strict total order comparator (a,b) → `.lt | .eq | .gt`
/// - `duplicateIsError`: if true, inserting an equal key returns `error.Duplicate`;
///   if false, equal keys are inserted on the left subtree and allowed to coexist.
pub fn RedBlackTree(
    comptime T: type,
    comptime cmpFn: fn (T, T) std.math.Order,
    comptime duplicateIsError: bool,
) type {
    return struct {
        const Self = @This();

        /// Allocator used for node storage.
        allocator: std.mem.Allocator,
        /// Root node pointer (null when empty).
        root: ?*Node,
        /// Number of elements in the tree.
        count: usize,

        /// Node color.
        const Color = enum {
            Red,
            Black,

            /// Returns the opposite color.
            ///
            /// Arguments:
            /// - `c`: color to flip.
            ///
            /// Returns:
            /// - The opposite of `c`.
            fn flip(c: Color) Color {
                return switch (c) {
                    Color.Red => Color.Black,
                    Color.Black => Color.Red,
                };
            }
        };

        /// Child side used by many helpers.
        pub const Direction = enum {
            left,
            right,

            /// Returns the opposite side.
            ///
            /// Arguments:
            /// - `d`: direction to flip.
            ///
            /// Returns:
            /// - The opposite of `d`.
            fn flip(d: Direction) Direction {
                return @enumFromInt(1 - @intFromEnum(d));
            }
        };

        /// Tree node holding one `T` value.
        pub const Node = struct {
            /// Red/black state.
            color: Color,
            /// Child pointers `[left, right]`.
            children: [2]?*Node,
            /// Parent pointer (null for root).
            parent: ?*Node,
            /// Stored element.
            data: T,

            /// Allocates and initializes a red node with `data`.
            ///
            /// Arguments:
            /// - `allocator`: backing allocator for the node.
            /// - `data`: element value to store.
            ///
            /// Returns:
            /// - Pointer to the newly created `Node`.
            ///
            /// Errors:
            /// - `std.mem.Allocator.Error` on allocation failure.
            fn create(allocator: std.mem.Allocator, data: T) !*Node {
                const ptr = try allocator.create(Node);
                ptr.* = .{
                    .color = Color.Red,
                    .children = .{ null, null },
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            /// Destroys the node using `allocator`.
            ///
            /// Arguments:
            /// - `self`: node to destroy.
            /// - `allocator`: allocator that owns the node.
            fn destroy(self: *Node, allocator: std.mem.Allocator) void {
                allocator.destroy(self);
            }

            /// Reads a child pointer by direction.
            ///
            /// Arguments:
            /// - `self`: node to inspect.
            /// - `d`: which child to return.
            ///
            /// Returns:
            /// - Child pointer (`?*Node`) for side `d`.
            ///
            /// Notes:
            /// - Public to enable external traversals without exposing internals.
            pub fn getChild(self: *Node, d: Direction) ?*Node {
                return self.children[@intFromEnum(d)];
            }

            /// Sets parent↔child links atomically for `self` and `child`.
            ///
            /// Arguments:
            /// - `self`: parent node whose child to set.
            /// - `child`: child pointer (nullable).
            /// - `d`: which side to set.
            fn setParentChildRelation(self: *Node, child: ?*Node, d: Direction) void {
                self.children[@intFromEnum(d)] = child;
                if (child) |c| c.parent = self;
            }

            /// Returns the sibling node if any.
            ///
            /// Arguments:
            /// - `self`: node whose sibling to fetch.
            ///
            /// Returns:
            /// - Sibling pointer or `null` if none.
            fn getSibling(self: *Node) ?*Node {
                if (self.parent) |p| {
                    std.debug.assert(p.getChild(.left) == self or p.getChild(.right) == self);
                    return if (self == p.getChild(Direction.left))
                        p.getChild(Direction.right)
                    else
                        p.getChild(Direction.left);
                }
                return null;
            }

            /// Returns the parent's sibling (uncle) if any.
            ///
            /// Arguments:
            /// - `self`: node whose uncle to fetch.
            ///
            /// Returns:
            /// - Uncle pointer or `null` if none.
            fn getUncle(self: *Node) ?*Node {
                if (self.parent) |p| {
                    return p.getSibling();
                }
                return null;
            }

            /// Returns the grandparent if any.
            ///
            /// Arguments:
            /// - `self`: node whose grandparent to fetch.
            ///
            /// Returns:
            /// - Grandparent pointer or `null` if none.
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

        /// Creates an empty tree using `allocator`.
        ///
        /// Arguments:
        /// - `allocator`: backing allocator for node storage.
        ///
        /// Returns:
        /// - New empty `Self`.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .root = null,
                .count = 0,
            };
        }

        /// Frees all nodes and resets the tree to empty.
        ///
        /// Arguments:
        /// - `self`: tree to deinitialize.
        ///
        /// Notes:
        /// - Complexity O(n). Traverses and destroys nodes without recursion.
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
                            p.setParentChildRelation(null, Direction.left);
                        } else {
                            p.setParentChildRelation(null, Direction.right);
                        }
                    }

                    c.destroy(self.allocator);
                    current = parent;
                }
            }

            self.root = null;
        }

        /// Returns true if an equal element exists.
        ///
        /// Arguments:
        /// - `self`: tree to query.
        /// - `data`: element to look up.
        ///
        /// Returns:
        /// - `true` if an equal key exists, else `false`.
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

        /// Inserts `data` according to `cmpFn`.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `data`: element to insert.
        ///
        /// Errors:
        /// - `ContainerError.Duplicate` if equal key and `duplicateIsError = true`.
        /// - `std.mem.Allocator.Error` on allocation failure.
        ///
        /// Notes:
        /// - If `duplicateIsError = false`, equal keys go to the left subtree.
        pub fn insert(self: *Self, data: T) !void {
            if (self.root == null) {
                _ = try self.insertAtPtr(null, Direction.left, data);
                return;
            }

            var current: ?*Node = self.root.?;
            var parent: ?*Node = null;
            var dir: Direction = Direction.left;

            while (current) |c| {
                parent = c;
                switch (cmpFn(data, c.data)) {
                    .lt => {
                        dir = Direction.left;
                        current = c.getChild(Direction.left);
                    },
                    .gt => {
                        dir = Direction.right;
                        current = c.getChild(Direction.right);
                    },
                    .eq => {
                        if (duplicateIsError) return ContainerError.Duplicate;
                        dir = Direction.left;
                        current = c.getChild(Direction.left);
                    },
                }
            }

            _ = try self.insertAtPtr(parent.?, dir, data);
        }

        /// Inserts a new node as `parent`’s `dir` child and rebalances if needed.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `parent`: parent under which to insert (null => becomes root).
        /// - `dir`: side under parent to place the node.
        /// - `data`: element to store in the node.
        ///
        /// Returns:
        /// - Pointer to the created node.
        ///
        /// Errors:
        /// - `std.mem.Allocator.Error` on allocation failure.
        pub fn insertAtPtr(self: *Self, parent: ?*Node, dir: Direction, data: T) !*Node {
            const node = try Node.create(self.allocator, data);

            if (parent) |p| {
                std.debug.assert(p.getChild(dir) == null);

                node.color = Color.Red;
                p.setParentChildRelation(node, dir);

                if (p.color == Color.Red) {
                    self.insertFix(node);
                }
            } else {
                node.color = Color.Black;
                self.root = node;
            }
            self.count += 1;
            return node;
        }

        /// Restores red-black invariants after insertion.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `node`: recently inserted node to fix up from.
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

        /// Removes an element equal to `data` and returns the removed value.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `data`: element to remove (by equality under `cmpFn`).
        ///
        /// Returns:
        /// - The removed value of type `T`.
        ///
        /// Errors:
        /// - `ContainerError.NotFound` if no equal element exists.
        pub fn remove(self: *Self, data: T) !T {
            var current: ?*Node = self.root orelse return ContainerError.NotFound;

            while (current) |c| {
                switch (cmpFn(data, c.data)) {
                    .lt => current = c.getChild(Direction.left),
                    .gt => current = c.getChild(Direction.right),
                    .eq => break,
                }
            }

            if (current == null) return ContainerError.NotFound;
            return self.removeFromPtr(current.?);
        }

        /// Removes the node at `target_node` and returns its value.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `target_node`: node to remove (obtained via prior search/traversal).
        ///
        /// Returns:
        /// - The removed value of type `T`.
        ///
        /// Notes:
        /// - Rebalances as needed to maintain red-black invariants.
        pub fn removeFromPtr(self: *Self, target_node: *Node) T {
            self.count -= 1;
            var parent_of_target: ?*Node = target_node.parent;
            const removed_value = target_node.data;

            const has_at_most_one_child =
                (target_node.getChild(.left) == null) or
                (target_node.getChild(.right) == null);

            if (has_at_most_one_child) {
                const non_null_direction: Direction =
                    if (target_node.getChild(.left) == null) Direction.right else Direction.left;
                const child_replacement = target_node.getChild(non_null_direction);

                if (target_node == self.root) {
                    self.root = child_replacement;
                    if (child_replacement) |r| r.parent = null;
                } else {
                    const direction_from_parent: Direction =
                        if (target_node == parent_of_target.?.getChild(.left)) Direction.left else Direction.right;

                    parent_of_target.?.setParentChildRelation(child_replacement, direction_from_parent);

                    if (target_node.color == Color.Black) {
                        if (child_replacement) |r| {
                            if (r.color == Color.Red) r.color = Color.Black;
                        } else {
                            self.removeFix(parent_of_target.?, direction_from_parent);
                        }
                    }
                }

                target_node.destroy(self.allocator);
                return removed_value;
            } else {
                var successor_node: *Node = target_node.getChild(.right).?;
                var parent_of_successor: ?*Node = null;
                while (successor_node.getChild(.left)) |left_child| {
                    parent_of_successor = successor_node;
                    successor_node = left_child;
                }

                const original_color_of_successor = successor_node.color;
                const replacement_subchild: ?*Node = successor_node.getChild(.right);

                if (parent_of_successor) |_| {
                    parent_of_successor.?.setParentChildRelation(replacement_subchild, .left);
                    successor_node.setParentChildRelation(target_node.getChild(.right), .right);
                }

                const parent_ptr = target_node.parent;
                if (parent_ptr) |p| {
                    const direction_to_target: Direction =
                        if (p.getChild(.left) == target_node) Direction.left else Direction.right;
                    p.setParentChildRelation(successor_node, direction_to_target);
                } else {
                    self.root = successor_node;
                    successor_node.parent = null;
                }

                successor_node.setParentChildRelation(target_node.getChild(.left), .left);
                successor_node.color = target_node.color;

                target_node.destroy(self.allocator);

                if (original_color_of_successor == .Black) {
                    const double_black_parent: *Node = if (parent_of_successor) |pos| pos else successor_node;
                    const double_black_side: Direction = if (parent_of_successor != null) Direction.left else Direction.right;
                    if (replacement_subchild) |child| {
                        if (child.color == .Red) {
                            child.color = .Black;
                        } else {
                            self.removeFix(double_black_parent, double_black_side);
                        }
                    } else {
                        self.removeFix(double_black_parent, double_black_side);
                    }
                }

                return removed_value;
            }
        }

        /// Restores invariants after deletion where a black-height deficit exists.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `parent`: parent at which the deficit is observed.
        /// - `which_child`: side of the deficit under `parent`.
        fn removeFix(
            self: *Self,
            parent: *Node,
            which_child: Direction,
        ) void {
            var current_parent = parent;
            var deficit_side = which_child;

            while (true) {
                const deficit_node = current_parent.getChild(deficit_side);

                if (deficit_node) |node_with_deficit| {
                    if (node_with_deficit.color == .Red) {
                        node_with_deficit.color = .Black;
                        break;
                    }
                }

                const sibling_opt = current_parent.getChild(deficit_side.flip());
                if (sibling_opt == null) {
                    if (current_parent.color == .Red) {
                        current_parent.color = Color.Black;
                        break;
                    }
                    const grand_opt = current_parent.parent;
                    if (grand_opt == null) break;
                    const grandparent = grand_opt.?;
                    deficit_side = if (current_parent == grandparent.getChild(.left)) .left else .right;
                    current_parent = grandparent;
                    continue;
                }

                const sibling = sibling_opt.?;
                const near_child = sibling.getChild(deficit_side);
                const far_child = sibling.getChild(deficit_side.flip());

                if (sibling.color == .Red) {
                    self.rotate(current_parent, deficit_side);
                    sibling.color = Color.Black;
                    current_parent.color = Color.Red;
                    continue;
                } else {
                    const far_is_red = if (far_child) |f| f.color == .Red else false;
                    const near_is_red = if (near_child) |n| n.color == .Red else false;

                    if (!far_is_red and !near_is_red) {
                        sibling.color = Color.Red;
                        if (current_parent.color == .Red) {
                            current_parent.color = Color.Black;
                            break;
                        }
                        const grand_opt = current_parent.parent;
                        if (grand_opt == null) break;
                        const grandparent = grand_opt.?;
                        deficit_side = if (current_parent == grandparent.getChild(.left)) .left else .right;
                        current_parent = grandparent;
                        continue;
                    } else if (far_is_red) {
                        sibling.color = current_parent.color;
                        current_parent.color = Color.Black;
                        far_child.?.color = Color.Black;
                        self.rotate(current_parent, deficit_side);
                        break;
                    } else {
                        sibling.color = Color.Red;
                        near_child.?.color = Color.Black;
                        self.rotate(sibling, deficit_side.flip());
                        continue;
                    }
                }
            }

            if (self.root) |root_node| root_node.color = Color.Black;
        }

        /// Single rotation around `pivot`. Direction `d` identifies the deficit side.
        ///
        /// Arguments:
        /// - `self`: target tree.
        /// - `pivot`: node to rotate around.
        /// - `d`: direction of deficit (determines left/right rotation).
        fn rotate(
            self: *Self,
            pivot: *Node,
            d: Direction,
        ) void {
            const new_parent = pivot.getChild(d.flip()).?;

            pivot.setParentChildRelation(new_parent.getChild(d), d.flip());

            new_parent.parent = pivot.parent;
            if (pivot.parent) |p| {
                std.debug.assert(p.getChild(.left) == pivot or p.getChild(.right) == pivot);
                const pivot_direction = if (p.getChild(Direction.left) == pivot) Direction.left else Direction.right;
                p.setParentChildRelation(new_parent, pivot_direction);
            } else {
                self.root = new_parent;
            }

            new_parent.setParentChildRelation(pivot, d);
        }

        /// Finds neighbors of `data` in the order defined by `cmpFn`.
        ///
        /// Arguments:
        /// - `self`: tree to query.
        /// - `data`: key to search around.
        ///
        /// Returns:
        /// - `{ lower, upper }` where:
        ///   - `lower` is the greatest element ≤ `data` (predecessor or equal)
        ///   - `upper` is the least element ≥ `data` (successor or equal)
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

        /// Test helper: asserts structural and value equality between two subtrees.
        ///
        /// Arguments:
        /// - `a`: left subtree root.
        /// - `b`: right subtree root.
        ///
        /// Errors:
        /// - Propagates `std.testing.expect*` errors on mismatch.
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

        /// Test helper: allocate a node with `data = 0` (when `T` is integer-like).
        ///
        /// Arguments:
        /// - `allocator`: allocator for the node.
        ///
        /// Returns:
        /// - Pointer to the created `Node`.
        ///
        /// Errors:
        /// - `std.mem.Allocator.Error` on allocation failure.
        fn testCreateNode(allocator: std.mem.Allocator) !*Node {
            return Node.create(allocator, 0);
        }

        /// Test helper: destroy a node created by `testCreateNode`.
        ///
        /// Arguments:
        /// - `node`: node to destroy.
        /// - `allocator`: allocator that owns the node.
        fn testDestroyNode(node: *Node, allocator: std.mem.Allocator) void {
            Node.destroy(node, allocator);
        }

        /// Validates red-black invariants and returns `(valid, black_height)`.
        ///
        /// Arguments:
        /// - `node`: subtree root to validate (null = leaf).
        /// - `min_val`: strict lower bound (exclusive) for BST ordering, or null.
        /// - `max_val`: strict upper bound (exclusive) for BST ordering, or null.
        ///
        /// Returns:
        /// - `{ valid: bool, black_height: i32 }` where `black_height` is the
        ///   number of black nodes on any path to leaves (including leaf nil).
        ///
        /// Notes:
        /// - On failure, logs a diagnostic dump of the offending node.
        pub fn validateRedBlackTree(
            node: ?*Node,
            min_val: ?T,
            max_val: ?T,
        ) struct {
            valid: bool,
            black_height: i32,
        } {
            if (node == null) return .{ .valid = true, .black_height = 1 };
            const n = node.?;

            const fail = struct {
                fn dump(node_ptr: *Node, reason: []const u8) void {
                    std.debug.print("\n[RBTree Validation Failed]\n", .{});
                    std.debug.print("Reason: {s}\n", .{reason});
                    std.debug.print("Node @ {x}\n", .{@intFromPtr(node_ptr)});
                    std.debug.print("  data = {}\n", .{node_ptr.data});
                    std.debug.print("  color = {s}\n", .{if (node_ptr.color == .Red) "Red" else "Black"});

                    if (node_ptr.parent) |p| {
                        std.debug.print("  parent @ {x}, data = {}\n", .{ @intFromPtr(p), p.data });
                    } else {
                        std.debug.print("  parent = null\n", .{});
                    }
                    if (node_ptr.getChild(.left)) |l| {
                        std.debug.print("  left @ {x}, data = {}\n", .{ @intFromPtr(l), l.data });
                    } else {
                        std.debug.print("  left = null\n", .{});
                    }
                    if (node_ptr.getChild(.right)) |r| {
                        std.debug.print("  right @ {x}, data = {}\n", .{ @intFromPtr(r), r.data });
                    } else {
                        std.debug.print("  right = null\n", .{});
                    }
                }
            };

            // Root must have null parent on the top-level call
            if (min_val == null and max_val == null) {
                if (n.parent != null) {
                    fail.dump(n, "Root has non-null parent");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // ---- Symmetry checks (both directions) ----
            // Upward: if a parent exists, it must reference us as a child.
            if (n.parent) |p| {
                const parent_points_to_us =
                    (p.getChild(.left) == n) or (p.getChild(.right) == n);
                if (!parent_points_to_us) {
                    fail.dump(n, "Parent does not point to this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Downward: any child must have us as its parent.
            if (n.getChild(.left)) |l| {
                if (l.parent != n) {
                    fail.dump(n, "Left child's parent != this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }
            if (n.getChild(.right)) |r| {
                if (r.parent != n) {
                    fail.dump(n, "Right child's parent != this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Invariant: BST property
            if (min_val) |min| {
                if (cmpFn(n.data, min) != .gt) {
                    fail.dump(n, "BST violation: data <= min bound");
                    return .{ .valid = false, .black_height = 0 };
                }
            }
            if (max_val) |max| {
                if (cmpFn(n.data, max) != .lt) {
                    fail.dump(n, "BST violation: data >= max bound");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Invariant: red node never has a red child
            if (n.color == .Red) {
                if (n.getChild(.left)) |left| {
                    if (left.color == .Red) {
                        fail.dump(n, "Red node has red left child");
                        return .{ .valid = false, .black_height = 0 };
                    }
                }
                if (n.getChild(.right)) |right| {
                    if (right.color == .Red) {
                        fail.dump(n, "Red node has red right child");
                        return .{ .valid = false, .black_height = 0 };
                    }
                }
            }

            // Recurse
            const left_result = validateRedBlackTree(n.getChild(.left), min_val, n.data);
            if (!left_result.valid) return left_result;

            const right_result = validateRedBlackTree(n.getChild(.right), n.data, max_val);
            if (!right_result.valid) return right_result;

            // Invariant: equal black height on all descendant paths
            if (left_result.black_height != right_result.black_height) {
                fail.dump(n, "Black height mismatch between children");
                return .{ .valid = false, .black_height = 0 };
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
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const new_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_root, allocator);
    const left_of_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_of_root, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ null, sibling },
        .parent = null,
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
        .color = .Black,
        .children = .{ null, null },
        .parent = new_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 2: black sibling, red far child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
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

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ null, sibling },
        .parent = null,
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
        .children = .{ null, null },
        .parent = new_root,
    };
    far_expected.* = .{
        .data = 20,
        .color = .Black,
        .children = .{ null, null },
        .parent = new_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 3: black sibling, red near child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);
    const near = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(near, allocator);

    const root_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(root_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ null, sibling },
        .parent = null,
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

    root_expected.* = .{
        .data = 12,
        .color = .Black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ null, null },
        .parent = root_expected,
    };
    right_expected.* = .{
        .data = 15,
        .color = .Black,
        .children = .{ null, null },
        .parent = root_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, root_expected);
}

test "removeFix case 4: black sibling, black children" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const sibling_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .Black,
        .children = .{ null, sibling },
        .parent = null,
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
        .children = .{ null, sibling_expected },
        .parent = null,
    };
    sibling_expected.* = .{
        .data = 15,
        .color = .Red,
        .children = .{ null, null },
        .parent = parent_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

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
