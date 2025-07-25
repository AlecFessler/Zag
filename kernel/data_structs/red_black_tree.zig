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
};    

const Direction = enum {    
    left,    
    right,    

    fn opposite(d: Direction) Direction {    
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

    fn sibling(self: *Node) ?*Node {    
        if (self.parent) |p| {    
            return if (self == p.children[.left]) p.children[.right] else p.children[.left];    
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
    var current = self.root;    
    var prev: ?*Node = null;    
    var next: ?*Node = null;    
    while (current) : ({    
        prev = current;    
        current = next;    
    }) {    
        const prevIsParent = current.parent != null and prev == current.parent;    
        const prevIsLeft = current.children[.left] != null and prev == current.children[.left];    

        if (prevIsParent) {    
            if (current.children[.left]) |left| {    
                next = left;    
                continue;    
            } else if (current.children[.right]) |right| {    
                next = right;    
                continue;    
            }    
        } else if (prevIsLeft) {    
            if (current.children[.right]) |right| {    
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
            .lt => current = node.children[.left],    
            .gt => current = node.children[.right],    
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
                .lt => current = c.children[.left],    
                .gt => current = c.children[.right],    
                .eq => {    
                    if (duplicateIsError) return DataStructError.Duplicate;    
                    current = c.children[.left];    
                },    
            }    
        }    

        const node = try Node.create(self.alloctor, data);    
        if (parent) |p| {    
            node.parent = p;    
            if (cmpFn(data, p.data) == .lt) {    
                p.children[.left] = node;    
            } else {    
                p.children[.right] = node;    
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
}    

pub fn remove(self: *Self, data: T) !void {    
    var target: ?*Node = self.root;    

    while (target) |t| {    
        switch (cmpFn(data, t.data)) {    
            .lt => target = t.children[.left],    
            .gt => target = t.children[.right],    
            .eq => break,    
        }    
    } else return DataStructError.NotFound;    

    if (target.?.children[.left] != null and target.?.children[.right] != null) {    
        var successor = target.children[.right].?;    
        while (successor.children[.left]) |left| {    
            successor = left;    
        }    
        target.item = successor.item;    
        target = successor;    
    }    

    const replacement = target.children[.left] orelse target.children[.right];    
    if (replacement) |r| r.parent = target.parent;    

    if (target.parent) |p| {    
        if (target == p.children[.left]) {    
            p.children[.left] = replacement;    
        } else {    
            p.children[.right] = replacement;    
        }    
    } else {    
        self.root = replacement;    
    }    

    if (target.color == .Black) {    
        self.removeFix(replacement, target.parent);    
    }    

    target.destroy(self.allocator);    
}    

fn removeFix(self: *Self, node: ?*Node, parent: ?*Node) void {}    

fn rotateLeft(self: *Self, pivot: *Node) void {    
    const new_root = pivot.children[.right].?;    

    pivot.children[.right] = new_root.children[.left];    
    if (new_root.children[.left]) |subtree| {    
        subtree.parent = pivot;    
    }    

    new_root.parent = pivot.parent;    

    if (pivot.parent) |p| {    
        if (pivot == p.children[.left]) {    
            p.children[.left] = new_root;    
        } else {    
            p.children[.right] = new_root;    
        }    
    } else {    
        self.root = new_root;    
    }    

    new_root.children[.left] = pivot;    
    pivot.parent = new_root;    
}    

fn rotateRight(self: *Self, pivot: *Node) void {    
    const new_root = pivot.children[.left].?;    

    pivot.children[.left] = new_root.children[.right];    
    if (new_root.children[.right]) |subtree| {    
        subtree.parent = pivot;    
    }    

    new_root.parent = pivot.parent;    

    if (pivot.parent) |p| {    
        if (pivot == p.children[.left]) {    
            p.children[.left] = new_root;    
        } else {    
            p.children[.right] = new_root;    
        }    
    } else {    
        self.root = new_root;    
    }    

    new_root.children[.right] = pivot;    
    pivot.parent = new_root;    
}

};

}

