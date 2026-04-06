const std = @import("std");
const fuzz = @import("fuzz");
const rbt = @import("red_black_tree");

const RBTree = rbt.RedBlackTree(u64, cmpU64, false);

fn cmpU64(a: u64, b: u64) std.math.Order {
    return std.math.order(a, b);
}

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();

var inserted = std.ArrayListUnmanaged(u64){};
var rng: std.Random.DefaultPrng = undefined;

fn treeInsert(self: *RBTree, key: u64) !void {
    try self.insert(key);
}

fn treeRemove(self: *RBTree, key: u64) !u64 {
    return try self.remove(key);
}

fn treeContains(self: *RBTree, key: u64) bool {
    return self.contains(key);
}

fn treeFindNeighbors(self: *RBTree, key: u64) u64 {
    const result = self.findNeighbors(key);
    return if (result.lower) |l| l else 0;
}

fn insertCallback(key: u64) void {
    inserted.append(dbg_alloc, key) catch {};
}

fn removeKeyGenerator() u64 {
    if (inserted.items.len == 0) return rng.random().int(u64);
    const idx = rng.random().uintLessThan(usize, inserted.items.len);
    return inserted.swapRemove(idx);
}

fn validate(tree: *RBTree) bool {
    const result = RBTree.validateRedBlackTree(tree.root, null, null);
    if (!result.valid) {
        std.debug.print("[RBTree Fuzzer] Invariant violation detected\n", .{});
        return false;
    }

    if (tree.root) |root| {
        if (root.color != .Black) {
            std.debug.print("[RBTree Fuzzer] Root is not black\n", .{});
            return false;
        }
    }

    var actual_count: usize = 0;
    var count_stack: [64]?*RBTree.Node = undefined;
    var stack_top: usize = 0;
    var current: ?*RBTree.Node = tree.root;

    while (current != null or stack_top > 0) {
        while (current) |c| {
            count_stack[stack_top] = c;
            stack_top += 1;
            current = c.getChild(.left);
        }
        if (stack_top == 0) break;
        stack_top -= 1;
        const node = count_stack[stack_top].?;
        actual_count += 1;
        current = node.getChild(.right);
    }

    if (actual_count != tree.count) {
        std.debug.print("[RBTree Fuzzer] Count mismatch: tree.count={} actual={}\n", .{ tree.count, actual_count });
        return false;
    }

    return true;
}

const Fuzzer = fuzz.Fuzzer(RBTree, .{
    .{
        .func = treeInsert,
        .fmt = "insert {*}, {} ->!",
        .callbacks = .{
            .{ .param_idx = 1, .callback = insertCallback },
        },
        .priority = 5,
    },
    .{
        .func = treeRemove,
        .fmt = "remove {*}, {} ->!{}",
        .generators = .{
            .{ .param_idx = 1, .generator = removeKeyGenerator },
        },
        .priority = 4,
    },
    .{
        .func = treeContains,
        .fmt = "contains {*}, {} ->{}",
        .priority = 2,
    },
    .{
        .func = treeFindNeighbors,
        .fmt = "findNeighbors {*}, {} ->{}",
        .priority = 1,
    },
});

pub fn main() !void {
    var iterations: u64 = 100_000;
    var log_path: []const u8 = "fuzz.log";
    var seed: u64 = 0;

    var argsIter = try std.process.ArgIterator.initWithAllocator(dbg_alloc);
    defer argsIter.deinit();

    while (argsIter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-i")) {
            if (argsIter.next()) |iters| iterations = try std.fmt.parseInt(u64, iters, 10);
        } else if (std.mem.eql(u8, arg, "-o")) {
            if (argsIter.next()) |path| log_path = path;
        } else if (std.mem.eql(u8, arg, "-s")) {
            if (argsIter.next()) |s| seed = try std.fmt.parseInt(u64, s, 10);
        }
    }

    rng = std.Random.DefaultPrng.init(seed);

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var tree = RBTree.init(dbg_alloc);
    defer tree.deinit();

    var fuzzer = Fuzzer.init(validate, &tree, seed, &fw.interface);

    std.debug.print("Running red-black tree fuzzer for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        fuzzer.step() catch |err| switch (err) {
            error.NotFound, error.Duplicate => continue,
            error.DetectedInvalidState => {
                std.debug.print("INVARIANT VIOLATION at step {}\n", .{fuzzer.step_idx});
                return err;
            },
            else => return err,
        };
    }

    std.debug.print("Fuzzing complete. {} iterations, no invariant violations.\n", .{iterations});
}
