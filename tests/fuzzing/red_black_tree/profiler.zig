const std = @import("std");
const prof = @import("prof");
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

const Profiler = prof.Profiler(RBTree, .{
    .{ .func = treeInsert, .fmt = "insert {*}, {} ->!", .callbacks = .{.{ .param_idx = 1, .callback = insertCallback }}, .priority = 6 },
    .{ .func = treeRemove, .fmt = "remove {*}, {} ->!{}", .generators = .{.{ .param_idx = 1, .generator = removeKeyGenerator }}, .priority = 4 },
    .{ .func = treeContains, .fmt = "contains {*}, {} ->{}", .priority = 1 },
    .{ .func = treeFindNeighbors, .fmt = "findNeighbors {*}, {} ->{}", .priority = 1 },
});

pub fn main() !void {
    var iterations: u64 = 100_000;
    var log_path: []const u8 = "prof.log";
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

    var profiler = try Profiler.init(&tree, seed, &fw.interface);
    defer profiler.deinit();

    std.debug.print("Running red-black tree profiler for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        profiler.step() catch |err| switch (err) {
            error.NotFound, error.Duplicate => continue,
            else => return err,
        };
    }

    std.debug.print("Profiling complete. {} iterations.\n", .{iterations});
}
