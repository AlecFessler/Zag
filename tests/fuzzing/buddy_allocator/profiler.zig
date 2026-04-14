const std = @import("std");
const prof = @import("prof");
const buddy_mod = @import("buddy_allocator");

const BuddyAllocator = buddy_mod.BuddyAllocator;
const FreeListBatch = buddy_mod.FreeListBatch;

const PAGE_SIZE = 4096;
const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]u64 = undefined;
    for (0..NUM_ORDERS) |i| arr[i] = (1 << i) * PAGE_SIZE;
    break :blk arr;
};

const ORDER10_BLOCKS = 8;
const POOL_SIZE = ORDER10_BLOCKS * ORDERS[10];

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();

var backing_memory: []align(PAGE_SIZE) u8 = undefined;
var single_pages = std.ArrayListUnmanaged(u64){};
var large_allocs = std.ArrayListUnmanaged(LargeAlloc){};
var rng: std.Random.DefaultPrng = undefined;

const LargeAlloc = struct { addr: u64, order: u4 };

// Single page alloc - the dominant real-world pattern
fn allocSinglePage(self: *BuddyAllocator, _: u8) !void {
    const ptr = try self.allocator().alloc(u8, PAGE_SIZE);
    single_pages.append(dbg_alloc, @intFromPtr(ptr.ptr)) catch return error.OutOfMemory;
}

// Free a single page
fn freeSinglePage(self: *BuddyAllocator, idx_raw: u64) void {
    if (single_pages.items.len == 0) return;
    const addr = single_pages.swapRemove(idx_raw % single_pages.items.len);
    const slice: []u8 = @as([*]u8, @ptrFromInt(addr))[0..PAGE_SIZE];
    self.allocator().free(@as([]align(PAGE_SIZE) u8, @alignCast(slice)));
}

// Large alloc then bulk split to pages - how the kernel provisions regions
fn allocAndSplit(self: *BuddyAllocator, order_raw: u8) !void {
    const order: u4 = @intCast(@max(1, (order_raw % 6) + 1)); // orders 1-6
    const size = ORDERS[order];
    const ptr = try self.allocator().alloc(u8, size);
    const addr = @intFromPtr(ptr.ptr);
    var batch = self.splitAllocation(addr, 0);
    while (batch.pop()) |page| {
        single_pages.append(dbg_alloc, @intFromPtr(page)) catch {};
    }
}

const Profiler = prof.Profiler(BuddyAllocator, .{
    .{ .func = allocSinglePage, .fmt = "alloc_page {*}, {} ->!", .priority = 10 },
    .{ .func = freeSinglePage, .fmt = "free_page {*}, {} ->", .priority = 8 },
    .{ .func = allocAndSplit, .fmt = "alloc_split {*}, {} ->!", .priority = 2 },
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

    backing_memory = try dbg_alloc.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(PAGE_SIZE), POOL_SIZE);
    defer dbg_alloc.free(backing_memory);

    const start_addr = @intFromPtr(backing_memory.ptr);
    var buddy = try BuddyAllocator.init(start_addr, start_addr + POOL_SIZE, dbg_alloc);
    defer buddy.deinit();
    buddy.addRegion(start_addr, start_addr + POOL_SIZE);

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var profiler = try Profiler.init(&buddy, seed, &fw.interface);
    defer profiler.deinit();

    std.debug.print("Running buddy allocator profiler for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        profiler.step() catch |err| switch (err) {
            error.OutOfMemory => continue,
            else => return err,
        };
    }

    std.debug.print("Profiling complete. {} iterations.\n", .{iterations});
}
