const std = @import("std");
const prof = @import("prof");
const heap_mod = @import("heap_allocator");

const HeapAllocator = heap_mod.HeapAllocator;
const TreeAllocator = heap_mod.TreeAllocator;

const HEAP_SIZE = 64 * 1024 * 1024;
const ACTIVE_CAP = 16_384;

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();

var rng: std.Random.DefaultPrng = undefined;
var active_allocs = std.ArrayListUnmanaged(AllocHandle){};

const AllocHandle = struct { addr: u64, size: u64 };

// Small alloc (8-128 bytes) - slab-like objects, most common in kernel
fn heapAllocSmall(self: *HeapAllocator, size_raw: u64) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const size = (size_raw % 120) + 8; // 8-127 bytes
    const ptr = try self.allocator().alloc(u8, size);
    active_allocs.append(dbg_alloc, .{ .addr = @intFromPtr(ptr.ptr), .size = size }) catch return error.OutOfMemory;
}

// Medium alloc (128-1024 bytes) - buffers, strings
fn heapAllocMedium(self: *HeapAllocator, size_raw: u64) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const size = (size_raw % 896) + 128; // 128-1023 bytes
    const ptr = try self.allocator().alloc(u8, size);
    active_allocs.append(dbg_alloc, .{ .addr = @intFromPtr(ptr.ptr), .size = size }) catch return error.OutOfMemory;
}

// Large alloc (1K-16K) - page tables, large structures
fn heapAllocLarge(self: *HeapAllocator, size_raw: u64) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const size = (size_raw % (15 * 1024)) + 1024; // 1K-16K
    const ptr = try self.allocator().alloc(u8, size);
    active_allocs.append(dbg_alloc, .{ .addr = @intFromPtr(ptr.ptr), .size = size }) catch return error.OutOfMemory;
}

// Free - less frequent than allocs, kernel memory tends to accumulate
fn heapFree(self: *HeapAllocator, idx_raw: u64) void {
    if (active_allocs.items.len == 0) return;
    const handle = active_allocs.swapRemove(idx_raw % active_allocs.items.len);
    self.allocator().free(@as([*]u8, @ptrFromInt(handle.addr))[0..handle.size]);
}

const Profiler = prof.Profiler(HeapAllocator, .{
    .{ .func = heapAllocSmall, .fmt = "alloc_small {*}, {} ->!", .priority = 10 },
    .{ .func = heapAllocMedium, .fmt = "alloc_medium {*}, {} ->!", .priority = 4 },
    .{ .func = heapAllocLarge, .fmt = "alloc_large {*}, {} ->!", .priority = 1 },
    .{ .func = heapFree, .fmt = "free {*}, {} ->", .priority = 5 },
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

    const heap_mem = try dbg_alloc.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(8), HEAP_SIZE);
    defer dbg_alloc.free(heap_mem);

    var tree_allocator = try TreeAllocator.init(dbg_alloc);
    defer tree_allocator.deinit();

    var heap = HeapAllocator.init(@intFromPtr(heap_mem.ptr), @intFromPtr(heap_mem.ptr) + HEAP_SIZE, &tree_allocator);
    defer heap.deinit();

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var profiler = try Profiler.init(&heap, seed, &fw.interface);
    defer profiler.deinit();

    std.debug.print("Running heap allocator profiler for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        profiler.step() catch |err| switch (err) {
            error.OutOfMemory => continue,
            else => return err,
        };
    }

    std.debug.print("Profiling complete. {} iterations.\n", .{iterations});
}
