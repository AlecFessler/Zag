const std = @import("std");
const fuzz = @import("fuzz");
const heap_mod = @import("heap_allocator");

const HeapAllocator = heap_mod.HeapAllocator;
const TreeAllocator = heap_mod.TreeAllocator;

const HEAP_SIZE = 64 * 1024 * 1024;
const MAX_ALLOC_LEN = 1024;
const ACTIVE_CAP = 16_384;

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();

var rng: std.Random.DefaultPrng = undefined;
var active_allocs = std.ArrayListUnmanaged(AllocHandle){};

const AllocHandle = struct { addr: u64, size: u64 };

fn heapAlloc(self: *HeapAllocator, size_raw: u64) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const size = @max(1, (size_raw % MAX_ALLOC_LEN) + 1);
    const ptr = try self.allocator().alloc(u8, size);
    active_allocs.append(dbg_alloc, .{ .addr = @intFromPtr(ptr.ptr), .size = size }) catch return error.OutOfMemory;
}

fn heapFree(self: *HeapAllocator, idx_raw: u64) void {
    if (active_allocs.items.len == 0) return;
    const idx = idx_raw % active_allocs.items.len;
    const handle = active_allocs.swapRemove(idx);
    self.allocator().free(@as([*]u8, @ptrFromInt(handle.addr))[0..handle.size]);
}

fn heapAllocAndFree(self: *HeapAllocator, size_raw: u64) !void {
    const size = @max(1, (size_raw % MAX_ALLOC_LEN) + 1);
    const allocator = self.allocator();
    const ptr = try allocator.alloc(u8, size);
    allocator.free(ptr);
}

fn heapAllocAligned(self: *HeapAllocator, size_raw: u64) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const size = @max(64, (size_raw % MAX_ALLOC_LEN) + 1);
    const allocator = self.allocator();
    const ptr = try allocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(64), size);
    active_allocs.append(dbg_alloc, .{ .addr = @intFromPtr(ptr.ptr), .size = size }) catch {
        allocator.free(ptr);
        return error.OutOfMemory;
    };
}

fn validate(self: *HeapAllocator) bool {
    return self.validateState(dbg_alloc);
}

const Fuzzer = fuzz.Fuzzer(HeapAllocator, .{
    .{ .func = heapAlloc, .fmt = "alloc {*}, {} ->!", .priority = 5 },
    .{ .func = heapFree, .fmt = "free {*}, {} ->", .priority = 4 },
    .{ .func = heapAllocAndFree, .fmt = "alloc_free {*}, {} ->!", .priority = 2 },
    .{ .func = heapAllocAligned, .fmt = "alloc_aligned {*}, {} ->!", .priority = 2 },
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

    var fuzzer = Fuzzer.init(validate, &heap, seed, &fw.interface);

    std.debug.print("Running heap allocator fuzzer for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        fuzzer.step() catch |err| switch (err) {
            error.OutOfMemory => continue,
            error.DetectedInvalidState => {
                std.debug.print("INVARIANT VIOLATION at step {}\n", .{fuzzer.step_idx});
                return err;
            },
            else => return err,
        };
    }

    std.debug.print("Fuzzing complete. {} iterations, no invariant violations.\n", .{iterations});
}
