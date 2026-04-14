const std = @import("std");
const fuzz = @import("fuzz");
const buddy_mod = @import("buddy_allocator");

const BuddyAllocator = buddy_mod.BuddyAllocator;

const PAGE_SIZE = 4096;
const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]u64 = undefined;
    for (0..NUM_ORDERS) |i| arr[i] = (1 << i) * PAGE_SIZE;
    break :blk arr;
};

const ORDER10_BLOCKS = 8;
const POOL_SIZE = ORDER10_BLOCKS * ORDERS[10];
const ACTIVE_CAP = 16_384;

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();

var backing_memory: []align(PAGE_SIZE) u8 = undefined;
var allocations = BuddyAllocator.AllocationMap.init(dbg_alloc);
var active_allocs = std.ArrayListUnmanaged(AllocHandle){};
var rng: std.Random.DefaultPrng = undefined;

const AllocHandle = struct { addr: u64, size: u64, order: u4 };

fn buddyAllocOrder(self: *BuddyAllocator, order_raw: u8) !void {
    if (active_allocs.items.len >= ACTIVE_CAP) return;
    const order: u4 = @intCast(order_raw % NUM_ORDERS);
    const size = ORDERS[order];
    const allocator = self.allocator();
    const ptr = try allocator.alloc(u8, size);
    const addr = @intFromPtr(ptr.ptr);
    allocations.put(addr, .{ .size = size, .order = order }) catch return error.OutOfMemory;
    active_allocs.append(dbg_alloc, .{ .addr = addr, .size = size, .order = order }) catch return error.OutOfMemory;
}

fn buddyFree(self: *BuddyAllocator, idx_raw: u64) void {
    if (active_allocs.items.len == 0) return;
    const idx = idx_raw % active_allocs.items.len;
    const handle = active_allocs.swapRemove(idx);
    _ = allocations.remove(handle.addr);
    const allocator = self.allocator();
    const slice: []u8 = @as([*]u8, @ptrFromInt(handle.addr))[0..handle.size];
    allocator.free(@as([]align(PAGE_SIZE) u8, @alignCast(slice)));
}

fn buddyAllocAndFree(self: *BuddyAllocator, order_raw: u8) !void {
    const order: u4 = @intCast(order_raw % NUM_ORDERS);
    const size = ORDERS[order];
    const allocator = self.allocator();
    const ptr = try allocator.alloc(u8, size);
    allocator.free(@as([]align(PAGE_SIZE) u8, @alignCast(ptr)));
}

fn validate(self: *BuddyAllocator) bool {
    return self.validateState(&allocations);
}

const Fuzzer = fuzz.Fuzzer(BuddyAllocator, .{
    .{ .func = buddyAllocOrder, .fmt = "alloc {*}, {} ->!", .priority = 5 },
    .{ .func = buddyFree, .fmt = "free {*}, {} ->", .priority = 4 },
    .{ .func = buddyAllocAndFree, .fmt = "alloc_free {*}, {} ->!", .priority = 2 },
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

    backing_memory = try dbg_alloc.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(PAGE_SIZE), POOL_SIZE);
    defer dbg_alloc.free(backing_memory);

    const start_addr = @intFromPtr(backing_memory.ptr);
    const end_addr = start_addr + POOL_SIZE;

    var buddy = try BuddyAllocator.init(start_addr, end_addr, dbg_alloc);
    defer buddy.deinit();
    buddy.addRegion(start_addr, end_addr);

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var fuzzer = Fuzzer.init(validate, &buddy, seed, &fw.interface);

    std.debug.print("Running buddy allocator fuzzer for {} iterations (seed={})...\n", .{ iterations, seed });

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
