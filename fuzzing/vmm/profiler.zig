const std = @import("std");
const prof = @import("prof");
const vmm_mod = @import("vmm");
const address_mod = @import("address");
const perms_mod = @import("perms_permissions");

const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;
const VAddr = address_mod.VAddr;
const PAddr = address_mod.PAddr;
const VmReservationRights = perms_mod.VmReservationRights;
const HANDLE_NONE = vmm_mod.HANDLE_NONE;

const PAGE4K: u64 = 0x1000;
const RANGE_START: u64 = 0x1000_0000;
const RANGE_END: u64 = 0x5000_0000;

var gpa = std.heap.DebugAllocator(.{}).init;
const dbg_alloc = gpa.allocator();
var rng: std.Random.DefaultPrng = undefined;

const Reservation = struct { start: u64, size: u64 };
var reservations = std.ArrayListUnmanaged(Reservation){};

// Reserve - process creation, mmap. Sizes biased toward typical userspace
// mappings: stack (32K), heap region (64K-256K), small mmap (4K-16K)
fn vmmReserve(self: *VirtualMemoryManager, hint_raw: u64) !void {
    const rand = rng.random();
    const bucket = rand.int(u8) % 10;
    const pages: u64 = switch (bucket) {
        0...3 => (rand.int(u8) % 4) + 1, // 4K-16K: small mmaps (40%)
        4...6 => 8, // 32K: stacks (30%)
        7...8 => (rand.int(u8) % 48) + 16, // 64K-256K: heap regions (20%)
        9 => (rand.int(u8) % 4) + 1, // 4K-16K: misc (10%)
        else => unreachable,
    };
    const size = pages * PAGE4K;
    const hint_addr = RANGE_START + (hint_raw % (RANGE_END - RANGE_START - size));
    const hint = VAddr.fromInt(std.mem.alignForward(u64, hint_addr, PAGE4K));

    const result = self.reserve(hint, size, .{ .read = true, .write = true }) catch return;
    reservations.append(dbg_alloc, .{ .start = result.vaddr.addr, .size = size }) catch {};
}

// Page fault lookup - by far the most common VMM operation at runtime
fn vmmFindNode(self: *VirtualMemoryManager, addr_raw: u64) !void {
    if (reservations.items.len == 0) {
        _ = self.findNode(VAddr.fromInt(RANGE_START + (addr_raw % (RANGE_END - RANGE_START))));
        return;
    }
    // Usually we're looking up an address inside an existing reservation (page fault)
    const rand = rng.random();
    if (rand.int(u8) < 230) { // 90% hit an existing reservation
        const res = reservations.items[rand.uintLessThan(usize, reservations.items.len)];
        const offset = rand.uintLessThan(u64, res.size);
        _ = self.findNode(VAddr.fromInt(res.start + offset));
    } else { // 10% miss (segfault path)
        _ = self.findNode(VAddr.fromInt(RANGE_START + (addr_raw % (RANGE_END - RANGE_START))));
    }
}

// mprotect - sub-range permission change, triggers split+merge
fn vmmPerms(self: *VirtualMemoryManager, idx_raw: u64) !void {
    if (reservations.items.len == 0) return;
    const res = reservations.items[idx_raw % reservations.items.len];

    const max_pages: u8 = @intCast(@max(1, res.size / PAGE4K));
    const offset_pages = rng.random().int(u8) % max_pages;
    const offset: u64 = @as(u64, offset_pages) * PAGE4K;
    const remaining = res.size - offset;
    const sub_pages = @max(1, rng.random().int(u8) % @as(u8, @intCast(@max(1, remaining / PAGE4K))));
    const sub_size: u64 = @as(u64, sub_pages) * PAGE4K;

    self.mem_perms(HANDLE_NONE, VAddr.fromInt(res.start), res.size, offset, sub_size, .{
        .read = true,
        .write = rng.random().boolean(),
        .execute = rng.random().boolean(),
    }) catch {};
}

// munmap / process exit - least common
fn vmmRevoke(self: *VirtualMemoryManager, idx_raw: u64) !void {
    if (reservations.items.len == 0) return;
    const res = reservations.swapRemove(idx_raw % reservations.items.len);
    self.revokeReservation(VAddr.fromInt(res.start), res.size) catch {};
}

const Profiler = prof.Profiler(VirtualMemoryManager, .{
    .{ .func = vmmFindNode, .fmt = "findNode {*}, {} ->!", .priority = 20 },
    .{ .func = vmmReserve, .fmt = "reserve {*}, {} ->!", .priority = 5 },
    .{ .func = vmmPerms, .fmt = "perms {*}, {} ->!", .priority = 2 },
    .{ .func = vmmRevoke, .fmt = "revoke {*}, {} ->!", .priority = 1 },
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
    try vmm_mod.initSlabs(dbg_alloc, dbg_alloc);

    var vmm = VirtualMemoryManager.init(VAddr.fromInt(RANGE_START), VAddr.fromInt(RANGE_END), PAddr.fromInt(0));
    defer vmm.deinit();

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var profiler = try Profiler.init(&vmm, seed, &fw.interface);
    defer profiler.deinit();

    std.debug.print("Running VMM profiler for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        profiler.step() catch continue;
    }

    std.debug.print("Profiling complete. {} iterations.\n", .{iterations});
}
