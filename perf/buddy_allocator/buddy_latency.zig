const std = @import("std");
const libc = @cImport(@cInclude("sched.h"));

const Memory = @import("memory");
const buddy_alloc = Memory.BuddyAllocator;

const PAGE_SIZE = 4096;
const NUM_ORDERS = 11;
const ORDERS = blk: {
    var arr: [NUM_ORDERS]usize = undefined;
    for (0..NUM_ORDERS) |i| arr[i] = (1 << i) * PAGE_SIZE;
    break :blk arr;
};

const SEED = 0;
const ACTIVE_CAP = 16_384;
const ORDER10_BLOCKS = 8;
const POOL_SIZE = ORDER10_BLOCKS * ORDERS[10];

const AllocType = enum {
    const NUM_TYPES = @typeInfo(AllocType).@"enum".fields.len;

    O0,
    O1,
    O2,
    O3,
    O4,
    O5,
    O6,
    O7,
    O8,
    O9,
    O10,

    fn toString(a: AllocType) []const u8 {
        return switch (a) {
            .O0 => "o0",
            .O1 => "o1",
            .O2 => "o2",
            .O3 => "o3",
            .O4 => "o4",
            .O5 => "o5",
            .O6 => "o6",
            .O7 => "o7",
            .O8 => "o8",
            .O9 => "o9",
            .O10 => "o10",
        };
    }

    fn idx(a: AllocType) usize {
        return switch (a) {
            .O0 => 0,
            .O1 => 1,
            .O2 => 2,
            .O3 => 3,
            .O4 => 4,
            .O5 => 5,
            .O6 => 6,
            .O7 => 7,
            .O8 => 8,
            .O9 => 9,
            .O10 => 10,
        };
    }

    fn size(a: AllocType) usize {
        return ORDERS[a.idx()];
    }

    fn allocate(a: AllocType, allocator: std.mem.Allocator) ![*]u8 {
        const mem = try allocator.alloc(u8, a.size());
        return @ptrCast(mem.ptr);
    }

    fn free(a: AllocType, addr: usize, allocator: std.mem.Allocator) void {
        if (addr == 0) return;
        const p: [*]u8 = @ptrFromInt(addr);
        allocator.free(p[0..a.size()]);
    }
};

const AllocHandle = struct { alloc_type: AllocType, addr: usize };
const Action = enum { alloc, free };

pub fn rdtsc() u64 {
    var t: u64 = 0;
    asm volatile (
        \\ lfence
        \\ rdtsc
        \\ shl $32, %rdx
        \\ or %rdx, %rax
        : [tsc] "={rax}" (t),
        :
        : "rdx", "cc", "memory"
    );
    return t;
}

fn cpu_zero(set: *libc.cpu_set_t) void {
    const bytes: [*]u8 = @ptrCast(set);
    const slice: []u8 = bytes[0..@sizeOf(libc.cpu_set_t)];
    @memset(slice, 0);
}

fn cpu_set_bit(cpu: usize, set: *libc.cpu_set_t) void {
    const words: [*]usize = @ptrCast(set);
    const bits_per_word: usize = @sizeOf(usize) * 8;
    const idx: usize = cpu / bits_per_word;
    const bit_usize: usize = cpu % bits_per_word;
    const shift: u6 = @intCast(bit_usize);
    words[idx] |= (@as(usize, 1) << shift);
}

fn pinToCore(core: usize) !void {
    var mask: libc.cpu_set_t = undefined;
    cpu_zero(&mask);
    cpu_set_bit(core, &mask);
    const rc: usize = std.os.linux.syscall3(
        .sched_setaffinity,
        0,
        @as(usize, @sizeOf(libc.cpu_set_t)),
        @intFromPtr(&mask),
    );
    if (@as(isize, @bitCast(rc)) < 0) return error.FailedToPin;
}

fn probeSplits(buddy: *buddy_alloc.BuddyAllocator, order: u4) i32 {
    const base: usize = order;
    var o: usize = base;
    while (o < NUM_ORDERS and buddy.freelists[o].head == null) : (o += 1) {}
    if (o >= NUM_ORDERS) return -1;
    return @intCast(o - base);
}

pub fn main() !void {
    try pinToCore(0);

    var dbg_allocator = std.heap.DebugAllocator(.{}){};
    const backing_allocator = dbg_allocator.allocator();

    const backing_mem = try backing_allocator.alignedAlloc(u8, ORDERS[10], POOL_SIZE);
    defer backing_allocator.free(backing_mem);

    const start_addr = @intFromPtr(backing_mem.ptr);
    const end_addr = start_addr + backing_mem.len;

    var buddy = try buddy_alloc.BuddyAllocator.init(start_addr, end_addr, backing_allocator);
    defer buddy.deinit();
    const buddy_iface = buddy.allocator();

    var handles = std.ArrayList(AllocHandle).init(backing_allocator);
    defer handles.deinit();

    var prng = std.Random.DefaultPrng.init(SEED);
    var rand = prng.random();

    var file = try std.fs.cwd().createFile("data/buddy_latency.csv", .{ .truncate = true });
    defer file.close();
    var bw = std.io.bufferedWriter(file.writer());
    const w = bw.writer();

    try w.print("i,op,type,size,splits,cycles\n", .{});

    for (0..1_000_000) |i| {
        const action: Action = blk: {
            if (handles.items.len == 0) break :blk .alloc;
            if (handles.items.len == ACTIVE_CAP) break :blk .free;
            break :blk @enumFromInt(rand.intRangeAtMost(usize, 0, 1));
        };

        switch (action) {
            .alloc => {
                const at: AllocType = @enumFromInt(rand.intRangeAtMost(usize, 0, AllocType.NUM_TYPES - 1));
                const order: u4 = @intCast(at.idx());
                const splits = probeSplits(&buddy, order);

                const t0 = rdtsc();
                const ptr = AllocType.allocate(at, buddy_iface) catch {
                    continue;
                };
                const t1 = rdtsc();
                const cycles = t1 - t0;

                try handles.append(.{ .alloc_type = at, .addr = @intFromPtr(ptr) });

                try w.print("{},alloc,{s},{},{},{}\n", .{
                    i,
                    at.toString(),
                    at.size(),
                    splits,
                    cycles,
                });
            },
            .free => {
                const idx = rand.intRangeAtMost(usize, 0, handles.items.len - 1);
                const h = handles.swapRemove(idx);

                const t0 = rdtsc();
                AllocType.free(h.alloc_type, h.addr, buddy_iface);
                const t1 = rdtsc();
                const cycles = t1 - t0;

                try w.print("{},free,{s},{},{},{}\n", .{
                    i,
                    h.alloc_type.toString(),
                    h.alloc_type.size(),
                    -1,
                    cycles,
                });
            },
        }
    }

    try bw.flush();
}
