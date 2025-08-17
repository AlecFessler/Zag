const std = @import("std");
const libc = @cImport(@cInclude("sched.h"));

const Memory = @import("memory");
const heap_alloc = Memory.HeapAllocator;

const SEED = 0;
const MAX_ALLOC_LEN = 1024;
const HEAP_SIZE = 2 * 1024 * 1024 * 1024;
const ACTIVE_CAP = 16_384;

fn AlignedBlob(comptime N: usize) type {
    return struct { bytes: [N]u8 align(N) };
}

const AllocType = enum {
    const NUM_TYPES = @typeInfo(AllocType).@"enum".fields.len;

    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    U512,
    U1024,

    fn toString(a: AllocType) []const u8 {
        return switch (a) {
            .U8 => "u8",
            .U16 => "u16",
            .U32 => "u32",
            .U64 => "u64",
            .U128 => "u128",
            .U256 => "u256",
            .U512 => "u512",
            .U1024 => "u1024",
        };
    }

    fn alignment(a: AllocType) usize {
        return switch (a) {
            .U8 => @alignOf(u8),
            .U16 => @alignOf(u16),
            .U32 => @alignOf(u32),
            .U64 => @alignOf(u64),
            .U128 => 128,
            .U256 => 256,
            .U512 => 512,
            .U1024 => 1024,
        };
    }

    fn allocate(a: AllocType, len: usize, allocator: std.mem.Allocator) ![*]u8 {
        return switch (a) {
            .U8 => {
                const mem = try allocator.alloc(u8, len);
                return @ptrCast(mem.ptr);
            },
            .U16 => {
                const mem = try allocator.alloc(u16, len);
                return @ptrCast(mem.ptr);
            },
            .U32 => {
                const mem = try allocator.alloc(u32, len);
                return @ptrCast(mem.ptr);
            },
            .U64 => {
                const mem = try allocator.alloc(u64, len);
                return @ptrCast(mem.ptr);
            },
            .U128 => {
                const mem = try allocator.alloc(AlignedBlob(128), len);
                return @ptrCast(mem.ptr);
            },
            .U256 => {
                const mem = try allocator.alloc(AlignedBlob(256), len);
                return @ptrCast(mem.ptr);
            },
            .U512 => {
                const mem = try allocator.alloc(AlignedBlob(512), len);
                return @ptrCast(mem.ptr);
            },
            .U1024 => {
                const mem = try allocator.alloc(AlignedBlob(1024), len);
                return @ptrCast(mem.ptr);
            },
        };
    }

    fn free(a: AllocType, addr: usize, len: usize, allocator: std.mem.Allocator) void {
        if (addr == 0 or len == 0) return;
        switch (a) {
            .U8 => {
                const p: [*]u8 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U16 => {
                const p: [*]u16 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U32 => {
                const p: [*]u32 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U64 => {
                const p: [*]u64 = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U128 => {
                const p: [*]AlignedBlob(128) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U256 => {
                const p: [*]AlignedBlob(256) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U512 => {
                const p: [*]AlignedBlob(512) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
            .U1024 => {
                const p: [*]AlignedBlob(1024) = @ptrFromInt(addr);
                allocator.free(p[0..len]);
            },
        }
    }
};

const AllocHandle = struct { alloc_type: AllocType, len: usize, addr: usize };
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

fn probeTreeDepth(heap: *heap_alloc.HeapAllocator, user_len: usize, user_align: usize) i32 {
    const header_align: u48 = @alignOf(heap_alloc.AllocHeader);
    const key = heap_alloc.TreeEntry{ .bucket_size = @intCast(user_len), .freelist = undefined };

    var node_opt: ?*heap_alloc.RedBlackTree.Node = heap.free_tree.root;
    var candidate: ?*heap_alloc.RedBlackTree.Node = null;

    while (node_opt) |n| {
        const ord = heap_alloc.TreeEntry.cmpFn(n.data, key);
        if (ord == .lt) {
            node_opt = n.getChild(.right);
        } else {
            candidate = n;
            node_opt = n.getChild(.left);
        }
    }

    var cur = candidate;
    var depth: i32 = 0;

    while (cur) |tree_entry| {
        depth += 1;

        var maybe_list_entry: ?*heap_alloc.Freelist.FreeNode = tree_entry.data.freelist.head;
        while (maybe_list_entry) |list_entry| : (maybe_list_entry = list_entry.next) {
            const block_addr: u48 = @intCast(@intFromPtr(list_entry));
            const header_addr: u48 = block_addr - @sizeOf(heap_alloc.AllocHeader);
            const header: *heap_alloc.AllocHeader = @ptrFromInt(header_addr);
            if (!header.is_free) continue;

            const aligned_user = std.mem.alignForward(u48, block_addr, @intCast(user_align));
            const prefix_len = aligned_user - block_addr + 8;

            const postfix_len = std.mem.alignForward(
                u48,
                block_addr + prefix_len + @as(u48, @intCast(user_len)),
                header_align,
            ) - (block_addr + prefix_len + @as(u48, @intCast(user_len)));

            const required_len = prefix_len + @as(u48, @intCast(user_len)) + postfix_len;
            if (required_len <= header.bucket_size) return depth;
        }

        var succ: ?*heap_alloc.RedBlackTree.Node = null;
        if (tree_entry.getChild(.right)) |r| {
            var t = r;
            while (t.getChild(.left)) |l| t = l;
            succ = t;
        } else {
            var p = tree_entry.parent;
            var ch: *heap_alloc.RedBlackTree.Node = tree_entry;
            while (p) |pp| : (p = pp.parent) {
                if (pp.getChild(.left) == ch) {
                    succ = pp;
                    break;
                }
                ch = pp;
            }
        }
        cur = succ;
    }

    return -1;
}

pub fn main() !void {
    try pinToCore(0);

    var dbg_allocator = std.heap.DebugAllocator(.{}){};
    const backing_allocator = dbg_allocator.allocator();
    const backing_mem = try backing_allocator.alignedAlloc(u8, @alignOf(u64), HEAP_SIZE);
    defer backing_allocator.free(backing_mem);

    const reserve_start: u48 = @intCast(@intFromPtr(backing_mem.ptr));
    const reserve_end: u48 = @intCast(reserve_start + backing_mem.len);

    var tree_allocator = try heap_alloc.TreeAllocator.init(backing_allocator);
    defer tree_allocator.deinit();
    var heap_allocator = heap_alloc.HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();
    const heap_iface = heap_allocator.allocator();

    var allocations = std.ArrayList(AllocHandle).init(backing_allocator);
    defer allocations.deinit();

    var prng = std.Random.DefaultPrng.init(SEED);
    var rand = prng.random();

    var file = try std.fs.cwd().createFile("data/heap_latency.csv", .{ .truncate = true });
    defer file.close();
    var bw = std.io.bufferedWriter(file.writer());
    const w = bw.writer();

    try w.print("i,op,type,size,tree_count,from_tree,depth,cycles\n", .{});

    for (0..1_000_000) |i| {
        const action: Action = blk: {
            if (allocations.items.len == 0) break :blk .alloc;
            if (allocations.items.len == ACTIVE_CAP) break :blk .free;
            break :blk @enumFromInt(rand.intRangeAtMost(usize, 0, 1));
        };

        switch (action) {
            .alloc => {
                const at: AllocType = @enumFromInt(rand.intRangeAtMost(
                    usize,
                    0,
                    AllocType.NUM_TYPES - 1,
                ));
                const len = rand.intRangeAtMost(usize, 1, MAX_ALLOC_LEN);
                const depth = probeTreeDepth(
                    &heap_allocator,
                    len,
                    at.alignment(),
                );
                const from_tree = depth != -1;

                const t0 = rdtsc();
                const ptr = try AllocType.allocate(at, len, heap_iface);
                const t1 = rdtsc();

                const cycles = t1 - t0;

                try allocations.append(
                    .{ .alloc_type = at, .addr = @intFromPtr(ptr), .len = len },
                );

                try w.print("{},alloc,{s},{},{},{},{},{}\n", .{
                    i,
                    at.toString(),
                    len,
                    heap_allocator.free_tree.count,
                    from_tree,
                    depth,
                    cycles,
                });
            },
            .free => {
                const idx = rand.intRangeAtMost(
                    usize,
                    0,
                    allocations.items.len - 1,
                );
                const h = allocations.swapRemove(idx);

                const t0 = rdtsc();
                AllocType.free(h.alloc_type, h.addr, h.len, heap_iface);
                const t1 = rdtsc();

                const cycles = t1 - t0;

                try w.print("{},free,{s},{},{},{},{},{}\n", .{
                    i,
                    h.alloc_type.toString(),
                    h.len,
                    heap_allocator.free_tree.count,
                    false,
                    -1,
                    cycles,
                });
            },
        }
    }

    try bw.flush();
}
