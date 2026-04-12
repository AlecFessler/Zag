const std = @import("std");
const fuzz = @import("fuzz");
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

fn vmmReserve(self: *VirtualMemoryManager, hint_raw: u64) !void {
    const pages = @max(1, (rng.random().int(u16) % 16) + 1);
    const size = @as(u64, pages) * PAGE4K;
    const hint_addr = RANGE_START + (hint_raw % (RANGE_END - RANGE_START - size));
    const hint = VAddr.fromInt(std.mem.alignForward(u64, hint_addr, PAGE4K));

    const rights = VmReservationRights{
        .read = rng.random().boolean(),
        .write = rng.random().boolean(),
        .execute = false,
    };

    const result = self.reserve(hint, size, rights) catch return;
    reservations.append(dbg_alloc, .{ .start = result.vaddr.addr, .size = size }) catch {};
}

fn vmmRevoke(self: *VirtualMemoryManager, idx_raw: u64) !void {
    if (reservations.items.len == 0) return;
    const res = reservations.swapRemove(idx_raw % reservations.items.len);
    self.revokeReservation(VAddr.fromInt(res.start), res.size) catch {};
}

fn vmmPerms(self: *VirtualMemoryManager, idx_raw: u64) !void {
    if (reservations.items.len == 0) return;
    const res = reservations.items[idx_raw % reservations.items.len];

    const max_pages: u8 = @intCast(@max(1, res.size / PAGE4K));
    const offset_pages = rng.random().int(u8) % max_pages;
    const offset: u64 = @as(u64, offset_pages) * PAGE4K;
    const remaining = res.size - offset;
    const sub_pages = @max(1, rng.random().int(u8) % @as(u8, @intCast(@max(1, remaining / PAGE4K))));
    const sub_size: u64 = @as(u64, sub_pages) * PAGE4K;

    self.memPerms(HANDLE_NONE, VAddr.fromInt(res.start), res.size, offset, sub_size, .{
        .read = rng.random().boolean(),
        .write = rng.random().boolean(),
        .execute = rng.random().boolean(),
    }) catch {};
}

fn vmmFindNode(self: *VirtualMemoryManager, addr_raw: u64) !void {
    _ = self.findNode(VAddr.fromInt(RANGE_START + (addr_raw % (RANGE_END - RANGE_START))));
}

fn validate(self: *VirtualMemoryManager) bool {
    const tree_type = @TypeOf(self.tree);
    const tree_result = tree_type.validateRedBlackTree(self.tree.root, null, null);
    if (!tree_result.valid) {
        std.debug.print("[VMM Fuzzer] Red-black tree invariant violation\n", .{});
        return false;
    }

    var prev_end: u64 = 0;
    var node_count: usize = 0;
    var stack: [64]?*tree_type.Node = undefined;
    var top: usize = 0;
    var current = self.tree.root;

    while (current != null or top > 0) {
        while (current) |c| {
            stack[top] = c;
            top += 1;
            current = c.getChild(.left);
        }
        if (top == 0) break;
        top -= 1;
        const node = stack[top].?;
        const vm_node = node.data;
        node_count += 1;

        if (vm_node.size == 0) {
            std.debug.print("[VMM Fuzzer] Zero-size node at {x}\n", .{vm_node.start.addr});
            return false;
        }

        if (vm_node.start.addr < prev_end) {
            std.debug.print("[VMM Fuzzer] Overlapping nodes: prev_end={x} node_start={x}\n", .{ prev_end, vm_node.start.addr });
            return false;
        }

        prev_end = vm_node.end();
        current = node.getChild(.right);
    }

    if (node_count != self.tree.count) {
        std.debug.print("[VMM Fuzzer] Tree count mismatch: expected={} actual={}\n", .{ self.tree.count, node_count });
        return false;
    }

    return true;
}

const Fuzzer = fuzz.Fuzzer(VirtualMemoryManager, .{
    .{ .func = vmmReserve, .fmt = "reserve {*}, {} ->!", .priority = 5 },
    .{ .func = vmmRevoke, .fmt = "revoke {*}, {} ->!", .priority = 3 },
    .{ .func = vmmPerms, .fmt = "perms {*}, {} ->!", .priority = 3 },
    .{ .func = vmmFindNode, .fmt = "findNode {*}, {} ->!", .priority = 2 },
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
    try vmm_mod.initSlabs(dbg_alloc, dbg_alloc);

    var vmm = VirtualMemoryManager.init(VAddr.fromInt(RANGE_START), VAddr.fromInt(RANGE_END), PAddr.fromInt(0));
    defer vmm.deinit();

    const log_file = try std.fs.cwd().createFile(log_path, .{});
    defer log_file.close();
    var buf: [4096]u8 = undefined;
    var fw = log_file.writer(&buf);

    var fuzzer = Fuzzer.init(validate, &vmm, seed, &fw.interface);

    std.debug.print("Running VMM fuzzer for {} iterations (seed={})...\n", .{ iterations, seed });

    for (0..iterations) |_| {
        fuzzer.step() catch |err| switch (err) {
            error.DetectedInvalidState => {
                std.debug.print("INVARIANT VIOLATION at step {}\n", .{fuzzer.step_idx});
                return err;
            },
            else => continue,
        };
    }

    std.debug.print("Fuzzing complete. {} iterations, no invariant violations.\n", .{iterations});
}
