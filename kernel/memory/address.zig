const std = @import("std");
const zag = @import("zag");

const Range = zag.utils.range.Range;

const PAGE4K: u64 = 0x1000;
const PAGE2M: u64 = 0x200000;
const PAGE1G: u64 = 0x40000000;

const MAX_KERNEL_STACKS: u64 = 16384;
pub const KERNEL_STACK_PAGES: u64 = 8;
pub const KERNEL_STACK_SLOT_SIZE: u64 = (KERNEL_STACK_PAGES + 1) * PAGE4K;

const KERNEL_STACKS_RESERVATION: u64 = std.mem.alignForward(u64, MAX_KERNEL_STACKS * KERNEL_STACK_SLOT_SIZE, PAGE1G);
const SLAB_RESERVATION: u64 = 16 * 1024 * 1024;

pub const AddrSpacePartition = struct {
    pub const user: Range = .{
        .start = 0x0000_0000_0000_0000,
        .end = 0xFFFF_8000_0000_0000,
    };
    pub const kernel: Range = .{
        .start = 0xFFFF_8000_0000_0000,
        .end = 0xFFFF_8400_0000_0000,
    };
    pub const physmap: Range = .{
        .start = 0xFFFF_FF80_0000_0000,
        .end = 0xFFFF_FF88_0000_0000,
    };
};

pub const KernelVA = struct {
    pub const kernel_stacks: Range = .{
        .start = AddrSpacePartition.kernel.start,
        .end = AddrSpacePartition.kernel.start + KERNEL_STACKS_RESERVATION,
    };

    pub const KernelAllocators = struct {
        pub const vm_node_slab: Range = .{
            .start = kernel_stacks.end,
            .end = kernel_stacks.end + SLAB_RESERVATION,
        };
        pub const vm_tree_slab: Range = .{
            .start = vm_node_slab.end,
            .end = vm_node_slab.end + SLAB_RESERVATION,
        };
        pub const shm_slab: Range = .{
            .start = vm_tree_slab.end,
            .end = vm_tree_slab.end + SLAB_RESERVATION,
        };
        pub const device_region_slab: Range = .{
            .start = shm_slab.end,
            .end = shm_slab.end + SLAB_RESERVATION,
        };
        pub const heap_tree: Range = .{
            .start = device_region_slab.end,
            .end = device_region_slab.end + PAGE1G,
        };
        pub const heap: Range = .{
            .start = heap_tree.end,
            .end = heap_tree.end + 256 * PAGE1G,
        };

        pub const range: Range = .{
            .start = vm_node_slab.start,
            .end = heap.end,
        };
    };
};

comptime {
    const T = AddrSpacePartition;
    const info = @typeInfo(T).@"struct";
    const decls = info.decls;
    for (decls, 0..) |decl_i, i| {
        const lhs = @field(T, decl_i.name);
        if (@TypeOf(lhs) != Range) continue;
        for (decls[(i + 1)..]) |decl_j| {
            const rhs = @field(T, decl_j.name);
            if (@TypeOf(rhs) != Range) continue;
            if (lhs.overlapsWith(rhs)) {
                @compileError(std.fmt.comptimePrint(
                    "AddrSpacePartition.{s} overlaps with .{s}",
                    .{ decl_i.name, decl_j.name },
                ));
            }
        }
    }

    const K = KernelVA.KernelAllocators;
    const k_info = @typeInfo(K).@"struct";
    const k_decls = k_info.decls;
    for (k_decls, 0..) |decl_i, i| {
        const lhs = @field(K, decl_i.name);
        if (@TypeOf(lhs) != Range) continue;
        if (std.mem.eql(u8, decl_i.name, "range")) continue;
        if (!AddrSpacePartition.kernel.containsRange(lhs)) {
            @compileError(std.fmt.comptimePrint(
                "KernelAllocators.{s} is outside AddrSpacePartition.kernel",
                .{decl_i.name},
            ));
        }
        for (k_decls[(i + 1)..]) |decl_j| {
            const rhs = @field(K, decl_j.name);
            if (@TypeOf(rhs) != Range) continue;
            if (std.mem.eql(u8, decl_j.name, "range")) continue;
            if (lhs.overlapsWith(rhs)) {
                @compileError(std.fmt.comptimePrint(
                    "KernelAllocators.{s} overlaps with .{s}",
                    .{ decl_i.name, decl_j.name },
                ));
            }
        }
    }

    if (!AddrSpacePartition.kernel.containsRange(KernelVA.kernel_stacks)) {
        @compileError("KernelVA.kernel_stacks is outside AddrSpacePartition.kernel");
    }
    if (!AddrSpacePartition.kernel.containsRange(KernelVA.KernelAllocators.range)) {
        @compileError("KernelVA.KernelAllocators.range is outside AddrSpacePartition.kernel");
    }
    if (KernelVA.kernel_stacks.overlapsWith(KernelVA.KernelAllocators.range)) {
        @compileError("KernelVA.kernel_stacks overlaps KernelVA.KernelAllocators");
    }
}

pub const PAddr = extern struct {
    addr: u64,

    pub fn fromInt(addr: u64) PAddr {
        return .{ .addr = addr };
    }

    pub fn fromVAddr(vaddr: VAddr, addr_space_base: ?u64) PAddr {
        const base = blk: {
            if (addr_space_base) |b|
                break :blk b
            else
                break :blk AddrSpacePartition.physmap.start;
        };
        return .{ .addr = vaddr.addr - base };
    }

    pub fn getPtr(self: *const @This(), comptime t: anytype) t {
        return @ptrFromInt(self.addr);
    }
};

pub const VAddr = extern struct {
    addr: u64,

    pub fn fromInt(addr: u64) VAddr {
        return .{ .addr = addr };
    }

    pub fn fromPAddr(paddr: PAddr, addr_space_base: ?u64) VAddr {
        const base = blk: {
            if (addr_space_base) |b|
                break :blk b
            else
                break :blk AddrSpacePartition.physmap.start;
        };
        return .{ .addr = paddr.addr + base };
    }

    pub fn getPtr(self: *const @This(), comptime t: anytype) t {
        return @ptrFromInt(self.addr);
    }
};

pub fn alignStack(stack_top: VAddr) VAddr {
    const aligned = std.mem.alignBackward(u64, stack_top.addr, 16) - 8;
    return VAddr.fromInt(aligned);
}
