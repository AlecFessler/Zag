const std = @import("std");
const zag = @import("zag");

const Range = zag.utils.range.Range;

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
        const phys = vaddr.addr - base;
        return .{ .addr = phys };
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
        const virt = paddr.addr + base;
        return .{ .addr = virt };
    }

    pub fn getPtr(self: *const @This(), comptime t: anytype) t {
        return @ptrFromInt(self.addr);
    }
};

pub fn alignStack(stack_top: VAddr) VAddr {
    const aligned = std.mem.alignBackward(u64, stack_top.addr, 16) - 8;
    return VAddr.fromInt(aligned);
}
