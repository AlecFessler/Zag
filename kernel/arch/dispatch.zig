const aarch64 = @import("aarch64/aarch64.zig");
const builtin = @import("builtin");
const std = @import("std");
const x64 = @import("x64/x64.zig");
const zag = @import("zag");

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const VAddr = zag.memory.address.VAddr;

pub fn init() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.init.init(),
        .aarch64 => aarch64.init.init(),
        else => unreachable,
    }
}

pub fn getAddrSpaceRoot() PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.getAddrSpaceRoot(),
        .aarch64 => return aarch64.paging.getAddrSpaceRoot(),
        else => unreachable,
    }
}

pub fn halt() noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.halt(),
        .aarch64 => aarch64.cpu.halt(),
        else => unreachable,
    }
}

pub fn mapPage(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    allocator: std.mem.Allocator,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.mapPage(addr_space_root, phys, virt, size, perms, allocator),
        .aarch64 => aarch64.paging.mapPage(addr_space_root, phys, virt, size, perms, allocator),
        else => unreachable,
    }
}

pub fn swapAddrSpace(root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.swapAddrSpace(root),
        .aarch64 => aarch64.paging.swapAddrSpace(root),
        else => unreachable,
    }
}

pub fn swapStack(top: VAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.swapStack(top.addr),
        .aarch64 => aarch64.cpu.swapStack(top.addr),
        else => unreachable,
    }
}
