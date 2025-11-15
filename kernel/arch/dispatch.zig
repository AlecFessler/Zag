const aarch64 = @import("aarch64/aarch64.zig");
const builtin = @import("builtin");
const std = @import("std");
const x64 = @import("x64/x64.zig");
const zag = @import("zag");

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub fn init() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.init.init(),
        .aarch64 => aarch64.init.init(),
        else => unreachable,
    }
}

pub fn getAddrSpaceRoot() VAddr {
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
