const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;

pub const SyscallArgs = struct {
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
};

pub fn getSyscallArgs(ctx: *const ArchCpuContext) SyscallArgs {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{
            .num = ctx.regs.rax,
            .arg0 = ctx.regs.rdi,
            .arg1 = ctx.regs.rsi,
            .arg2 = ctx.regs.rdx,
            .arg3 = ctx.regs.r10,
            .arg4 = ctx.regs.r8,
        },
        .aarch64 => .{
            .num = ctx.regs.x8,
            .arg0 = ctx.regs.x0,
            .arg1 = ctx.regs.x1,
            .arg2 = ctx.regs.x2,
            .arg3 = ctx.regs.x3,
            .arg4 = ctx.regs.x4,
        },
        else => unreachable,
    };
}

pub fn getSyscallReturn(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.rax,
        .aarch64 => ctx.regs.x0,
        else => unreachable,
    };
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setSyscallReturn(ctx, value),
        .aarch64 => aarch64.interrupts.setSyscallReturn(ctx, value),
        else => unreachable,
    }
}

pub fn getIpcHandle(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r13,
        .aarch64 => ctx.regs.x5,
        else => unreachable,
    };
}

pub fn getIpcMetadata(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r14,
        .aarch64 => ctx.regs.x6,
        else => unreachable,
    };
}

pub fn setIpcMetadata(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => ctx.regs.r14 = value,
        .aarch64 => ctx.regs.x6 = value,
        else => unreachable,
    }
}

pub fn getIpcPayloadWords(ctx: *const ArchCpuContext) [5]u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ ctx.regs.rdi, ctx.regs.rsi, ctx.regs.rdx, ctx.regs.r8, ctx.regs.r9 },
        .aarch64 => .{ ctx.regs.x0, ctx.regs.x1, ctx.regs.x2, ctx.regs.x3, ctx.regs.x4 },
        else => unreachable,
    };
}

pub fn copyIpcPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.copyIpcPayload(dst, src, word_count),
        .aarch64 => aarch64.interrupts.copyIpcPayload(dst, src, word_count),
        else => unreachable,
    };
}

pub const IpcPayloadSnapshot = struct { words: [5]u64 };

pub fn saveIpcPayload(ctx: *const ArchCpuContext) IpcPayloadSnapshot {
    return .{ .words = getIpcPayloadWords(ctx) };
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, snap: IpcPayloadSnapshot) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.restoreIpcPayload(ctx, snap.words),
        .aarch64 => aarch64.interrupts.restoreIpcPayload(ctx, snap.words),
        else => unreachable,
    }
}
