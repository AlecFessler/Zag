const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;

pub const SyscallArgs = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.SyscallArgs,
    .aarch64 => aarch64.interrupts.SyscallArgs,
    else => unreachable,
};

pub const IpcPayloadSnapshot = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.IpcPayloadSnapshot,
    .aarch64 => aarch64.interrupts.IpcPayloadSnapshot,
    else => unreachable,
};

pub fn getSyscallArgs(ctx: *const ArchCpuContext) SyscallArgs {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getSyscallArgs(ctx),
        .aarch64 => aarch64.interrupts.getSyscallArgs(ctx),
        else => unreachable,
    };
}

pub fn getSyscallReturn(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getSyscallReturn(ctx),
        .aarch64 => aarch64.interrupts.getSyscallReturn(ctx),
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

/// Write syscall-return vreg 2 — used by handle-creating syscalls to
/// deliver the new handle's field0 snapshot alongside the slot id in
/// vreg 1. Reuses the same physical reg as `setEventSubcode` (rbx on
/// x86-64; x1 on aarch64) since both ABIs back vreg 2 with the same
/// register; the names disambiguate intent at the call site.
pub fn setSyscallVreg2(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventSubcode(ctx, value),
        .aarch64 => aarch64.interrupts.setEventSubcode(ctx, value),
        else => unreachable,
    }
}

/// Write syscall-return vreg 3 — used by handle-creating syscalls to
/// deliver the new handle's field1 snapshot. Same physical reg as
/// `setEventAddr` (rdx on x86-64; x2 on aarch64); see `setSyscallVreg2`.
pub fn setSyscallVreg3(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventAddr(ctx, value),
        .aarch64 => aarch64.interrupts.setEventAddr(ctx, value),
        else => unreachable,
    }
}

/// Write syscall-return vreg 4 — used by syscalls (e.g. info_system)
/// that surface multi-vreg payloads. Same physical reg as event-state
/// vreg 4 (rbp on x86-64; x3 on aarch64).
pub fn setSyscallVreg4(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventVreg4(ctx, value),
        .aarch64 => aarch64.interrupts.setEventVreg4(ctx, value),
        else => unreachable,
    }
}

/// Write event-state vreg 2 — the per-event-type sub-code (Spec
/// §[event_state]). x86-64: rbx; aarch64: x1.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventSubcode(ctx, value),
        .aarch64 => aarch64.interrupts.setEventSubcode(ctx, value),
        else => unreachable,
    }
}

/// Write event-state vreg 3 — the event-type-specific u64 payload
/// value (faulting address for memory_fault, etc.; Spec §[event_state]).
/// x86-64: rdx; aarch64: x2.
pub fn setEventAddr(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventAddr(ctx, value),
        .aarch64 => aarch64.interrupts.setEventAddr(ctx, value),
        else => unreachable,
    }
}

/// Read event-state vreg 3 from a suspending EC — used to snapshot
/// the sender's GPR-backed vreg 3 at suspend time for propagation
/// through the event delivery (Spec §[event_state] vregs 1..13 = the
/// suspended EC's GPRs). x86-64: rdx; aarch64: x2.
pub fn getEventVreg3(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getEventVreg3(ctx),
        .aarch64 => aarch64.interrupts.getEventVreg3(ctx),
        else => unreachable,
    };
}

/// Write event-state vreg 4 — the suspended EC's GPR-backed vreg 4
/// snapshot delivered to the receiver at recv time per Spec
/// §[event_state]. x86-64: rbp; aarch64: x3.
pub fn setEventVreg4(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventVreg4(ctx, value),
        .aarch64 => aarch64.interrupts.setEventVreg4(ctx, value),
        else => unreachable,
    }
}

/// Read event-state vreg 4 from a suspending EC — companion to
/// `getEventVreg3`.
pub fn getEventVreg4(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getEventVreg4(ctx),
        .aarch64 => aarch64.interrupts.getEventVreg4(ctx),
        else => unreachable,
    };
}

/// Read event-state vreg 5 from a suspending EC — third propagated
/// GPR (alongside vregs 3 and 4). x86-64: rsi; aarch64: x4.
pub fn getEventVreg5(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getEventVreg5(ctx),
        .aarch64 => aarch64.interrupts.getEventVreg5(ctx),
        else => unreachable,
    };
}

/// Write event-state vreg 5 on a receiving EC — companion to
/// `getEventVreg5`.
pub fn setEventVreg5(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setEventVreg5(ctx, value),
        .aarch64 => aarch64.interrupts.setEventVreg5(ctx, value),
        else => unreachable,
    }
}

pub fn getIpcHandle(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getIpcHandle(ctx),
        .aarch64 => aarch64.interrupts.getIpcHandle(ctx),
        else => unreachable,
    };
}

pub fn getIpcMetadata(ctx: *const ArchCpuContext) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getIpcMetadata(ctx),
        .aarch64 => aarch64.interrupts.getIpcMetadata(ctx),
        else => unreachable,
    };
}

pub fn setIpcMetadata(ctx: *ArchCpuContext, value: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.setIpcMetadata(ctx, value),
        .aarch64 => aarch64.interrupts.setIpcMetadata(ctx, value),
        else => unreachable,
    }
}

pub fn getIpcPayloadWords(ctx: *const ArchCpuContext) [5]u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.getIpcPayloadWords(ctx),
        .aarch64 => aarch64.interrupts.getIpcPayloadWords(ctx),
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

pub fn saveIpcPayload(ctx: *const ArchCpuContext) IpcPayloadSnapshot {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.saveIpcPayload(ctx),
        .aarch64 => aarch64.interrupts.saveIpcPayload(ctx),
        else => unreachable,
    };
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, snap: IpcPayloadSnapshot) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.interrupts.restoreIpcPayload(ctx, snap.words),
        .aarch64 => aarch64.interrupts.restoreIpcPayload(ctx, snap.words),
        else => unreachable,
    }
}
