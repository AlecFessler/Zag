const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const Thread = zag.sched.thread.Thread;

// --- Lazy FPU dispatch ---
//
// User-mode FP/SIMD state is owned by exactly one thread per core at a
// time (`scheduler.last_fpu_owner[core]`). When the kernel switches to
// a different thread it arms a trap; when that thread first touches
// FP, the arch-specific exception handler calls into `sched.fpu` to
// swap state. These wrappers are the arch-specific primitives that
// machinery uses.

/// Initialise an FPU buffer to the architectural reset state for a
/// brand-new thread (FCW/MXCSR defaults on x64; FPCR/FPSR defaults
/// on aarch64). Called once from `Thread.create`.
pub fn fpuStateInit(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuStateInit(area),
        .aarch64 => aarch64.cpu.fpuStateInit(area),
        else => unreachable,
    }
}

/// Save the current core's FP/SIMD register file into `area`.
/// `area` must be 64-byte aligned and at least 576 bytes (FXSAVE format
/// on x64; V0-V31 + FPCR + FPSR on aarch64).
pub fn fpuSave(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuSave(area),
        .aarch64 => aarch64.cpu.fpuSave(area),
        else => unreachable,
    }
}

/// Restore the FP/SIMD register file from `area`. Same alignment and
/// format requirements as `fpuSave`.
pub fn fpuRestore(area: *[576]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuRestore(area),
        .aarch64 => aarch64.cpu.fpuRestore(area),
        else => unreachable,
    }
}

/// Re-enable user-mode FP access on the local core after a trap was
/// serviced. x64: clear CR0.TS via CLTS. aarch64: set CPACR_EL1.FPEN
/// to 0b11 (EL0 and EL1 both allowed).
pub fn fpuClearTrap() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuClearTrap(),
        .aarch64 => aarch64.cpu.fpuClearTrap(),
        else => unreachable,
    }
}

/// Arm the FP-disable trap on the local core so the next user-mode FP
/// access raises #NM (x64) / EC=0x07 (aarch64). Called from switchTo
/// at every context switch out.
pub fn fpuArmTrap() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuArmTrap(),
        .aarch64 => aarch64.cpu.fpuArmTrap(),
        else => unreachable,
    }
}

/// Synchronously flush `thread`'s FP state from the source core's
/// registers into `thread.fpu_state`. Called by the destination core
/// when work-stealing has migrated `thread` and a subsequent
/// `fpuRestore` would otherwise read stale buffer contents. Sends an
/// IPI and spins until the source core acknowledges.
pub fn fpuFlushIpi(target_core: u8, thread: *Thread) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.fpuFlushIpi(target_core, thread),
        .aarch64 => aarch64.cpu.fpuFlushIpi(target_core, thread),
        else => unreachable,
    }
}
