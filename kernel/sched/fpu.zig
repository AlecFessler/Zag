//! Lazy FPU save/restore.
//!
//! The kernel itself is built without SSE/NEON (see `cpu_features_sub`
//! in build.zig), so user-mode FP/SIMD state survives across syscalls
//! and interrupts untouched in the CPU registers. The eager
//! FXSAVE/FXRSTOR on every syscall entry/exit was deleted from the asm
//! stubs.
//!
//! Per core, `scheduler.last_fpu_owner[core_id]` names the thread whose
//! FP regs are currently in that core's hardware. On every context
//! switch we re-arm the FP-disable trap (CR0.TS on x64, CPACR_EL1.FPEN
//! EL0 bit on aarch64). When a different thread tries to use FP, the
//! arch-specific trap handler calls `handleTrap` here, which:
//!   1. saves the previous owner's regs into `prev.fpu_state` (if any),
//!   2. loads the current thread's regs from `current.fpu_state`,
//!   3. updates `last_fpu_owner[core_id]` and the per-thread
//!      `last_fpu_core` field,
//!   4. clears the trap so the faulting instruction can re-execute.
//!
//! Cross-core migration: if a stolen thread's FP state lives in a
//! different core's registers, the destination core sends an IPI to
//! the source core to flush. See `migrateFlush`.

const build_options = @import("build_options");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const sched = zag.sched.scheduler;

const Thread = zag.sched.thread.Thread;

/// Build-time switch (`-Dlazy_fpu`). When false, the FP-disable trap is
/// never armed and `arch.switchTo` falls back to unconditional eager
/// fpuSave/fpuRestore in `scheduler.switchToWithPmu`. Used for A/B perf
/// comparison; production kernels run with this true.
pub const lazy_enabled: bool = build_options.lazy_fpu;

/// Called from the arch-specific FP-trap handler (#NM on x64,
/// ESR_EL1.EC=0x07 on aarch64). Swaps FPU state ownership on this core
/// from the previous owner (if any) to `current`, then clears the
/// trap. Safe to call with interrupts disabled (which is the natural
/// state inside an exception entry).
pub fn handleTrap(current: *Thread) void {
    const core_id: u8 = @truncate(arch.coreID());

    // Clear the trap FIRST. FXSAVE and FXRSTOR themselves raise #NM
    // when CR0.TS is set (Intel SDM Vol 2A "FXSAVE — Operation"), so
    // calling fpuSave/fpuRestore below with the trap still armed
    // would recursively re-fault and overflow the kernel stack.
    arch.fpuClearTrap();
    sched.fpu_trap_armed[core_id] = false;

    const prev = sched.last_fpu_owner[core_id];
    if (prev) |p| {
        if (p == current) {
            // Same thread re-acquiring on the same core. Regs are
            // still valid — no save, no restore, just leave TS clear.
            return;
        }
        arch.fpuSave(&p.fpu_state);
        p.last_fpu_core = null;
    }

    arch.fpuRestore(&current.fpu_state);
    sched.last_fpu_owner[core_id] = current;
    current.last_fpu_core = core_id;
}

/// IPI handler invoked on the source core when another core needs to
/// take ownership of `thread`'s FPU state across a migration. Saves
/// the regs (if this core still owns them) and clears `last_fpu_owner`
/// so the source core won't try to save them again on its next trap.
///
/// Race: between the requester's `migrateFlush` decision and this
/// handler running, another thread on this core may have caused a #NM
/// and already evicted `thread` (saving it). In that case
/// `last_fpu_owner[core_id] != thread` and we no-op — `thread.fpu_state`
/// is already fresh from the eviction.
pub fn flushIpiHandler(thread: *Thread) void {
    const core_id: u8 = @truncate(arch.coreID());
    if (sched.last_fpu_owner[core_id] == thread) {
        arch.fpuSave(&thread.fpu_state);
        sched.last_fpu_owner[core_id] = null;
    }
    thread.last_fpu_core = null;
}

/// Called from the scheduler when about to run `thread` on the local
/// core, but the thread's FP state may still be in another core's
/// registers (work-stealing migration). Synchronously flushes the
/// state via IPI before the destination core can `fxrstor` from the
/// thread's `fpu_state` buffer.
pub fn migrateFlush(thread: *Thread) void {
    const my_core: u8 = @truncate(arch.coreID());
    const src = thread.last_fpu_core orelse return;
    if (src == my_core) return;
    // The source core may have already evicted `thread` between the
    // load above and the IPI delivery; the IPI handler tolerates that
    // (no-op when last_fpu_owner mismatches). We still always clear
    // last_fpu_core so subsequent migration checks short-circuit.
    arch.fpuFlushIpi(src, thread);
}
