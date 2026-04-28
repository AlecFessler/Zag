//! Lazy FPU save/restore.
//!
//! The kernel itself is built without SSE/NEON (see `cpu_features_sub`
//! in build.zig), so user-mode FP/SIMD state survives across syscalls
//! and interrupts untouched in the CPU registers. There is no eager
//! FXSAVE/FXRSTOR on syscall entry/exit and no save/restore on context
//! switch — eviction happens only when a different EC on the same core
//! actually issues an FP/SIMD instruction and traps the FPU-disabled
//! bit (CR0.TS on x86-64, CPACR_EL1.FPEN on aarch64).
//!
//! Per core, `scheduler.core_states[core_id].last_fpu_owner` names the
//! EC whose FP regs currently live in that core's hardware. The
//! receiving-side bookkeeping in `arm` only writes the trap-arm bit
//! when the new dispatch target differs from this slot, avoiding
//! redundant CR-writes (each costs a vmexit under KVM).
//!
//! Cross-core migration: if a stolen EC's FP state still lives on a
//! different core's registers, the destination core sends an IPI to
//! the source core to FXSAVE into the EC's own buffer and clear its
//! `last_fpu_owner` slot. See `migrateFlush`.
//!
//! Spec §[execution_context] lazy FPU.

const build_options = @import("build_options");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const scheduler = zag.sched.scheduler;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;

/// Build-time switch (`-Dlazy_fpu`). When false, the FP-disable trap is
/// never armed and the scheduler falls back to unconditional eager
/// fpuSave/fpuRestore. Used for A/B perf comparison; production
/// kernels run with this true.
pub const lazy_enabled: bool = build_options.lazy_fpu;

/// Called from the arch-specific FP-trap handler (#NM on x64,
/// ESR_EL1.EC=0x07 on aarch64). Swaps FPU state ownership on this core
/// from the previous owner (if any) to `current`, then clears the
/// trap. Safe to call with interrupts disabled (which is the natural
/// state inside an exception entry).
pub fn handleTrap(current: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    const per_core = &scheduler.core_states[core_id];

    // Clear the trap FIRST. FXSAVE and FXRSTOR themselves raise #NM
    // when CR0.TS is set (Intel SDM Vol 2A "FXSAVE — Operation"), so
    // calling fpuSave/fpuRestore below with the trap still armed
    // would recursively re-fault and overflow the kernel stack.
    arch.cpu.fpuClearTrap();
    per_core.fpu_trap_armed = false;

    if (per_core.last_fpu_owner) |prev_ref| {
        // self-alive: prev FPU owner is either still alive (handle
        // refcount) or being torn down — `last_fpu_core` clear in
        // `flushIpiHandler` keeps this slot consistent.
        const p = prev_ref.ptr;
        if (p == current) {
            // Same EC re-acquiring on the same core. Regs are still
            // valid — no save, no restore, just leave the trap clear.
            return;
        }
        arch.cpu.fpuSave(&p.fpu_state);
        p.last_fpu_core = null;
    }

    arch.cpu.fpuRestore(&current.fpu_state);
    per_core.last_fpu_owner = SlabRef(ExecutionContext).init(current, current._gen_lock.currentGen());
    current.last_fpu_core = core_id;
}

/// IPI handler invoked on the source core when another core needs to
/// take ownership of `ec`'s FPU state across a migration. Saves the
/// regs (if this core still owns them) and clears `last_fpu_owner`
/// so the source core won't try to save them again on its next trap.
///
/// Race: between the requester's `migrateFlush` decision and this
/// handler running, another EC on this core may have caused an
/// FP-disabled trap and already evicted `ec` (saving it). In that
/// case `last_fpu_owner != ec` and we no-op — `ec.fpu_state` is
/// already fresh from the eviction.
pub fn flushIpiHandler(ec: *ExecutionContext) void {
    const core_id: u8 = @truncate(arch.smp.coreID());
    const per_core = &scheduler.core_states[core_id];
    if (per_core.last_fpu_owner) |ref| {
        // self-alive: identity compare on `last_fpu_owner` slot.
        if (ref.ptr == ec) {
            arch.cpu.fpuSave(&ec.fpu_state);
            per_core.last_fpu_owner = null;
        }
    }
    ec.last_fpu_core = null;
}

/// Called from the scheduler when about to dispatch `ec` on the local
/// core, but the EC's FP state may still live in another core's
/// registers (work-stealing migration). Synchronously flushes the
/// state via IPI before the destination core can FXRSTOR from the
/// EC's own `fpu_state` buffer.
pub fn migrateFlush(ec: *ExecutionContext) void {
    const my_core: u8 = @truncate(arch.smp.coreID());
    const src = ec.last_fpu_core orelse return;
    if (src == my_core) return;
    // The source core may have already evicted `ec` between the load
    // above and the IPI delivery; the IPI handler tolerates that
    // (no-op when last_fpu_owner mismatches). We still always clear
    // `last_fpu_core` so subsequent migration checks short-circuit.
    arch.cpu.fpuFlushIpiEc(src, ec);
}

/// Receiver-side dispatch hook — called from the scheduler immediately
/// before resuming `incoming` on the local core. Arms the FPU-disabled
/// trap iff `incoming` is not already this core's `last_fpu_owner`,
/// avoiding a redundant CR-write when an EC is reselected after only
/// a brief preemption. Also tracks `fpu_trap_armed` so the trap
/// handler knows whether the incoming fault is a genuine first-touch
/// or a stale one. Spec §[execution_context] lazy FPU.
pub fn arm(incoming: *ExecutionContext) void {
    if (!lazy_enabled) return;
    const core_id: u8 = @truncate(arch.smp.coreID());
    const per_core = &scheduler.core_states[core_id];
    if (per_core.last_fpu_owner) |ref| {
        // self-alive: identity compare against `incoming` (passed by
        // dispatch path with the slot pinned).
        if (ref.ptr == incoming) {
            // Regs are still valid; leave trap clear so the EC can use
            // FP without faulting.
            if (per_core.fpu_trap_armed) {
                arch.cpu.fpuClearTrap();
                per_core.fpu_trap_armed = false;
            }
            return;
        }
    }
    if (!per_core.fpu_trap_armed) {
        arch.cpu.fpuArmTrap();
        per_core.fpu_trap_armed = true;
    }
}
