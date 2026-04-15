//! ARM Generic Timer driver.
//!
//! The ARM Generic Timer is a mandatory architectural feature that provides
//! high-resolution monotonic timekeeping and per-core timer interrupts.
//! It replaces both x86's TSC (for timestamps) and LAPIC timer / HPET
//! (for preemption / monotonic clock).
//!
//! Timer registers (ARM ARM D11.2):
//!   CNTFRQ_EL0:     counter frequency in Hz (set by firmware, read-only to OS)
//!   CNTVCT_EL0:     virtual counter value (monotonically increasing, read-only)
//!   CNTPCT_EL0:     physical counter value
//!   CNTP_CTL_EL0:   physical timer control (ENABLE, IMASK, ISTATUS)
//!   CNTP_CVAL_EL0:  physical timer comparator value (fire when CNTPCT >= CVAL)
//!   CNTP_TVAL_EL0:  physical timer countdown value (sets CVAL = CNTPCT + TVAL)
//!   CNTV_CTL_EL0:   virtual timer control
//!   CNTV_CVAL_EL0:  virtual timer comparator value
//!   CNTV_TVAL_EL0:  virtual timer countdown value
//!
//! Which timer to use:
//! - Preemption: EL1 physical timer (CNTP_*, INTID 30). Works both
//!   bare-metal and under KVM. Pi 5 KVM vGICv2 drops CNTV injections
//!   to secondary vCPUs once they run EL0, so CNTV (INTID 27) is
//!   unsafe as a per-core preemption source (see writeCntpTval docs).
//! - Timestamp reads: CNTVCT_EL0 (virtual counter) — still always
//!   safe to read; its behaviour is independent of the CNTV interrupt.
//!
//! Timer interrupt: PPI 30 (physical). The GIC must be configured to
//! route this to the exception handler. When the timer fires, the
//! handler calls the scheduler's preemption logic.
//!
//! Tick → nanosecond conversion:
//!   ns = ticks * 1_000_000_000 / CNTFRQ_EL0
//! Use the arch/timer.zig nanosFromTicksFloor / ticksFromNanosCeil helpers
//! with freq = CNTFRQ_EL0.
//!
//! Dispatch interface mapping:
//!   getPreemptionTimer()  → Timer backed by CNTP_CVAL_EL0 (arm interrupt at deadline)
//!   getMonotonicClock()   → Timer backed by CNTVCT_EL0 (read-only clock source)
//!   readTimestamp()       → MRS CNTVCT_EL0
//!
//! References:
//! - ARM ARM D11.2: The Generic Timer
//! - ARM ARM D13.8: Generic Timer registers

const zag = @import("zag");

const cpu = zag.arch.aarch64.cpu;
const timer_mod = zag.arch.timer;

const Timer = zag.arch.timer.Timer;

var preemption_timer_instance: PreemptionTimer = undefined;
var monotonic_clock_instance: MonotonicClock = undefined;
var cached_freq_hz: u64 = 0;

/// Read CNTFRQ_EL0 — the counter frequency set by firmware.
/// ARM ARM D13.8.1: CNTFRQ_EL0, Counter-timer Frequency register.
inline fn readCntfrq() u64 {
    var freq: u64 = undefined;
    asm volatile ("mrs %[freq], cntfrq_el0"
        : [freq] "=r" (freq),
    );
    return freq;
}

/// Write CNTP_TVAL_EL0 — physical timer 32-bit downcounter.
///
/// We use the EL1 physical timer (PPI 30) for scheduler preemption
/// rather than the virtual timer (PPI 27). Both are architecturally
/// usable from EL1 once CNTHCTL_EL2.{EL1PCEN,EL1PCTEN} are set (done
/// by the bootloader EL2→EL1 drop and by the secondary-CPU EL2→EL1
/// drop in smp.zig) and match our platform profile: AAVMF firmware
/// sets these bits on EL2 exit, and KVM makes CNTP directly usable
/// by guest EL1 with CNTVOFF_EL2 transparent to the guest.
///
/// Empirically, Pi 5 KVM's in-kernel vGICv2 drops CNTV PPI 27
/// injections to secondary vCPUs once they dispatch an EL0 thread:
/// PMCCNTR/INTID 27 IRQ counters advance on core 0 (whose yield-SGI
/// path keeps ticking) but stay at single-digit totals on cores 1-3
/// for the whole test window. The EL1 physical timer (INTID 30) is
/// routed by the same vGICv2 bypassing the CNTV path and is reliably
/// delivered to every vCPU. Switching preemption to CNTP also removes
/// the last dependency on vGICv2 CNTV injection, which is the quirk
/// documented in kernel/arch/aarch64/gic.zig:906-944. TCG GICv3 and
/// TCG GICv2 both route INTID 30 correctly, so this is a strict
/// reliability improvement, not a Pi-only workaround.
///
/// ARM ARM D13.8.12: CNTP_TVAL_EL0. Writing TVAL sets CVAL = CNTPCT + TVAL.
inline fn writeCntpTval(val: u32) void {
    asm volatile ("msr cntp_tval_el0, %[val]"
        :
        : [val] "r" (@as(u64, val)),
    );
}

/// Write CNTP_CTL_EL0 — physical timer control register.
/// ARM ARM D13.8.11: CNTP_CTL_EL0. Bit 0 ENABLE, bit 1 IMASK, bit 2 ISTATUS.
inline fn writeCntpCtl(val: u64) void {
    asm volatile ("msr cntp_ctl_el0, %[val]"
        :
        : [val] "r" (val),
    );
}

inline fn ensureFreqCached() void {
    if (cached_freq_hz != 0) return;
    cached_freq_hz = readCntfrq();
}

/// Physical timer for preemption — arms a deadline interrupt via CNTP_TVAL_EL0.
///
/// We use the EL1 physical timer (INTID 30) instead of the virtual
/// timer (INTID 27) because Pi 5 KVM's vGICv2 drops CNTV injections
/// to secondary vCPUs once they run an EL0 thread (see writeCntpTval
/// and gic.zig:906-944 for the diagnosis). CNTP is universally
/// available at EL1 on every platform we target: the bootloader
/// EL2→EL1 drop and smp.zig's secondary EL2→EL1 drop both set
/// CNTHCTL_EL2.{EL1PCEN,EL1PCTEN} = 1 before handing off, and under
/// KVM the host leaves CNTP directly accessible to the guest kernel.
///
/// ARM ARM D11.2.4: Timer conditions and timer interrupts.
const PreemptionTimer = struct {
    fn timer(self: *PreemptionTimer) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    /// Read current time as nanoseconds via CNTVCT_EL0.
    /// ARM ARM D11.2.3: CNTVCT_EL0 increments at CNTFRQ_EL0 Hz.
    fn now(_: *anyopaque) u64 {
        return timer_mod.nanosFromTicksFloor(cached_freq_hz, cpu.readCntvct());
    }

    /// Arm a one-shot interrupt `delta_ns` nanoseconds from now.
    ///
    /// The `Timer` vtable contract (shared with x64 LAPIC/HPET) treats
    /// `timer_val_ns` as a RELATIVE delta, not an absolute deadline. The
    /// ARM generic timer provides CNTP_TVAL_EL0 which internally computes
    /// CVAL = CNTPCT + TVAL, so we clamp the delta to 32 bits and let
    /// hardware do the offset math.
    ///
    /// ARM ARM D13.8.12: CNTP_TVAL_EL0.
    /// ARM ARM D13.8.11: CNTP_CTL_EL0 — ENABLE=1, IMASK=0.
    fn armInterruptTimer(_: *anyopaque, delta_ns: u64) void {
        var delta_ticks = timer_mod.ticksFromNanosCeil(cached_freq_hz, delta_ns);
        if (delta_ticks == 0) delta_ticks = 1;
        if (delta_ticks > 0x7FFF_FFFF) delta_ticks = 0x7FFF_FFFF;
        writeCntpTval(@intCast(delta_ticks));
        // ENABLE=1 (bit 0), IMASK=0 (bit 1 clear)
        writeCntpCtl(0x1);
    }
};

/// Monotonic clock — read-only time source backed by CNTVCT_EL0.
/// Never arms interrupts; used only for timestamp queries.
const MonotonicClock = struct {
    fn timer(self: *MonotonicClock) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .armInterruptTimer = armInterruptTimer,
            },
        };
    }

    /// ARM ARM D11.2.3: CNTVCT_EL0, virtual counter.
    fn now(_: *anyopaque) u64 {
        return timer_mod.nanosFromTicksFloor(cached_freq_hz, cpu.readCntvct());
    }

    /// The monotonic clock never arms interrupts — this is unreachable.
    /// Mirrors x64 HPET behavior where armInterruptTimer is unreachable.
    fn armInterruptTimer(_: *anyopaque, _: u64) void {
        unreachable;
    }
};

// Module-scope const vtables. Keeping them here (rather than in an
// anonymous `&.{...}` literal inside a method) means the address is
// taken at comptime rather than through any runtime pool, and the
// resulting `Timer` can be returned by value through a single register
// pair with no per-call ABI struct-return shuffling — see the note on
// `getPreemptionTimer` below.
const preemption_vtable: timer_mod.VTable = .{
    .now = PreemptionTimer.now,
    .armInterruptTimer = PreemptionTimer.armInterruptTimer,
};

const monotonic_vtable: timer_mod.VTable = .{
    .now = MonotonicClock.now,
    .armInterruptTimer = MonotonicClock.armInterruptTimer,
};

/// `inline` is load-bearing on aarch64 + TCG SMP. When this function is
/// emitted as a free-standing out-of-line body, secondary cores brought
/// up via PSCI CPU_ON hang somewhere between its prologue and the caller
/// receiving the returned `Timer` (observed with earlyDebugChar markers:
/// core 0 completes the call, cores 1..N enter but never return to the
/// caller). The exact miscompile is not pinned down — it may be an
/// LLVM/Zig ABI issue with 16-byte struct returns, KASLR-relocated .text
/// calls, or a TCG GICv3/Cortex-A72 interaction — but `inline` makes the
/// call disappear entirely at the call site and SMP bring-up succeeds.
/// `getMonotonicClock` is inlined for symmetry and to avoid any latent
/// variant of the same miscompile.
pub inline fn getPreemptionTimer() Timer {
    ensureFreqCached();
    return .{
        .ptr = &preemption_timer_instance,
        .vtable = &preemption_vtable,
    };
}

pub inline fn getMonotonicClock() Timer {
    ensureFreqCached();
    return .{
        .ptr = &monotonic_clock_instance,
        .vtable = &monotonic_vtable,
    };
}
