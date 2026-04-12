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
//! - Non-virtualized kernel: physical timer (CNTP_*) for preemption.
//! - Under a hypervisor: virtual timer (CNTV_*) — host controls physical.
//! - Timestamp reads: CNTVCT_EL0 (virtual counter) is always safe to use.
//!
//! Timer interrupt: PPI 30 (physical) or PPI 27 (virtual). The GIC must
//! be configured to route these to the exception handler. When the timer
//! fires, the handler calls the scheduler's preemption logic.
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

/// Write CNTP_CVAL_EL0 — set the physical timer comparator value.
/// ARM ARM D13.8.9: CNTP_CVAL_EL0, Counter-timer Physical Timer CompareValue register.
/// The timer fires when CNTPCT_EL0 >= CVAL.
inline fn writeCntpCval(val: u64) void {
    asm volatile ("msr cntp_cval_el0, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write CNTP_CTL_EL0 — physical timer control register.
/// ARM ARM D13.8.7: CNTP_CTL_EL0, Counter-timer Physical Timer Control register.
/// Bit 0: ENABLE — enables the timer.
/// Bit 1: IMASK — interrupt mask (0 = unmasked, 1 = masked).
/// Bit 2: ISTATUS — read-only interrupt status.
inline fn writeCntpCtl(val: u64) void {
    asm volatile ("msr cntp_ctl_el0, %[val]"
        :
        : [val] "r" (val),
    );
}

fn ensureFreqCached() void {
    if (cached_freq_hz != 0) return;
    cached_freq_hz = readCntfrq();
}

/// Physical timer for preemption — arms a deadline interrupt via CNTP_CVAL_EL0.
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

    /// Arm a one-shot interrupt at an absolute nanosecond deadline.
    /// Converts the deadline to ticks via ticksFromNanosCeil, writes
    /// CNTP_CVAL_EL0, and enables the physical timer with IMASK cleared.
    /// ARM ARM D13.8.9: CNTP_CVAL_EL0 — comparator fires when CNTPCT >= CVAL.
    /// ARM ARM D13.8.7: CNTP_CTL_EL0 — ENABLE=1, IMASK=0.
    fn armInterruptTimer(_: *anyopaque, deadline_ns: u64) void {
        const deadline_ticks = timer_mod.ticksFromNanosCeil(cached_freq_hz, deadline_ns);
        writeCntpCval(deadline_ticks);
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

pub fn getPreemptionTimer() Timer {
    ensureFreqCached();
    return preemption_timer_instance.timer();
}

pub fn getMonotonicClock() Timer {
    ensureFreqCached();
    return monotonic_clock_instance.timer();
}
