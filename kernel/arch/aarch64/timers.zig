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
//! - ACPI 6.5, Section 5.2.25: GTDT (timer interrupt numbers and flags)

const zag = @import("zag");

const Timer = zag.arch.timer.Timer;

pub fn getPreemptionTimer() Timer {
    @panic("aarch64 preemption timer not implemented");
}

pub fn getMonotonicClock() Timer {
    @panic("aarch64 monotonic clock not implemented");
}
