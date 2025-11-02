//! Scheduler timer utilities (TSC-deadline timeslice).
//!
//! Arms and services a periodic scheduler tick using x2APIC TSC-deadline mode.
//! You must initialize the measured TSC frequency before arming the timer.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - `SCHED_TIMESLICE_NS` — nominal scheduler timeslice length in nanoseconds.
//! - `ONE_BILLION_CYCLES` — nanoseconds-per-second factor (1_000_000_000).
//!
//! ## Variables
//! - `freq_hz` — optionally stored TSC frequency in Hz; required before arming.
//!
//! ## Functions
//! - `scheduler.armSchedTimer` — arm next TSC-deadline tick based on `freq_hz`.
//! - `scheduler.initFreqHz` — set the measured TSC frequency (Hz).
//! - `scheduler.schedTimerHandler` — IRQ handler; logs and rearms the timer.

const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const serial = zag.x86.Serial;

/// Nominal scheduler timeslice in nanoseconds (2 ms).
pub const SCHED_TIMESLICE_NS = 2_000_000;

/// Nanoseconds-per-second factor used for ns→ticks scaling.
const ONE_BILLION_CYCLES = 1_000_000_000;

/// Optionally stored TSC frequency in Hz; must be set before arming.
var freq_hz: ?u64 = null;

/// Function: `scheduler.armSchedTimer`
///
/// Summary:
/// Compute the next TSC-deadline from `SCHED_TIMESLICE_NS` and the measured
/// TSC frequency, then program the LAPIC TSC-deadline timer.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if `freq_hz` is null (must call `scheduler.initFreqHz` first).
pub fn armSchedTimer() void {
    const delta_ticks = freq_hz.? * SCHED_TIMESLICE_NS / ONE_BILLION_CYCLES;
    const now_ticks = cpu.rdtscp();
    apic.armTscDeadline(now_ticks + delta_ticks);
}

/// Function: `scheduler.initFreqHz`
///
/// Summary:
/// Initialize the stored TSC frequency used for timeslice scheduling.
///
/// Arguments:
/// - `freq`: Measured TSC frequency in Hertz.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn initFreqHz(freq: u64) void {
    freq_hz = freq;
}

/// Function: `scheduler.schedTimerHandler`
///
/// Summary:
/// Scheduler timer interrupt handler: logs a tick and rearms the deadline.
///
/// Arguments:
/// - `ctx`: Interrupt context pointer (`*cpu.Context`). Not used.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if `freq_hz` is null (because it calls `scheduler.armSchedTimer`).
pub fn schedTimerHandler(ctx: *cpu.Context) void {
    _ = ctx;
    serial.print("Sched timer!\n", .{});
    armSchedTimer();
}
