//! Scheduler timer utilities (generic `Timer`-backed timeslice).
//!
//! Arms and services a periodic scheduler tick using a provided `timers.Timer`
//! implementation (e.g. TSC-deadline or LAPIC one-shot). A timer must be
//! installed via `scheduler.init` before arming.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - `SCHED_TIMESLICE_NS` — nominal scheduler timeslice length in nanoseconds.
//!
//! ## Variables
//! - `timer` — optional `timers.Timer`; must be set by `scheduler.init` before use.
//!
//! ## Functions
//! - `scheduler.armSchedTimer` — arm next tick after a delta in nanoseconds.
//! - `scheduler.init` — install the active `timers.Timer` implementation.
//! - `scheduler.schedTimerHandler` — IRQ handler; logs and rearms the timer.

const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const serial = zag.x86.Serial;
const timers = zag.x86.Timers;

/// Nominal scheduler timeslice in nanoseconds (2 ms).
pub const SCHED_TIMESLICE_NS = 2_000_000;

var timer: ?timers.Timer = null;

/// Arm the scheduler timer to fire after `delta_ns`.
///
/// Arguments:
/// - `delta_ns`: nanoseconds until the next scheduler tick.
///
/// Panics:
/// - Panics if `timer` is null (must call `scheduler.init` first).
pub fn armSchedTimer(delta_ns: u64) void {
    timer.?.arm_interrupt_timer(delta_ns);
}

/// Install the active `timers.Timer` used by the scheduler.
///
/// Arguments:
/// - `t`: timer implementation to use for arming deadlines.
pub fn init(t: timers.Timer) void {
    timer = t;
}

/// Scheduler timer interrupt handler: logs a tick and rearms the deadline.
///
/// Arguments:
/// - `ctx`: interrupt context pointer (`*cpu.Context`). Not used.
///
/// Panics:
/// - Panics if `timer` is null (because it calls `scheduler.armSchedTimer`).
pub fn schedTimerHandler(ctx: *cpu.Context) void {
    _ = ctx;
    //serial.print("Sched timer!\n", .{});
    armSchedTimer(SCHED_TIMESLICE_NS);
}
