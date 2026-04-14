const lib = @import("lib");

const syscall = lib.syscall;

/// kprof workload — exercises sched_timer_tick, sched_switch, sched_yield,
/// and syscall_dispatch by spinning in a tight thread_yield() loop.
pub fn main(_: u64) void {
    while (true) syscall.thread_yield();
}
