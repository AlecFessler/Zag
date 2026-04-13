const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const sched = zag.sched.scheduler;

const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

/// Wall clock offset: difference between RTC-derived Unix nanoseconds
/// and the monotonic clock. Initialized at boot from the CMOS RTC.
/// Spec §2.16; systems.md §wall-clock.
pub var wall_offset: i64 = 0;

pub fn sysClockGettime() i64 {
    return @bitCast(arch.getMonotonicClock().now());
}

pub fn sysClockGetwall() i64 {
    const monotonic_now = arch.getMonotonicClock().now();
    const offset = @atomicLoad(i64, &wall_offset, .monotonic);
    return @as(i64, @bitCast(monotonic_now)) +% offset;
}

pub fn sysClockSetwall(requested_nanos: u64) i64 {
    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_time) return E_PERM;
    const new_offset = @as(i64, @bitCast(requested_nanos)) -% @as(i64, @bitCast(arch.getMonotonicClock().now()));
    @atomicStore(i64, &wall_offset, new_offset, .monotonic);
    return E_OK;
}
