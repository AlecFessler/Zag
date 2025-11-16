pub const VTable = struct {
    now: *const fn (*anyopaque) u64,
    armInterruptTimer: *const fn (*anyopaque, u64) void,
};

pub const Timer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn now(self: *const Timer) u64 {
        return self.vtable.now(self.ptr);
    }

    pub fn armInterruptTimer(self: *const Timer, timer_val_ns: u64) void {
        return self.vtable.armInterruptTimer(self.ptr, timer_val_ns);
    }
};

pub const ONE_BILLION_NS = 1_000_000_000;
pub const ONE_QUADRILLION_NS = 1_000_000_000_000_000;
pub const TEN_MILLION_NS = 10_000_000;

pub fn nanosFromTicksCeil(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS + freq_hz - 1) / freq_hz;
}

pub fn nanosFromTicksFloor(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS) / freq_hz;
}

pub fn ticksFromNanosCeil(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns + ONE_BILLION_NS - 1) / ONE_BILLION_NS;
}

pub fn ticksFromNanosFloor(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns) / ONE_BILLION_NS;
}
