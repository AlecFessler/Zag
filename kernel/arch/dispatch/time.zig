const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const Timer = zag.arch.timer.Timer;

/// Read the CPU cycle counter. `serialized=true` uses LFENCE (x86) or a
/// full ISB before read so prior instructions finish before the counter
/// read; `serialized=false` is the unfenced fast path suitable for
/// in-hot-path tracing where the ~20-cycle LFENCE cost matters. aarch64
/// reads CNTVCT_EL0 in both modes (the counter is already self-ordered).
pub inline fn readTimestamp(serialized: bool) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => if (serialized) x64.cpu.rdtscLFenced() else x64.cpu.rdtscp(),
        .aarch64 => aarch64.cpu.readCntvct(),
        else => unreachable,
    };
}

pub fn readRtc() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.rtc.readRtc(),
        .aarch64 => aarch64.rtc.readRtc(),
        else => unreachable,
    };
}

pub inline fn getPreemptionTimer() Timer {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.timers.getPreemptionTimer(),
        .aarch64 => return aarch64.timers.getPreemptionTimer(),
        else => unreachable,
    }
}

pub inline fn getMonotonicClock() Timer {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.timers.getMonotonicClock(),
        .aarch64 => return aarch64.timers.getMonotonicClock(),
        else => unreachable,
    }
}

/// One-shot BSP-side init for the monotonic clock backend. On x86-64 this
/// promotes `getMonotonicClock()` from HPET (MMIO, vm-exits) to invariant
/// TSC (per-core register read) when the CPU advertises it. On aarch64
/// CNTVCT_EL0 is the only backend, so this is a no-op.
pub inline fn initMonotonicClock() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.timers.initMonotonicClock(),
        .aarch64 => {},
        else => unreachable,
    }
}
