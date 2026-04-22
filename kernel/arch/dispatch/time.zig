const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const Timer = zag.arch.timer.Timer;

pub fn readTimestamp() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdtscLFenced(),
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

pub inline fn rdtscp() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.rdtscp(),
        .aarch64 => aarch64.cpu.readCntvct(),
        else => unreachable,
    };
}
