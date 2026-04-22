const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

// --- System info (sys_info) dispatch (systems.md §arch-interface, §sysinfo) ---

/// One-time system-info bring-up on the bootstrap core. Called from `kMain`
/// after `arch.pmuInit()` and before `sched.globalInit()`.
pub fn sysInfoInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoInit(),
        .aarch64 => aarch64.sysinfo.sysInfoInit(),
        else => unreachable,
    }
}

/// Per-core system-info bring-up. Runs on every core from `sched.perCoreInit`
/// alongside `arch.pmuPerCoreInit`.
pub fn sysInfoPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sysInfoPerCoreInit(),
        .aarch64 => aarch64.sysinfo.sysInfoPerCoreInit(),
        else => unreachable,
    }
}

/// Sample this core's frequency / temperature / C-state into its cache slot.
/// Called from `schedTimerHandler` on every scheduler tick. Must run on the
/// target core because the underlying MSR reads are core-local.
pub fn sampleCoreHwState() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.sampleCoreHwState(),
        .aarch64 => aarch64.sysinfo.sampleCoreHwState(),
        else => unreachable,
    }
}

/// Read the cached current frequency of `core_id` in hertz. Up to one
/// scheduler tick stale for remote cores. See systems.md §sysinfo for the
/// tick-sampled cache design.
pub fn getCoreFreq(core_id: u64) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreFreq(core_id),
        .aarch64 => aarch64.sysinfo.getCoreFreq(core_id),
        else => unreachable,
    };
}

/// Read the cached current temperature of `core_id` in milli-celsius.
pub fn getCoreTemp(core_id: u64) u32 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreTemp(core_id),
        .aarch64 => aarch64.sysinfo.getCoreTemp(core_id),
        else => unreachable,
    };
}

/// Read the cached current C-state level of `core_id`. 0 means active;
/// higher values indicate progressively deeper idle states.
pub fn getCoreState(core_id: u64) u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.sysinfo.getCoreState(core_id),
        .aarch64 => aarch64.sysinfo.getCoreState(core_id),
        else => unreachable,
    };
}
