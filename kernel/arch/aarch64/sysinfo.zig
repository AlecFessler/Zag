//! aarch64 system-information stubs (unimplemented).
//!
//! Per systems.md §sysinfo "aarch64 Stubs": the stub exists so
//! `kernel/arch/dispatch.zig`'s comptime switches compile on aarch64 and
//! so `sys_info` returns a syntactically valid `CoreInfo` array (all
//! hardware fields zero) instead of `@compileError`-ing the build.
//!
//! Scheduler accounting (`idle_ns`, `busy_ns`) is produced by
//! architecture-independent code and is unaffected. When aarch64 gains
//! real `CNTFRQ_EL0`- or vendor-sideband-based temperature/frequency
//! support, it replaces the stubs here in-place with no changes required
//! to the generic layer.

pub fn sysInfoInit() void {}

pub fn sysInfoPerCoreInit() void {}

pub fn sampleCoreHwState() void {}

pub fn getCoreFreq(core_id: u64) u64 {
    _ = core_id;
    return 0;
}

pub fn getCoreTemp(core_id: u64) u32 {
    _ = core_id;
    return 0;
}

pub fn getCoreState(core_id: u64) u8 {
    _ = core_id;
    return 0;
}
