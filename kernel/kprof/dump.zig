//! Kprof rolling-dump quiesce path.
//!
//! The dump-all-logs serial output path lived here pre-spec-v3 and was
//! removed when the test runner switched to in-memory result reporting.
//! What's left is the IPI-driven quiesce hook other cores enter via
//! `parkForDump`, kept so the kprof IPI handler still has a target.

const log_mod = @import("log.zig");
const mode = @import("mode.zig");
const zag = @import("zag");

const arch = zag.arch.dispatch;

/// Called from the kprof-dump IPI handler on non-dumping cores.
/// Records this core as parked, snapshots the current epoch, then
/// spins until the dumper bumps epoch. Returns from the IPI handler
/// so the core resumes whatever it was running when the IPI arrived.
pub fn parkForDump() void {
    if (!mode.any_enabled) return;
    const my_epoch = @atomicLoad(u64, &log_mod.epoch, .acquire);
    _ = @atomicRmw(u32, &log_mod.parked_cores, .Add, 1, .acq_rel);
    while (@atomicLoad(u64, &log_mod.epoch, .acquire) == my_epoch) {
        arch.cpu.cpuRelax();
    }
}
