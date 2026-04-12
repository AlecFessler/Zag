const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.90 — `pmu_start` with `configs_ptr` not pointing to a readable region of `count * sizeof(PmuCounterConfig)` bytes returns `E_BADADDR`.
pub fn main(_: u64) void {
    const self_thread: u64 = @bitCast(syscall.thread_self());
    const rc = syscall.pmu_start(self_thread, 0, 1);
    t.expectEqual("§4.1.90", syscall.E_BADADDR, rc);
    syscall.shutdown();
}
