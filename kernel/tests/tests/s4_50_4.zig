const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.50.4 — On hardware with no supported performance counters, `pmu_info` succeeds and writes `num_counters = 0`, `supported_events = 0`, `overflow_support = false`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    // Pre-poison to detect failure to write.
    info.num_counters = 0xff;
    info.supported_events = 0xffff_ffff_ffff_ffff;
    info.overflow_support = true;

    const rc = syscall.pmu_info(@intFromPtr(&info));
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.50.4", syscall.E_OK, rc);
        syscall.shutdown();
    }

    // If the kernel reports num_counters == 0, then §4.50.4 requires the
    // other fields be zero as well. On hardware with counters, this test
    // degrades to a smoke check and just verifies the syscall succeeded.
    if (info.num_counters == 0) {
        if (info.supported_events != 0 or info.overflow_support) {
            t.fail("§4.50.4 no-counter fields not zero");
            syscall.shutdown();
        }
    }

    t.pass("§4.50.4");
    syscall.shutdown();
}
