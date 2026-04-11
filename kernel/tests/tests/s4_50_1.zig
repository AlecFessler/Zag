const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.50.1 — `pmu_info` returns `E_OK` on success.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    const rc = syscall.pmu_info(@intFromPtr(&info));
    t.expectEqual("§4.50.1", syscall.E_OK, rc);
    syscall.shutdown();
}
