const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.80 — `pmu_info` with `info_ptr` not pointing to a writable region of `sizeof(PmuInfo)` bytes returns `E_BADADDR`.
pub fn main(_: u64) void {
    // Null pointer is never writable.
    const rc = syscall.pmu_info(0);
    t.expectEqual("§4.1.80", syscall.E_BADADDR, rc);
    syscall.shutdown();
}
