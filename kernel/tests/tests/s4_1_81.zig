const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.81 — On hardware with no supported performance counters, `pmu_info` succeeds and writes `num_counters = 0`, `supported_events = 0`, `overflow_support = false`.
///
/// On counter-capable hardware this clause is vacuously true, but the tag
/// is not untestable: we still sanity-check the returned info
/// (`num_counters <= PMU_MAX_COUNTERS`; no `supported_events` bits outside
/// the defined `PmuEvent` range) so a kernel regression that leaves
/// garbage in the struct is caught here. §4.1.81 is "vacuously passed on
/// counter-capable HW after sanity checks".
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    // Pre-poison the entire struct bytewise (m4) so a kernel regression
    // that fails to write any field surfaces as a non-zero/invalid
    // value rather than whatever the Zig default happens to be.
    const info_bytes: [*]u8 = @ptrCast(&info);
    for (0..@sizeOf(syscall.PmuInfo)) |i| info_bytes[i] = 0xff;

    const rc = syscall.pmu_info(@intFromPtr(&info));
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.1.81", syscall.E_OK, rc);
        syscall.shutdown();
    }

    if (info.num_counters == 0) {
        // The §4.1.81 clause: verify the required zero invariants.
        if (info.supported_events != 0 or info.overflow_support) {
            t.fail("§4.1.81 no-counter fields not zero");
            syscall.shutdown();
        }
    } else {
        // Counter-capable HW: §4.1.81 is vacuously satisfied here, so
        // exercise non-vacuous sanity checks on the returned info so
        // the tag still catches struct-layout/marshalling regressions.
        if (info.num_counters > syscall.PMU_MAX_COUNTERS) {
            t.failWithVal(
                "§4.1.81 num_counters > PMU_MAX_COUNTERS",
                @intCast(syscall.PMU_MAX_COUNTERS),
                @intCast(info.num_counters),
            );
            syscall.shutdown();
        }

        // Compute the mask of bits covered by defined PmuEvent variants.
        // Any bit in supported_events outside this mask is a bug.
        comptime var defined_mask: u64 = 0;
        inline for (@typeInfo(syscall.PmuEvent).@"enum".fields) |f| {
            defined_mask |= @as(u64, 1) << f.value;
        }
        if ((info.supported_events & ~defined_mask) != 0) {
            t.failWithVal(
                "§4.1.81 supported_events has undefined bits",
                @bitCast(defined_mask),
                @bitCast(info.supported_events),
            );
            syscall.shutdown();
        }
    }

    t.pass("§4.1.81");
    syscall.shutdown();
}
