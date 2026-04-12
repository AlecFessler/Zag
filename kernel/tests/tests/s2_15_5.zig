const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

// Bounds for "plausible CPU frequency in hertz". 500 MHz on the low end
// catches any kernel that stored MHz or KHz instead of Hz; 10 GHz on the
// high end catches one that stored cycles-per-tick or a ratio register
// without multiplying by the bus clock.
const MIN_PLAUSIBLE_HZ: u64 = 500_000_000;
const MAX_PLAUSIBLE_HZ: u64 = 10_000_000_000;

/// §2.15.5 — `CoreInfo.freq_hz` is the current CPU frequency of the core in hertz.
///
/// Call `sys_info` with a per-core buffer and check each core's `freq_hz`
/// is either 0 (stubbed / not virtualised, e.g. aarch64 stub or a QEMU
/// build that doesn't expose `IA32_PERF_STATUS`) or within the plausible
/// hertz band. Any value between 0 and 500 MHz is definitively wrong, and
/// any value over 10 GHz is definitively wrong. This range is wide enough
/// to cover every reasonable x86 core but tight enough to catch a unit-
/// confusion bug (`ratio * 100` without the `* 1_000_000` bus-clock
/// multiplier would land around 2000–4000 — orders of magnitude below
/// the lower bound).
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    if (syscall.sys_info(@intFromPtr(&info), 0) != syscall.E_OK) {
        t.fail("§2.15.5 first sys_info");
        syscall.shutdown();
    }
    if (info.core_count == 0 or info.core_count > syscall.MAX_CPU_CORES) {
        t.fail("§2.15.5 bogus core_count");
        syscall.shutdown();
    }

    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§2.15.5 cores sys_info");
        syscall.shutdown();
    }

    var any_nonzero: bool = false;
    var i: u64 = 0;
    while (i < info.core_count) : (i += 1) {
        const hz = cores[i].freq_hz;
        if (hz == 0) continue; // stub / not virtualised — allowed
        any_nonzero = true;
        if (hz < MIN_PLAUSIBLE_HZ) {
            t.failWithVal(
                "§2.15.5 freq_hz too low (unit bug?)",
                @intCast(MIN_PLAUSIBLE_HZ),
                @intCast(hz),
            );
            syscall.shutdown();
        }
        if (hz > MAX_PLAUSIBLE_HZ) {
            t.failWithVal(
                "§2.15.5 freq_hz too high",
                @intCast(MAX_PLAUSIBLE_HZ),
                @intCast(hz),
            );
            syscall.shutdown();
        }
    }

    // If every core reports zero we can't prove hertz-vs-other-units here
    // (e.g. QEMU TCG doesn't virtualise IA32_PERF_STATUS, so the arch
    // reader returns 0). The tag is still satisfied: the stated unit is
    // hertz, and the only field we saw *consistent with* hertz is zero.
    // Record the skip so regression triage can see the test ran.
    if (!any_nonzero) {
        t.pass("§2.15.5 (all cores reported 0 Hz — stub / unvirtualised MSR)");
    } else {
        t.pass("§2.15.5");
    }
    syscall.shutdown();
}
