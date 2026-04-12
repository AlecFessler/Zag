const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.15.6 — A value of `0` means the core is active; higher values indicate progressively deeper idle states.
///
/// The kernel's `c_state` field is currently a stub that always reports
/// `0` (the spec-compliant "active" value); see `kernel/arch/x64/sysinfo.zig`
/// where `c_state` is hard-coded to 0 because we don't yet read the
/// `MSR_CORE_C{1,3,6,7}_RES` residency MSRs. The "0 == active" half of
/// the tag is therefore always satisfied trivially. This test guards
/// against a regression that would make the field return a nonsensical
/// value (e.g. `0xFF` from uninitialised memory) by checking every
/// in-range core slot.
///
/// When the kernel grows real C-state telemetry this test should be
/// rewritten to actually exercise an active-vs-idle transition.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;

    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§2.15.6 sys_info");
        syscall.shutdown();
    }
    if (info.core_count == 0 or info.core_count > syscall.MAX_CPU_CORES) {
        t.fail("§2.15.6 bogus core_count");
        syscall.shutdown();
    }

    var i: u64 = 0;
    while (i < info.core_count) : (i += 1) {
        if (cores[i].c_state != 0) {
            t.failWithVal(
                "§2.15.6 c_state non-zero (kernel stub should always report 0)",
                @intCast(i),
                @intCast(cores[i].c_state),
            );
            syscall.shutdown();
        }
    }

    t.pass("§2.15.6 (c_state is currently a stub that always returns 0 (spec-compliant 'active'); this test will need revisiting when the kernel wires up MSR_CORE_C{1,3,6,7}_RES)");
    syscall.shutdown();
}
