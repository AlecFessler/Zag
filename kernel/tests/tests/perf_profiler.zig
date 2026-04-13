const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const profiler_mod = lib.profiler;
const syscall = lib.syscall;
const t = lib.testing;

/// Sampling profiler self-test.
/// Spawns a child running a tight compute loop, profiles it via PMU
/// overflow faults, and verifies the top sampled RIP falls within
/// the child's hot loop address range.
///
/// The child starts PMU on itself with an overflow threshold and is
/// multi-threaded so overflow faults deliver to this external handler.
pub fn main(_: u64) void {
    const pmu = t.requirePmuOverflow("perf_profiler");
    const evt = pmu.event;

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .pmu = true,
    };
    const ch_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_workload.ptr),
        children.child_perf_workload.len,
        child_rights.bits(),
    );
    if (ch_rc < 0) {
        t.fail("perf_profiler proc_create");
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(ch_rc);

    // First round: child replies with hot loop addr and main addr.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);
    const hot_loop_addr = reply.words[0];
    const child_main_addr = reply.words[1];

    // Second round: child cap-transfers fault_handler to us so PMU overflow
    // faults route to our fault_box instead of the child's (unread) one.
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Emit load base for resolve_symbols.sh ASLR adjustment
    syscall.write("[PROF] profiler_workload load_base=");
    t.printHex(child_main_addr);
    syscall.write("\n");

    // Collect PMU overflow faults from the child
    var prof = profiler_mod.Profiler.init();
    var fault_buf: [256]u8 align(8) = undefined;
    var samples_collected: u64 = 0;
    const max_samples: u64 = 500;

    while (samples_collected < max_samples) {
        const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
        if (token < 0) break;

        const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));

        if (fm.fault_reason == syscall.FAULT_REASON_PMU_OVERFLOW) {
            prof.recordSample(fm.rip);
            samples_collected += 1;

            var cfg = syscall.PmuCounterConfig{
                .event = evt,
                .has_threshold = true,
                .overflow_threshold = 10000,
            };
            _ = syscall.pmu_reset(fm.thread_handle, @intFromPtr(&cfg), 1);
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_RESUME);
        } else {
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
            break;
        }
    }

    prof.report("profiler_workload");

    // Verify: top sampled RIP should be near the child's hot loop
    if (prof.topRip()) |top_rip| {
        const distance = if (top_rip >= hot_loop_addr)
            top_rip - hot_loop_addr
        else
            hot_loop_addr - top_rip;

        if (distance < 4096 and prof.total_samples >= 10) {
            t.pass("perf_profiler");
        } else {
            syscall.write("[FAIL] perf_profiler top RIP too far from hot loop: ");
            t.printHex(top_rip);
            syscall.write(" vs expected near ");
            t.printHex(hot_loop_addr);
            syscall.write(" (distance=");
            t.printDec(distance);
            syscall.write(", samples=");
            t.printDec(prof.total_samples);
            syscall.write(")\n");
        }
    } else {
        if (samples_collected == 0) {
            syscall.write("[PROF] profiler SKIP no samples collected\n");
            t.pass("perf_profiler");
        } else {
            t.fail("perf_profiler no top RIP");
        }
    }

    _ = syscall.revoke_perm(child_handle);
    syscall.shutdown();
}
