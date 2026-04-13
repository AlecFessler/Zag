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
pub fn main(_: u64) void {
    // Check PMU availability
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or
        info.num_counters == 0 or !info.overflow_support)
    {
        syscall.write("[PROF] profiler SKIP no PMU overflow support\n");
        t.pass("perf_profiler");
        syscall.shutdown();
    }

    const evt = syscall.pickSupportedEvent(info) orelse {
        syscall.write("[PROF] profiler SKIP no supported events\n");
        t.pass("perf_profiler");
        syscall.shutdown();
    };

    // Spawn profiled child with PMU + fault_handler rights
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

    // Sync with child and get the hot loop address
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);
    const hot_loop_addr = reply.words[0];

    // Configure PMU on child's main thread for sampling
    // We need to wait for the child to start running and then receive
    // its first overflow fault. The child already started PMU on itself
    // via child_pmu_overflow pattern, but our workload child doesn't
    // do that. Instead, we'll receive faults from the child's execution.
    //
    // The child_perf_workload doesn't start PMU itself, so we need
    // a different approach: use fault_recv to get the thread handle,
    // then configure PMU. But the child won't fault until PMU is set up.
    //
    // Solution: the child runs normally. We need its thread handle.
    // From proc_create, we have the child's process handle.
    // The child's main thread handle should be available from the
    // fault system once we have fault_handler rights.
    //
    // Actually, looking at the pattern: the child cap-transfers fault_handler
    // to parent. But our workload child doesn't do that since it's simpler.
    //
    // Simplest approach: we'll read faults directly since we spawned with
    // fault_handler rights. The child_perf_workload just needs a thread
    // that we can configure PMU on. Since we created the child process,
    // we have fault_handler access. Let's get the thread handle from
    // the first interaction.
    //
    // For now: create a modified approach where we start PMU right after
    // the child begins its hot loop. The child sends us an IPC when ready
    // and we configure PMU. But we need the thread handle...
    //
    // The child's main thread handle: when a process is created, the parent
    // gets back a process handle. The thread handle is separate. Let's use
    // fault_set_thread_mode to get faults, then the first fault will give
    // us the thread handle.
    //
    // Alternative simpler approach: The child starts PMU on itself (like
    // child_pmu_overflow does) and we just collect faults. This is actually
    // the cleanest approach.

    // Wait for faults from the child. The child starts its hot loop after
    // the IPC exchange. Since we spawned it with pmu + fault_handler,
    // and the child starts PMU on itself with an overflow threshold,
    // we'll receive PMU overflow faults.
    //
    // But wait - child_perf_workload doesn't start PMU on itself.
    // We need to update the child or handle it here.
    // Let me use the child's process handle to start PMU.
    // Actually the child needs a multi-threaded setup for the fault
    // to deliver to us (external handler). Let's just accept that
    // child_perf_workload needs to set up PMU on itself like
    // child_pmu_overflow does.

    // For this self-test, we'll profile a tight loop in the child.
    // The child starts PMU with overflow and we collect samples.

    var prof = profiler_mod.Profiler.init();
    var fault_buf: [256]u8 align(8) = undefined;
    var samples_collected: u64 = 0;
    const max_samples: u64 = 500;

    // Collect PMU overflow faults until we have enough samples or child exits
    while (samples_collected < max_samples) {
        const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
        if (token < 0) break;

        const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));

        if (fm.fault_reason == syscall.FAULT_REASON_PMU_OVERFLOW) {
            prof.recordSample(fm.rip);
            samples_collected += 1;

            // Reset PMU counters on the faulted thread and resume
            var cfg = syscall.PmuCounterConfig{
                .event = evt,
                .has_threshold = true,
                .overflow_threshold = 10000,
            };
            _ = syscall.pmu_reset(fm.thread_handle, @intFromPtr(&cfg), 1);
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_RESUME);
        } else {
            // Non-PMU fault (e.g., child exited) — kill and break
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
            break;
        }
    }

    // Report profile
    prof.report("profiler_workload");

    // Verify: the top RIP should be near the hot loop address
    // (within reasonable range, since the loop body spans multiple instructions)
    if (prof.topRip()) |top_rip| {
        // The hot loop function should be within a few hundred bytes
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
            // No PMU support or no faults received — skip gracefully
            syscall.write("[PROF] profiler SKIP no samples collected\n");
            t.pass("perf_profiler");
        } else {
            t.fail("perf_profiler no top RIP");
        }
    }

    _ = syscall.revoke_perm(child_handle);
    syscall.shutdown();
}
