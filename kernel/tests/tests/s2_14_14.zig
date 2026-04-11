const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.14 — A single-threaded process that is its own fault handler cannot use sample-based profiling: when its only thread overflows, the normal single-thread-fault semantics (§2.12.7) apply and the process is killed (or restarted).
pub fn main(pv: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or
        info.num_counters == 0 or !info.overflow_support)
    {
        t.pass("§2.14.14");
        syscall.shutdown();
    }

    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Child is its own fault handler (default when nobody claims
    // fault_handler) AND single-threaded. pmu_overflow must kill it.
    const child_rights = perms.ProcessRights{ .pmu = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_pmu_overflow_self.ptr),
        children.child_pmu_overflow_self.len,
        child_rights.bits(),
    )));

    // Poll until the child transitions to dead_process (field0 is the
    // CrashReason).
    var spins: u64 = 0;
    while (spins < 2_000_000) : (spins += 1) {
        for (0..128) |i| {
            const e = &view[i];
            if (e.entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) continue;
            if (e.handle != ch) continue;
            // Found — child is dead. §2.14.14 says it is killed or
            // restarted; we spawned without ProcessRights.restart so it
            // must be dead (not restarted) and the reason is the one
            // recorded by §3.11 / §2.12.7.
            const reason = e.processCrashReason();
            if (reason == perm_view.CrashReason.illegal_instruction) {
                // Child signals setup failure (pmu_info / pmu_start
                // rejected, or overflow never delivered) via `ud2`.
                // This is a test-setup or kernel-delivery regression,
                // not a §2.14.14 violation — report it distinctly.
                t.fail("§2.14.14 child setup failed or overflow not delivered");
                syscall.shutdown();
            }
            if (reason != perm_view.CrashReason.pmu_overflow) {
                t.failWithVal("§2.14.14 wrong crash reason",
                    @intFromEnum(perm_view.CrashReason.pmu_overflow),
                    @intFromEnum(reason));
                syscall.shutdown();
            }
            t.pass("§2.14.14");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }

    t.fail("§2.14.14 child not killed");
    syscall.shutdown();
}
