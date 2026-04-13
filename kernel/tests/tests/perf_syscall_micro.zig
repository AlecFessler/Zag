const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;
const t = lib.testing;

/// Per-syscall microbenchmarks — one [PERF] group per syscall, measuring
/// the cheapest legal invocation. The goal is to catch anomalies in
/// individual syscalls that subsystem-level benches hide.
///
/// Each body uses `runBench` which pins to core 0 at REALTIME and handles
/// warmup, sorting, and stats.
///
/// Interpretation notes:
///   - The absolute floor for these measurements is ~30-40 cycles of
///     rdtscp serialization + syscall entry/exit; the fastest syscalls
///     here (`thread_self`, `clock_getwall`) are dominated by that floor,
///     so the reported numbers are meaningful only as *relative* to each
///     other, not as absolute kernel overhead.
///   - `*_badh` variants pass BOGUS_HANDLE. The kernel rejects these at
///     `getPermByHandle` (the capability table lookup) before any
///     syscall-specific validation runs, so every `*_badh` measurement
///     converges on "lookup + E_BADCAP return" cost plus the per-syscall
///     argument-register unpack. Use them as a proxy for "is the
///     capability lookup path getting slower", not "is pmu_start getting
///     slower" — the latter never runs on a bad handle.
///   - `set_priority_same` / `set_affinity_same` write the same value
///     they already have, but the kernel does not early-exit; these
///     measure the full "lookup + write" path, not a no-op.
///
/// Omitted (covered by dedicated perf tests or unsafe to loop):
///   thread_yield       → perf_syscall_yield
///   clock_gettime      → perf_clock_gettime
///   mem_reserve        → perf_mem_reserve
///   thread_create      → perf_thread_create
///   ipc_call/recv/reply→ perf_ipc, perf_ipc_cross
///   futex_wait/wake    → perf_futex
///   shutdown           → terminates the process
///   disable_restart    → one-shot, cannot be looped
///   sys_power/cpu_power→ reboots / alters CPU state
///   proc_create        → too slow for a tight loop
///   vm_*               → requires VM-creator rights + VM handle plumbing
///   fault_*            → requires a blocked faulting target
///   ioport/mmio/dma/irq→ requires device caps
///   clock_setwall      → mutates system state

// --- Module-level state captured once in main ---

var self_thread_handle: u64 = 0;
var local_futex: u64 = 0;
var rand_buf: [8]u8 = .{0} ** 8;
var sys_info_buf: syscall.SysInfo = undefined;
var pmu_info_buf: syscall.PmuInfo = undefined;
var fault_buf: [256]u8 align(8) = undefined;
var ipc_msg: syscall.IpcMessage = .{};

pub fn main(_: u64) void {
    self_thread_handle = @bitCast(syscall.thread_self());

    // --- Trivial null-path syscalls ---
    _ = bench.runBench(.{ .name = "syscall_thread_self", .warmup = 1000, .iterations = 10000 }, benchThreadSelf);
    _ = bench.runBench(.{ .name = "syscall_clock_getwall", .warmup = 1000, .iterations = 10000 }, benchClockGetwall);
    _ = bench.runBench(.{ .name = "syscall_sys_info", .warmup = 1000, .iterations = 10000 }, benchSysInfo);
    _ = bench.runBench(.{ .name = "syscall_pmu_info", .warmup = 1000, .iterations = 10000 }, benchPmuInfo);
    _ = bench.runBench(.{ .name = "syscall_getrandom_8", .warmup = 1000, .iterations = 10000 }, benchGetrandom8);

    // --- Scheduler state setters (writing the current value — no early-exit) ---
    _ = bench.runBench(.{ .name = "syscall_set_priority_same", .warmup = 1000, .iterations = 10000 }, benchSetPrioritySame);
    _ = bench.runBench(.{ .name = "syscall_set_affinity_same", .warmup = 1000, .iterations = 10000 }, benchSetAffinitySame);

    // --- Capability-table lookup + early return (E_BADHANDLE) ---
    // Complement to perf_cap_lookup's ipc_send paths: these measure the
    // cost of the rights/lookup check across different syscall handlers.
    _ = bench.runBench(.{ .name = "syscall_revoke_badh", .warmup = 1000, .iterations = 10000 }, benchRevokeBad);
    _ = bench.runBench(.{ .name = "syscall_thread_suspend_badh", .warmup = 1000, .iterations = 10000 }, benchSuspendBad);
    _ = bench.runBench(.{ .name = "syscall_thread_resume_badh", .warmup = 1000, .iterations = 10000 }, benchResumeBad);
    _ = bench.runBench(.{ .name = "syscall_thread_kill_badh", .warmup = 1000, .iterations = 10000 }, benchKillBad);
    _ = bench.runBench(.{ .name = "syscall_mem_perms_badh", .warmup = 1000, .iterations = 10000 }, benchMemPermsBad);
    _ = bench.runBench(.{ .name = "syscall_mem_shm_map_badh", .warmup = 1000, .iterations = 10000 }, benchShmMapBad);
    _ = bench.runBench(.{ .name = "syscall_mem_mmio_map_badh", .warmup = 1000, .iterations = 10000 }, benchMmioMapBad);
    _ = bench.runBench(.{ .name = "syscall_mem_dma_map_badh", .warmup = 1000, .iterations = 10000 }, benchDmaMapBad);
    _ = bench.runBench(.{ .name = "syscall_ioport_read_badh", .warmup = 1000, .iterations = 10000 }, benchIoportReadBad);
    _ = bench.runBench(.{ .name = "syscall_ioport_write_badh", .warmup = 1000, .iterations = 10000 }, benchIoportWriteBad);
    _ = bench.runBench(.{ .name = "syscall_irq_ack_badh", .warmup = 1000, .iterations = 10000 }, benchIrqAckBad);
    _ = bench.runBench(.{ .name = "syscall_pmu_start_badh", .warmup = 1000, .iterations = 10000 }, benchPmuStartBad);
    _ = bench.runBench(.{ .name = "syscall_pmu_read_badh", .warmup = 1000, .iterations = 10000 }, benchPmuReadBad);
    _ = bench.runBench(.{ .name = "syscall_pmu_reset_badh", .warmup = 1000, .iterations = 10000 }, benchPmuResetBad);
    _ = bench.runBench(.{ .name = "syscall_pmu_stop_badh", .warmup = 1000, .iterations = 10000 }, benchPmuStopBad);

    // --- Non-blocking wait paths (return without sleeping) ---
    // fault_recv with blocking=0 and no pending fault returns E_AGAIN.
    _ = bench.runBench(.{ .name = "syscall_fault_recv_nonblock", .warmup = 1000, .iterations = 10000 }, benchFaultRecvNonblock);
    // ipc_recv with blocking=false and no pending message returns E_AGAIN.
    _ = bench.runBench(.{ .name = "syscall_ipc_recv_nonblock", .warmup = 1000, .iterations = 10000 }, benchIpcRecvNonblock);
    // notify_wait with timeout=0 returns immediately (E_TIMEOUT / E_AGAIN).
    _ = bench.runBench(.{ .name = "syscall_notify_wait_zero", .warmup = 1000, .iterations = 10000 }, benchNotifyWaitZero);

    // --- Null entry floor ---
    // write(0, 0) is the cheapest syscall-entry path we can drive from
    // userspace: it bounces off the argument check and returns
    // immediately. Useful as a lower bound for "how cheap can *any*
    // syscall be" on this hardware.
    _ = bench.runBench(.{ .name = "syscall_null_entry", .warmup = 1000, .iterations = 10000 }, benchWriteEmpty);

    syscall.shutdown();
}

// --- Bench bodies ---

fn benchThreadSelf() void {
    _ = syscall.thread_self();
}

fn benchClockGetwall() void {
    _ = syscall.clock_getwall();
}

fn benchSysInfo() void {
    _ = syscall.sys_info(@intFromPtr(&sys_info_buf), 0);
}

fn benchPmuInfo() void {
    _ = syscall.pmu_info(@intFromPtr(&pmu_info_buf));
}

fn benchGetrandom8() void {
    _ = syscall.getrandom(&rand_buf, rand_buf.len);
}

fn benchSetPrioritySame() void {
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);
}

fn benchSetAffinitySame() void {
    _ = syscall.set_affinity(1);
}

fn benchRevokeBad() void {
    _ = syscall.revoke_perm(t.BOGUS_HANDLE);
}

fn benchSuspendBad() void {
    _ = syscall.thread_suspend(t.BOGUS_HANDLE);
}

fn benchResumeBad() void {
    _ = syscall.thread_resume(t.BOGUS_HANDLE);
}

fn benchKillBad() void {
    _ = syscall.thread_kill(t.BOGUS_HANDLE);
}

fn benchMemPermsBad() void {
    _ = syscall.mem_perms(t.BOGUS_HANDLE, 0, syscall.PAGE4K, 0x7);
}

fn benchShmMapBad() void {
    _ = syscall.mem_shm_map(t.BOGUS_HANDLE, t.BOGUS_HANDLE, 0);
}

fn benchMmioMapBad() void {
    _ = syscall.mem_mmio_map(t.BOGUS_HANDLE, t.BOGUS_HANDLE, 0);
}

fn benchDmaMapBad() void {
    _ = syscall.mem_dma_map(t.BOGUS_HANDLE, t.BOGUS_HANDLE);
}

fn benchIoportReadBad() void {
    _ = syscall.ioport_read(t.BOGUS_HANDLE, 0, 1);
}

fn benchIoportWriteBad() void {
    _ = syscall.ioport_write(t.BOGUS_HANDLE, 0, 1, 0);
}

fn benchIrqAckBad() void {
    _ = syscall.irq_ack(t.BOGUS_HANDLE);
}

fn benchPmuStartBad() void {
    var cfg = syscall.PmuCounterConfig{
        .event = .cycles,
        .has_threshold = false,
        .overflow_threshold = 0,
    };
    _ = syscall.pmu_start(t.BOGUS_HANDLE, @intFromPtr(&cfg), 1);
}

fn benchPmuReadBad() void {
    var sample: syscall.PmuSample = undefined;
    _ = syscall.pmu_read(t.BOGUS_HANDLE, @intFromPtr(&sample));
}

fn benchPmuResetBad() void {
    var cfg = syscall.PmuCounterConfig{
        .event = .cycles,
        .has_threshold = false,
        .overflow_threshold = 0,
    };
    _ = syscall.pmu_reset(t.BOGUS_HANDLE, @intFromPtr(&cfg), 1);
}

fn benchPmuStopBad() void {
    _ = syscall.pmu_stop(t.BOGUS_HANDLE);
}

fn benchFaultRecvNonblock() void {
    _ = syscall.fault_recv(@intFromPtr(&fault_buf), 0);
}

fn benchIpcRecvNonblock() void {
    _ = syscall.ipc_recv(false, &ipc_msg);
}

fn benchNotifyWaitZero() void {
    _ = syscall.notify_wait(0);
}

fn benchWriteEmpty() void {
    _ = syscall.write_raw(0, 0);
}
