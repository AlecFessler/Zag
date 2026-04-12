const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

var worker_ready: u64 align(8) = 0;
var worker_stop: u64 align(8) = 0;

fn spinLoop() void {
    @atomicStore(u64, &worker_ready, 1, .seq_cst);
    while (@atomicLoad(u64, &worker_stop, .seq_cst) == 0) {
        // Tight loop with no yield — we want the thread to actually be
        // observably `.running` (or at least `.ready`, never `.suspended`
        // or `.faulted`) when the parent issues pmu_read. A yield-heavy
        // loop might transiently deschedule into a state the kernel
        // counts differently.
        asm volatile ("" ::: .{ .memory = true });
    }
}

fn runningBusySubtest(info: syscall.PmuInfo) void {
    const evt = syscall.pickSupportedEvent(info) orelse return;
    const worker = syscall.thread_create(&spinLoop, 0, 4);
    if (worker <= 0) {
        t.failWithVal("§4.1.47 thread_create", 1, worker);
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(worker);

    // Race-free running signal.
    while (@atomicLoad(u64, &worker_ready, .seq_cst) == 0) syscall.thread_yield();

    var cfg = syscall.PmuCounterConfig{ .event = evt, .has_threshold = false, .overflow_threshold = 0 };
    if (syscall.pmu_start(worker_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.1.47 pmu_start");
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Running thread -> E_BUSY.
    var sample: syscall.PmuSample = undefined;
    const busy_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (busy_rc != syscall.E_BUSY) {
        t.failWithVal("§4.1.47 running", syscall.E_BUSY, busy_rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Suspended thread -> E_OK.
    _ = syscall.thread_suspend(worker_h);
    const suspended_rc = syscall.pmu_read(worker_h, @intFromPtr(&sample));
    if (suspended_rc != syscall.E_OK) {
        t.failWithVal("§4.1.47 suspended", syscall.E_OK, suspended_rc);
        @atomicStore(u64, &worker_stop, 1, .seq_cst);
        _ = syscall.thread_kill(worker_h);
        syscall.shutdown();
    }

    // Tear down.
    _ = syscall.pmu_stop(worker_h);
    @atomicStore(u64, &worker_stop, 1, .seq_cst);
    _ = syscall.thread_kill(worker_h);
}

fn faultedSubtest() void {
    // Drive a worker into `.faulted` state via PMU overflow and assert
    // `pmu_read` on that faulted thread returns `E_OK`. This exercises
    // the second half of §4.1.47 (the `.faulted` positive path). On
    // rigs without overflow support we skip this subtest — §2.14.13
    // covers the same positive path via its own overflow-capable path.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .pmu = true,
    };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_pmu_overflow.ptr),
        children.child_pmu_overflow.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§4.1.47 faulted fault_recv", 0, token);
        syscall.shutdown();
    }
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const target = fm.thread_handle;

    var sample: syscall.PmuSample = undefined;
    const rc = syscall.pmu_read(target, @intFromPtr(&sample));
    if (rc != syscall.E_OK) {
        t.failWithVal("§4.1.47 faulted pmu_read", syscall.E_OK, rc);
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
}

/// §4.1.47 — `pmu_read` is only valid when the target thread is in `.faulted` or `.suspended` state.
///
/// Two subtests:
///   (1) Running -> E_BUSY, then suspend -> E_OK (race-free via a
///       worker_ready signal).
///   (2) Drive a child thread into `.faulted` via PMU overflow and
///       assert `pmu_read` on the faulted thread returns `E_OK` — this
///       is the `.faulted` half of the §4.1.47 positive path that was
///       not previously exercised here (only implicitly by §2.14.13).
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.47");
        syscall.shutdown();
    }

    runningBusySubtest(info);

    if (info.overflow_support) {
        faultedSubtest();
    }

    t.pass("§4.1.47");
    syscall.shutdown();
}
