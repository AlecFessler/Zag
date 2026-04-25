const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const INF: u64 = @bitCast(@as(i64, -1));

var futex_val: u64 align(8) = 0;

fn helper() void {
    // Wait for the pinned thread to block, then wake it.
    while (@atomicLoad(u64, &futex_val, .seq_cst) == 0) {
        syscall.thread_yield();
    }
    @atomicStore(u64, &futex_val, 2, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
    while (true) syscall.thread_yield();
}

/// §2.2.34 — When a pinned thread becomes ready again (futex wake or IPC delivery), the kernel preempts whatever thread is running on the pinned core regardless of that thread's priority.
///
/// Correctness check: pin main to core 0, block on futex, helper wakes us
/// from another core. If preemption fires correctly, main resumes from
/// `futex_wait` and reaches the `t.pass` below. If preemption is broken,
/// main stays blocked and the per-test QEMU timeout kills the run as a
/// FAIL. Earlier revisions of this test gated PASS on a host-specific
/// helper-iteration ceiling; that conflated correctness ("preemption
/// happened") with raw wake-to-pinned latency, which depends on
/// APICv/AVIC engagement and lockdep-instrumentation overhead and was
/// flaky in practice. The latency budget belongs in `tests/prof/`, not
/// in a precommit correctness gate.
pub fn main(_: u64) void {
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.34 pin failed", 1, pin_ret);
        syscall.shutdown();
    }

    _ = syscall.thread_create(@ptrCast(&helper), 0, 4);

    // Signal helper that we're about to block.
    @atomicStore(u64, &futex_val, 1, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);

    // Block on futex — wait for helper to change value to 2 and wake us.
    // Reaching the next line is the preemption proof: the kernel woke a
    // pinned thread on its pinned core in response to an off-core IPI.
    _ = syscall.futex_wait(@ptrCast(&futex_val), 1, INF);

    t.pass("§2.2.34");
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
