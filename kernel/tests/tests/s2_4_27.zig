const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const INF: u64 = @bitCast(@as(i64, -1));

var futex_val: u64 align(8) = 0;
var helper_counter: u64 align(8) = 0;
var pinned_woke: u64 align(8) = 0;

fn helper() void {
    // Wait for the pinned thread to block, then wake it.
    // Keep incrementing a counter to show we're running.
    while (@atomicLoad(u64, &futex_val, .seq_cst) == 0) {
        syscall.thread_yield();
    }

    // Wake the pinned thread.
    @atomicStore(u64, &futex_val, 2, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);

    // After waking the pinned thread, keep counting.
    // If the pinned thread preempts us immediately, we won't
    // get many iterations before it sets pinned_woke.
    var i: u64 = 0;
    while (@atomicLoad(u64, &pinned_woke, .seq_cst) == 0) : (i += 1) {
        // Tight loop — no yield. If pinned thread preempts us,
        // we stop counting.
    }
    @atomicStore(u64, &helper_counter, i, .seq_cst);
    while (true) syscall.thread_yield();
}

/// §2.4.27 — When a pinned thread becomes ready again (futex wake or IPC delivery), the kernel immediately preempts whatever thread is running on the pinned core regardless of that thread's priority.
///
/// Pin main to core 0. Block on futex. Helper (on core 0) wakes us and
/// starts counting. If the kernel immediately preempts the helper, the
/// counter should be very low (0-2 iterations at most).
pub fn main(_: u64) void {
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret <= 0) {
        t.failWithVal("§2.4.27 pin failed", 1, pin_ret);
        syscall.shutdown();
    }

    _ = syscall.thread_create(@ptrCast(&helper), 0, 4);

    // Signal helper that we're about to block.
    @atomicStore(u64, &futex_val, 1, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);

    // Block on futex — wait for helper to change value to 2.
    _ = syscall.futex_wait(@ptrCast(&futex_val), 1, INF);

    // We were woken — signal that we're running.
    @atomicStore(u64, &pinned_woke, 1, .seq_cst);

    // Give helper a chance to store its counter.
    for (0..5) |_| syscall.thread_yield();

    const count = @atomicLoad(u64, &helper_counter, .seq_cst);
    // The helper should have been preempted almost immediately.
    // Allow a small window (< 100 iterations).
    if (count < 100) {
        t.pass("§2.4.27 pinned thread preempted helper on wake");
    } else {
        t.failWithVal("§2.4.27 helper ran too long after wake", 0, @bitCast(count));
    }

    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
