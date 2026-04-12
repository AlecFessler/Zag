const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const INF: u64 = @bitCast(@as(i64, -1));

var futex_val: u64 align(8) = 0;
var helper_ran: u64 align(8) = 0;

fn helper() void {
    // This helper runs on whatever core is available.
    // If the pinned thread's core was released when it blocked,
    // this helper should be able to run and increment the counter.
    @atomicStore(u64, &helper_ran, 1, .seq_cst);
    _ = syscall.futex_wake(@ptrCast(&helper_ran), 1);
    // Spin until pinned thread wakes and shuts down.
    while (true) syscall.thread_yield();
}

/// §2.2.33 — When a pinned thread blocks (on a futex or IPC recv), it temporarily releases its core.
///
/// Pin the main thread on core 0. Create a helper thread with affinity to
/// core 0. Main blocks on a futex. If the core was released, the helper
/// should run and set a flag. Another mechanism wakes the main thread to
/// verify.
pub fn main(_: u64) void {
    // Pin main thread to core 0.
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret <= 0) {
        t.failWithVal("§2.2.33 pin failed", 1, pin_ret);
        syscall.shutdown();
    }

    // Create helper on core 0.
    const th = syscall.thread_create(@ptrCast(&helper), 0, 4);
    if (th <= 0) {
        t.failWithVal("§2.2.33 thread_create", 1, th);
        syscall.shutdown();
    }

    // Block on futex — should release core 0, letting helper run.
    // Use a short timeout so we wake up even if no one wakes us.
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, 50_000_000);

    // Give a few yields for the helper to have set the flag.
    for (0..10) |_| syscall.thread_yield();

    const ran = @atomicLoad(u64, &helper_ran, .seq_cst);
    if (ran == 1) {
        t.pass("§2.2.33 helper ran on released core");
    } else {
        t.fail("§2.2.33 helper did not run while pinned thread blocked");
    }

    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
