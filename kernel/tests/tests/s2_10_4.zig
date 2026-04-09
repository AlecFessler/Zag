const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var ran_on_pinned_core: u64 align(8) = 0;

fn try_run_on_core1() void {
    // Restrict to core 1 only, then yield to move there.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    // If we reach here, we're running on core 1.
    @atomicStore(u64, &ran_on_pinned_core, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&ran_on_pinned_core), 1);
}

/// §2.10.4 — After `pin_exclusive`, only the pinned thread executes on that core.
pub fn main(_: u64) void {
    // Pin main thread to core 1.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    const ret = syscall.pin_exclusive();
    if (ret < 0) {
        t.fail("§2.10.4");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    // Spawn thread that tries to run on core 1.
    // It sets affinity to core 1 and yields — but core 1 is exclusively pinned,
    // so the scheduler can't place it there. It stays in the ready queue.
    _ = syscall.thread_create(&try_run_on_core1, 0, 4);

    // Give scheduler many chances to schedule the thread on core 1.
    for (0..100) |_| syscall.thread_yield();

    // Thread should NOT have reached its flag-set code (core 1 is exclusive).
    const ran_while_pinned = @atomicLoad(u64, &ran_on_pinned_core, .acquire) != 0;

    // Unpin core 1.
    _ = syscall.revoke_perm(pin_handle);

    // Now the thread can be scheduled on core 1. Wait for it.
    var attempts: u32 = 0;
    while (@atomicLoad(u64, &ran_on_pinned_core, .acquire) == 0 and attempts < 100000) : (attempts += 1) {
        syscall.thread_yield();
    }
    const ran_after_unpin = @atomicLoad(u64, &ran_on_pinned_core, .acquire) != 0;

    if (!ran_while_pinned and ran_after_unpin) {
        t.pass("§2.10.4");
    } else {
        t.fail("§2.10.4");
    }
    syscall.shutdown();
}
