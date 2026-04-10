const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

// Helper thread blocks on a futex until the main thread pins core 1 and
// releases it. It then sets its affinity to core 1 and busy-bumps a counter.
// As long as the main thread holds the pin on core 1, this counter must
// remain zero. After revoke, the counter must finally increment.
var helper_counter: u64 align(8) = 0;
var helper_release: u64 align(8) = 0;
var helper_affinity_set: u64 align(8) = 0;

fn helper() void {
    // Block until main pins core 1 and wakes us.
    while (@atomicLoad(u64, &helper_release, .acquire) == 0) {
        _ = syscall.futex_wait(@ptrCast(&helper_release), 0, MAX_TIMEOUT);
    }
    // Constrain ourselves to core 1. This syscall runs on whatever core
    // we were scheduled on, then the next scheduling decision places us
    // on core 1's queue, where we must block because the pin owns it.
    _ = syscall.set_affinity(0x2);
    @atomicStore(u64, &helper_affinity_set, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&helper_affinity_set), 1);
    // Yield BEFORE touching the counter. We may currently be running on
    // a non-pinned core (affinity was just changed); the scheduler's
    // affinity check on the next tick migrates us to core 1's queue,
    // where the pin starves us. Only after the pin is revoked can we
    // actually bump the counter.
    syscall.thread_yield();
    while (true) {
        _ = @atomicRmw(u64, &helper_counter, .Add, 1, .release);
        syscall.thread_yield();
    }
}

/// §2.10.1 — `pin_exclusive` grants exclusive, non-preemptible core ownership.
///
/// Spawns a helper thread affined to the same core as the pinned thread;
/// while we hold the pin, the helper must make no progress (starved).
/// After revoke, the helper must finally run.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn helper BEFORE pinning so it ends up on a different core than
    // the one we will pin. It will block on helper_release until we signal.
    const h_ret = syscall.thread_create(&helper, 0, 4);
    if (h_ret < 0) {
        t.fail("§2.10.1 thread_create failed");
        syscall.shutdown();
    }

    // Put main on core 1 and pin it.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    const ret = syscall.pin_exclusive();
    if (ret < 0) {
        t.fail("§2.10.1 pin_exclusive failed");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    // Verify core_pin entry exists.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == perm_view.ENTRY_TYPE_CORE_PIN) {
            found = true;
            break;
        }
    }
    if (!found) {
        _ = syscall.revoke_perm(pin_handle);
        t.fail("§2.10.1 pin entry missing");
        syscall.shutdown();
    }

    // Release helper — it will set its affinity to core 1 then block.
    @atomicStore(u64, &helper_release, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&helper_release), 1);

    // Spin on our pinned core — helper must not make progress even though
    // we yield. (Yield on a pinned core returns without actually giving the
    // core up; the only runnable thread is us.)
    var i: u32 = 0;
    while (i < 2000) : (i += 1) {
        syscall.thread_yield();
    }
    const starved_counter = @atomicLoad(u64, &helper_counter, .acquire);
    if (starved_counter != 0) {
        _ = syscall.revoke_perm(pin_handle);
        t.fail("§2.10.1 helper ran while pinned");
        syscall.shutdown();
    }

    // Revoke pin. Helper should now finally run.
    _ = syscall.revoke_perm(pin_handle);

    // Wait until helper increments. If it never does, fail.
    var attempts: u32 = 0;
    while (attempts < 1000000) : (attempts += 1) {
        if (@atomicLoad(u64, &helper_counter, .acquire) > 0) break;
        syscall.thread_yield();
    }
    if (@atomicLoad(u64, &helper_counter, .acquire) == 0) {
        t.fail("§2.10.1 helper never ran after unpin");
        syscall.shutdown();
    }

    t.pass("§2.10.1");
    syscall.shutdown();
}
