const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

// Helper thread targets core 1 with a counter it bumps in a tight loop.
// Pinned thread is also on core 1, so this thread must be starved until
// revoke_perm undoes the pin.
var helper_counter: u64 align(8) = 0;
var helper_started: u64 align(8) = 0;

fn helper() void {
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    @atomicStore(u64, &helper_started, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&helper_started), 1);
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

    // Pin ourselves on core 1.
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

    // Spawn helper targeting the same core. It will run on a different core
    // temporarily until it calls set_affinity; after that it must block
    // because core 1 is owned by us.
    const h_ret = syscall.thread_create(&helper, 0, 4);
    if (h_ret < 0) {
        _ = syscall.revoke_perm(pin_handle);
        t.fail("§2.10.1 thread_create failed");
        syscall.shutdown();
    }

    // Wait for helper to at least reach set_affinity. The helper signals
    // helper_started *after* set_affinity, which it cannot do while we hold
    // the pin (it targets our core). So we must not wait on helper_started
    // while pinned — instead give the helper a bounded window on *other*
    // cores: since we pinned core 1 and the helper was created on some
    // other core, it can run set_affinity then block. We simply yield many
    // times from our pinned core to prove the scheduler keeps us running.
    //
    // After that window, snapshot the helper counter. It must still be 0
    // because the helper's affinity was set to core 1 which is owned by us.
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
    while (attempts < 100000) : (attempts += 1) {
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
