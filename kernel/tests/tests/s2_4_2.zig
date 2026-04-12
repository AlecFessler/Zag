const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var helper_counter: u64 align(8) = 0;
var helper_release: u64 align(8) = 0;

fn helper() void {
    while (@atomicLoad(u64, &helper_release, .acquire) == 0) {
        _ = syscall.futex_wait(@ptrCast(&helper_release), 0, MAX_TIMEOUT);
    }
    _ = syscall.set_affinity(0x2);
    while (true) {
        _ = @atomicRmw(u64, &helper_counter, .Add, 1, .release);
        syscall.thread_yield();
    }
}

/// §2.4.2 — Core pin is created via `set_priority(.pinned)` and revoked via `revoke_perm` or `set_priority` with a non-pinned level.
/// After revoke, a second thread pinned to the same core can be scheduled.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn helper before pinning so its initial placement is not core 1.
    const h_ret = syscall.thread_create(&helper, 0, 4);
    if (h_ret < 0) {
        t.fail("§2.4.2 thread_create failed");
        syscall.shutdown();
    }

    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret < 0) {
        t.fail("§2.4.2 set_priority(PINNED) failed");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    // Revoke the core pin.
    const revoke_ret = syscall.revoke_perm(pin_handle);
    if (revoke_ret != 0) {
        t.fail("§2.4.2 revoke failed");
        syscall.shutdown();
    }

    // Verify the slot is cleared.
    var still_exists = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == perm_view.ENTRY_TYPE_CORE_PIN) {
            still_exists = true;
            break;
        }
    }
    if (still_exists) {
        t.fail("§2.4.2 pin entry persisted after revoke");
        syscall.shutdown();
    }

    // Release the helper. It will set affinity to core 1 and must now run,
    // proving core 1 is schedulable again after revoke.
    @atomicStore(u64, &helper_release, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&helper_release), 1);

    var attempts: u32 = 0;
    while (attempts < 1000000) : (attempts += 1) {
        if (@atomicLoad(u64, &helper_counter, .acquire) > 0) break;
        syscall.thread_yield();
    }
    if (@atomicLoad(u64, &helper_counter, .acquire) == 0) {
        t.fail("§2.4.2 second thread could not run on unpinned core");
        syscall.shutdown();
    }

    t.pass("§2.4.2");
    syscall.shutdown();
}
