const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.28 — `set_affinity` constrains the calling thread's core affinity; the change takes effect at the next scheduling decision.
///
/// Set affinity to core 1 only, yield, then pin. If pinning succeeds the
/// core_pin entry's field0 (pinned core) must match the affinity core,
/// proving the thread actually migrated to core 1.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Constrain to core 1.
    const ret = syscall.set_affinity(0b10);
    t.expectOk("§2.4.28 set_affinity core 1", ret);

    // Yield to trigger a scheduling decision with the new affinity.
    syscall.thread_yield();

    // If we're still running, the affinity change took effect.
    t.pass("§2.4.28 thread still runs after affinity change");

    // Strengthen: pin on the constrained core. The pin succeeds only if the
    // thread is on a core allowed by its affinity mask (core 1). The core_pin
    // entry's field0 records the pinned core — verify it is 1.
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret <= 0) {
        t.failWithVal("§2.4.28 pin failed", 1, pin_ret);
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(pin_ret);

    var found_core: bool = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == pin_handle) {
            // field0 is the pinned core index.
            if (e.field0 == 1) {
                found_core = true;
            }
            break;
        }
    }
    if (found_core) {
        t.pass("§2.4.28 pinned on core 1 (confirms migration)");
    } else {
        t.fail("§2.4.28 core_pin entry missing or wrong core");
    }

    // Clean up: unpin.
    _ = syscall.revoke_perm(pin_handle);

    syscall.shutdown();
}
