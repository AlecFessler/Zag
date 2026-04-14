const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.35 — `set_affinity` constrains the calling thread's core affinity; the change takes effect at the next scheduling decision.
///
/// Set affinity to core 1 only, yield, then pin. If pinning succeeds the
/// thread's field1 (pinned core) must match the affinity core,
/// proving the thread actually migrated to core 1.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Constrain to core 1.
    const ret = syscall.set_affinity(0b10);
    t.expectOk("§2.2.35 set_affinity core 1", ret);

    // Yield to trigger a scheduling decision with the new affinity.
    syscall.thread_yield();

    // If we're still running, the affinity change took effect.
    t.pass("§2.2.35 thread still runs after affinity change");

    // Strengthen: pin on the constrained core. The pin succeeds only if the
    // thread is on a core allowed by its affinity mask (core 1). The return
    // value is the pinned core ID — verify it is 1.
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.35 pin failed", 1, pin_ret);
        syscall.shutdown();
    }

    if (pin_ret == 1) {
        t.pass("§2.2.35 pinned on core 1 (confirms migration)");
    } else {
        t.failWithVal("§2.2.35 expected core 1", 1, pin_ret);
    }

    // Verify thread entry field1 also shows core 1.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            if (e.field1 != 1) {
                t.failWithVal("§2.2.35 field1 mismatch", 1, @bitCast(e.field1));
            }
            break;
        }
    }

    // Clean up: unpin.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);

    syscall.shutdown();
}
