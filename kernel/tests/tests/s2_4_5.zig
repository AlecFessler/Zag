const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const ENTRY_TYPE_CORE_PIN: u8 = 4;

/// §2.4.5 — Core pin user view `field0` = `core_id`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Pin to core 1.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    const pin_handle: u64 = @bitCast(ret);

    // Check field0 == core_id (should be 1).
    var core_id: u64 = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            core_id = view[i].field0;
            break;
        }
    }

    _ = syscall.revoke_perm(pin_handle);

    if (core_id == 1) {
        t.pass("§2.4.5");
    } else {
        t.fail("§2.4.5");
    }
    syscall.shutdown();
}
