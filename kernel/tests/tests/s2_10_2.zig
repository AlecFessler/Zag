const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const ENTRY_TYPE_CORE_PIN: u8 = 4;

/// §2.10.2 — Core pin is created via `pin_exclusive` and revoked via `revoke_perm`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.pin_exclusive();
    const pin_handle: u64 = @bitCast(ret);

    // Revoke the core pin.
    const revoke_ret = syscall.revoke_perm(pin_handle);

    // Verify the slot is cleared.
    var still_exists = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            still_exists = true;
            break;
        }
    }

    if (revoke_ret == 0 and !still_exists) {
        t.pass("§2.10.2");
    } else {
        t.fail("§2.10.2");
    }
    syscall.shutdown();
}
