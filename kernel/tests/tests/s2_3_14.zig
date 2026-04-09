const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const ENTRY_TYPE_CORE_PIN: u8 = 4;

/// §2.3.14 — Revoking a core pin unpins the thread, restores preemptive scheduling, and clears the slot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Pin to core 0.
    _ = syscall.set_affinity(0b1);
    const pin_handle: u64 = @bitCast(@as(i64, syscall.pin_exclusive()));
    // Verify core_pin entry exists.
    var pin_found = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            pin_found = true;
            break;
        }
    }
    // Revoke the pin.
    const revoke_ret = syscall.revoke_perm(pin_handle);
    // Verify the core_pin slot is cleared.
    var pin_still_found = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            pin_still_found = true;
            break;
        }
    }
    if (pin_found and revoke_ret == 0 and !pin_still_found) {
        t.pass("§2.3.14");
    } else {
        t.fail("§2.3.14");
    }
    syscall.shutdown();
}
