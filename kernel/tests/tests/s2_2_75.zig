const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.2.75 — `set_priority` with a non-pinned level while currently pinned implicitly revokes the `core_pin` handle, restores the pre-pin affinity mask, and applies the new priority.
pub fn main(pv_addr: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv_addr);

    // Pin on core 0.
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret <= 0) {
        t.failWithVal("§2.2.75 setup pin", 1, pin_ret);
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(pin_ret);

    // Verify core_pin entry exists.
    var found_before = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == pin_handle) {
            found_before = true;
            break;
        }
    }
    if (!found_before) {
        t.fail("§2.2.75 core_pin not found before unpin");
        syscall.shutdown();
    }

    // Unpin by setting a non-pinned priority.
    const ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectEqual("§2.2.75 unpin", E_OK, ret);

    // Verify core_pin handle is gone.
    var found_after = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == pin_handle) {
            found_after = true;
            break;
        }
    }
    if (!found_after) {
        t.pass("§2.2.75 core_pin revoked");
    } else {
        t.fail("§2.2.75 core_pin still present after unpin");
    }

    // Verify the thread truly accepted a non-pinned priority and is not still
    // internally pinned: cycle through HIGH and back to NORMAL. Both should
    // succeed, proving the priority system treats the thread as unpinned.
    const r_high = syscall.set_priority(syscall.PRIORITY_HIGH);
    t.expectEqual("§2.2.75 set HIGH after unpin", E_OK, r_high);

    const r_normal = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectEqual("§2.2.75 set NORMAL after unpin", E_OK, r_normal);

    syscall.shutdown();
}
