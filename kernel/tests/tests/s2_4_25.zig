const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

fn findCorePinEntry(view: [*]const perm_view.UserViewEntry, handle: u64) bool {
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == handle)
            return true;
    }
    return false;
}

/// §2.4.25 — There are two ways to unpin: (1) call `revoke_perm` on the `core_pin` handle, which restores the pre-pin affinity mask and drops priority to the pre-pin level; (2) call `set_priority` with any non-pinned level, which implicitly revokes the `core_pin` handle, restores affinity, and applies the new priority.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // --- Path 1: revoke_perm on the core_pin handle ---
    _ = syscall.set_affinity(0b10);
    const pin1 = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin1 <= 0) {
        t.failWithVal("§2.4.25 pin1 failed", 1, pin1);
        syscall.shutdown();
    }
    const handle1: u64 = @bitCast(pin1);

    // Revoke the core_pin handle to unpin.
    const revoke_ret = syscall.revoke_perm(handle1);
    t.expectOk("§2.4.25 path1 revoke_perm", revoke_ret);

    // Verify handle is gone (revoke again should fail).
    const revoke2 = syscall.revoke_perm(handle1);
    t.expectEqual("§2.4.25 path1 handle gone", E_BADHANDLE, revoke2);

    // Verify we can set_affinity again (no longer pinned).
    const aff_ret = syscall.set_affinity(0b1);
    t.expectOk("§2.4.25 path1 affinity restored", aff_ret);

    // --- Path 2: set_priority to non-pinned ---
    _ = syscall.set_affinity(0b10);
    const pin2 = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin2 <= 0) {
        t.failWithVal("§2.4.25 pin2 failed", 1, pin2);
        syscall.shutdown();
    }
    const handle2: u64 = @bitCast(pin2);

    // Set to NORMAL — should implicitly revoke the core_pin handle.
    const set_ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.4.25 path2 set_priority NORMAL", set_ret);

    // The core_pin handle should be gone from the perm_view.
    if (!findCorePinEntry(view, handle2)) {
        t.pass("§2.4.25 path2 core_pin handle revoked");
    } else {
        t.fail("§2.4.25 path2 core_pin handle still present");
    }

    syscall.shutdown();
}
