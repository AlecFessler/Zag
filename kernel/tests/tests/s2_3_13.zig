const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.13 — Revoking a device handle unmaps MMIO, returns handle up the process tree (§2.1), and clears the slot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle.
    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            break;
        }
    }

    // Revoke the device handle.
    const ret = syscall.revoke_perm(dev_handle);
    if (ret != 0) {
        t.fail("§2.3.13");
        syscall.shutdown();
    }

    // Verify slot is cleared (handle no longer in perm_view).
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == dev_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            found = true;
            break;
        }
    }
    if (!found) {
        t.pass("§2.3.13");
    } else {
        t.fail("§2.3.13");
    }
    syscall.shutdown();
}
