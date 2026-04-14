const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.34 — On first boot, only `HANDLE_SELF` exists with `field0` = 0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Slot 0 should be HANDLE_SELF with field0 = 0 (crash_reason=none, restart_count=0)
    if (view[0].field0 != 0) {
        t.fail("§2.1.34 slot0 field0 != 0");
        syscall.shutdown();
    }
    // All other slots (1..128) should be empty on first boot, except device entries
    // which the kernel populates for the root service during boot.
    for (1..128) |i| {
        const etype = view[i].entry_type;
        if (etype != perm_view.ENTRY_TYPE_EMPTY and etype != perm_view.ENTRY_TYPE_DEVICE_REGION and etype != perm_view.ENTRY_TYPE_THREAD) {
            t.fail("§2.1.34 unexpected non-empty slot");
            syscall.shutdown();
        }
    }
    t.pass("§2.1.34");
    syscall.shutdown();
}
