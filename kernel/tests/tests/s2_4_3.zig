const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.3 — The core_pin handle is a revocation token only; it carries no rights bits (rights = 0).
pub fn main(pv_addr: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv_addr);

    // Pin to get a core_pin handle.
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret <= 0) {
        t.failWithVal("§2.4.3 pin", 1, ret);
        syscall.shutdown();
    }

    const handle: u64 = @bitCast(ret);

    // Find the core_pin entry and verify rights == 0.
    var found = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == handle) {
            if (e.rights == 0) {
                t.pass("§2.4.3 core_pin rights=0");
            } else {
                t.failWithVal("§2.4.3 core_pin rights", 0, @as(i64, e.rights));
            }
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.4.3 core_pin entry not found");
    }

    // Clean up.
    _ = syscall.revoke_perm(handle);
    syscall.shutdown();
}
