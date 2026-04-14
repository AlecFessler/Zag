const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.56 — The user view is sized to maximum permissions table capacity.
pub fn main(pv: u64) void {
    // The user view should be 128 entries × 32 bytes = 4096 bytes (1 page).
    // Verify we can read all 128 entries without faulting, and entry size is 32.
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    if (@sizeOf(perm_view.UserViewEntry) == 32) {
        // Access the last entry to confirm the full range is mapped.
        _ = view[127].entry_type;
        t.pass("§2.1.56");
    } else {
        t.fail("§2.1.56");
    }
    syscall.shutdown();
}
