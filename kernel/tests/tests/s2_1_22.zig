const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.22 — On first boot, process entry `field0` = 0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const slot0 = view[0];
    if (slot0.field0 == 0) {
        t.pass("§2.1.22");
    } else {
        t.fail("§2.1.22");
    }
    syscall.shutdown();
}
