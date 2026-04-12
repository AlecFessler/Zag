const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.6 — Core pin user view `field1` = 0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret < 0) {
        t.fail("§2.4.6 set_priority(PINNED) failed");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    var field1: u64 = 0xDEADBEEF;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == perm_view.ENTRY_TYPE_CORE_PIN) {
            field1 = view[i].field1;
            break;
        }
    }

    _ = syscall.revoke_perm(pin_handle);

    if (field1 == 0) {
        t.pass("§2.4.6");
    } else {
        t.failWithVal("§2.4.6", 0, @bitCast(field1));
    }
    syscall.shutdown();
}
