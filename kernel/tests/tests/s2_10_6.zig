const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const ENTRY_TYPE_CORE_PIN: u8 = 4;

/// §2.10.6 — Core pin user view `field1` = `thread_tid`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();

    const ret = syscall.pin_exclusive();
    const pin_handle: u64 = @bitCast(ret);

    // Check field1 = thread_tid. The initial thread should have tid 0.
    var tid: u64 = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            tid = view[i].field1;
            break;
        }
    }

    _ = syscall.revoke_perm(pin_handle);

    // Initial thread tid should be 0.
    if (tid == 0) {
        t.pass("§2.10.6");
    } else {
        t.fail("§2.10.6");
    }
    syscall.shutdown();
}
