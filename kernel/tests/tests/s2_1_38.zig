const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {}
    syscall.thread_exit();
}

/// §2.1.38 — Thread entry `field1` exposes the fault-handler exclude flags: bit 0 = `exclude_oneshot`, bit 1 = `exclude_permanent`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.1.38 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].field1 == 0) {
                found = true;
            }
            break;
        }
    }

    if (found) {
        t.pass("§2.1.38");
    } else {
        t.fail("§2.1.38");
    }
    syscall.shutdown();
}
