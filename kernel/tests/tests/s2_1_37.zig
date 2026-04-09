const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {}
    syscall.thread_exit();
}

/// §2.1.37 — Thread entry `field0` encodes `state(u8, bits 0–7) | core_id(u8, bits 8–15)`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.1.37 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            const state = view[i].threadState();
            // A newly created thread should be ready (0) or running (1)
            if (state <= 1) {
                found = true;
            }
            break;
        }
    }

    if (found) {
        t.pass("§2.1.37");
    } else {
        t.fail("§2.1.37");
    }
    syscall.shutdown();
}
