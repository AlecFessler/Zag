const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    syscall.thread_exit();
}

/// §2.1.39 — The user permissions view is kept in sync with the kernel permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.1.39 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Insert was a mutation: the new thread entry must be visible.
    var idx: ?usize = null;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            idx = i;
            break;
        }
    }

    if (idx == null) {
        t.fail("§2.1.39 thread entry not found after insert");
        syscall.shutdown();
    }

    const entry_idx = idx.?;

    // Yield until the child thread exits — exit removes its perm slot, and
    // removal is a table mutation that must sync the user view.
    var attempts: u32 = 0;
    while (attempts < 10000) : (attempts += 1) {
        syscall.thread_yield();
        if (view[entry_idx].entry_type != perm_view.ENTRY_TYPE_THREAD) {
            t.pass("§2.1.39");
            syscall.shutdown();
        }
    }

    t.fail("§2.1.39");
    syscall.shutdown();
}
