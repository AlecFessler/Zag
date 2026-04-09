const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    syscall.thread_exit();
}

/// §2.1.39 — The kernel updates a thread entry's `field0` in every permissions table that holds a handle to that thread on every thread state transition, and calls `syncUserView` on each such table
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&threadFn, 0, 4);
    if (ret < 0) {
        t.fail("§2.1.39 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Find the thread entry index
    var idx: ?usize = null;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            idx = i;
            break;
        }
    }

    if (idx == null) {
        t.fail("§2.1.39 thread entry not found");
        syscall.shutdown();
    }

    const entry_idx = idx.?;

    // Record the initial state
    const initial_state = view[entry_idx].threadState();

    // Yield repeatedly to give the child thread time to run and exit
    var attempts: u32 = 0;
    while (attempts < 10000) : (attempts += 1) {
        syscall.thread_yield();
        const current_state = view[entry_idx].threadState();
        if (current_state != initial_state) {
            // State transitioned -- kernel updated field0
            t.pass("§2.1.39");
            syscall.shutdown();
        }
    }

    // If the entry was cleared (type changed to EMPTY), that also counts as an update
    if (view[entry_idx].entry_type != perm_view.ENTRY_TYPE_THREAD) {
        t.pass("§2.1.39");
        syscall.shutdown();
    }

    t.fail("§2.1.39");
    syscall.shutdown();
}
