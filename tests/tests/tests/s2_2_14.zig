const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn workerThread() void {
    while (true) {
        syscall.thread_yield();
    }
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, handle: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            return &view[i];
        }
    }
    return null;
}

/// §2.2.14 — A thread entry's `field0` in the user view exposes the thread's stable kernel-assigned thread id in bits 0-31 and fault-handler exclude flags in bits 32-33.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Self thread's entry must have a non-zero tid.
    const self_ret = syscall.thread_self();
    if (self_ret < 0) {
        t.fail("§2.2.14 thread_self failed");
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(self_ret);
    const self_entry = findThreadEntry(view, self_handle) orelse {
        t.fail("§2.2.14 self thread entry missing");
        syscall.shutdown();
    };
    const self_tid = self_entry.threadTid();
    if (self_tid == 0) {
        t.fail("§2.2.14 self tid is 0");
        syscall.shutdown();
    }

    // A freshly spawned thread has its own distinct tid.
    const ret = syscall.thread_create(&workerThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.14 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    const entry = findThreadEntry(view, handle) orelse {
        t.fail("§2.2.14 spawned thread entry missing");
        syscall.shutdown();
    };
    const spawned_tid = entry.threadTid();
    if (spawned_tid == 0) {
        t.fail("§2.2.14 spawned tid is 0");
        syscall.shutdown();
    }
    if (spawned_tid == self_tid) {
        t.fail("§2.2.14 spawned tid collides with self tid");
        syscall.shutdown();
    }

    // The tid is stable — repeated observations (even across a suspend
    // which used to mutate the old state field) return the same value.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret < 0) {
        t.fail("§2.2.14 thread_suspend failed");
        syscall.shutdown();
    }
    if (findThreadEntry(view, handle)) |e2| {
        if (e2.threadTid() != spawned_tid) {
            t.fail("§2.2.14 tid changed after suspend");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.2.14 spawned entry missing after suspend");
        syscall.shutdown();
    }

    t.pass("§2.2.14");
    syscall.shutdown();
}
