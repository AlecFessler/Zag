const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

fn exitImmediately() void {
    syscall.thread_exit();
}

/// §4.30.6 — `thread_suspend` on a thread in `.exited` state returns `E_BADHANDLE`.
///
/// Poll the perm view for entry removal instead of relying on a fixed yield
/// count to "wait for exit" — per §2.12.x thread entries are removed on exit.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const thread_handle = syscall.thread_create(&exitImmediately, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.30.6 thread_create", 1, thread_handle);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(thread_handle);

    // Find the thread slot so we can observe removal.
    var slot: usize = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            slot = i;
            break;
        }
    }
    if (slot == 0xFFFF) {
        t.fail("§4.30.6 thread slot not found");
        syscall.shutdown();
    }

    // Poll until the thread's perm entry is gone (thread exited and was reaped).
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        const et = view[slot].entry_type;
        const h = view[slot].handle;
        if (et != perm_view.ENTRY_TYPE_THREAD or h != handle) break;
        syscall.thread_yield();
    }
    if (attempts == 100000) {
        t.fail("§4.30.6 thread entry never removed");
        syscall.shutdown();
    }

    // Thread has exited; suspend should return E_BADHANDLE.
    const ret = syscall.thread_suspend(handle);
    t.expectEqual("§4.30.6", E_BADHANDLE, ret);
    syscall.shutdown();
}
