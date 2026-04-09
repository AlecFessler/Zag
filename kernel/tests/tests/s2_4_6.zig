const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn exitingThread() void {
    syscall.thread_exit();
}

/// §2.4.6 — When a thread exits, its handle entry is cleared from its owning process's permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&exitingThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.6 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Wait for the thread to exit by yielding in a loop.
    var attempts: u32 = 0;
    while (attempts < 1000) : (attempts += 1) {
        syscall.thread_yield();

        // Check if the entry has been cleared.
        var still_present = false;
        for (0..128) |i| {
            if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
                // Check if it transitioned to exited state — it may briefly be exited before removal.
                const state = view[i].threadState();
                if (state == 5) {
                    // Exited but not yet cleared — keep waiting.
                    still_present = true;
                    break;
                }
                still_present = true;
                break;
            }
        }
        if (!still_present) {
            // Entry is gone — either entry_type changed to EMPTY or handle changed to U64_MAX.
            t.pass("§2.4.6");
            syscall.shutdown();
        }
    }

    // If we get here, the entry was never cleared.
    t.fail("§2.4.6 thread handle not cleared after exit");
    syscall.shutdown();
}
