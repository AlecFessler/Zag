const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn loopForever() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// §4.32.1 — `thread_kill` returns `E_OK` on success.
///
/// Observable side effect via the perm view: after kill, the thread entry
/// disappears (or its entry_type flips away from THREAD).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§4.32.1 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Locate the entry slot so we can observe its removal.
    var slot: usize = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            slot = i;
            break;
        }
    }
    if (slot == 0xFFFF) {
        t.fail("§4.32.1 thread entry not found pre-kill");
        syscall.shutdown();
    }

    for (0..5) |_| syscall.thread_yield();

    const kill_ret = syscall.thread_kill(handle);
    t.expectEqual("§4.32.1 kill rc", E_OK, kill_ret);

    // Poll for removal.
    var attempts: u32 = 0;
    while (attempts < 10000) : (attempts += 1) {
        const et = view[slot].entry_type;
        const h = view[slot].handle;
        if (et != perm_view.ENTRY_TYPE_THREAD or h != handle) {
            t.pass("§4.32.1 thread entry removed");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }
    t.fail("§4.32.1 thread entry persisted after kill");
    syscall.shutdown();
}
