const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    for (0..100) |_| syscall.thread_yield();
    syscall.thread_exit();
}

/// §2.4.20 — `pin_exclusive` requires both `ProcessRights.pin_exclusive` on slot 0 AND `ThreadHandleRights.set_affinity` on the thread handle; the thread handle must refer to the calling thread; returns `E_INVAL` if it refers to any other thread
///           `ThreadHandleRights.set_affinity` on the thread handle; the thread handle must
///           refer to the calling thread; returns `E_INVAL` if it refers to any other thread.
///
/// Root has both required process and thread handle rights. We test:
///   1. pin_exclusive_thread with another thread's handle → E_INVAL (-1)
///   2. pin_exclusive_thread with own handle (thread_self) → E_OK (0)
///   3. pin_exclusive_thread with invalid handle → E_BADHANDLE (-3)
pub fn main(_: u64) void {
    // First, set our affinity to a single core so pin_exclusive can succeed.
    const self_ret = syscall.thread_self();
    if (self_ret <= 0) {
        t.failWithVal("§2.4.20 thread_self", 1, self_ret);
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(self_ret);

    // Create a second thread.
    const create_ret = syscall.thread_create(&worker, 0, 4);
    if (create_ret <= 0) {
        t.failWithVal("§2.4.20 thread_create", 1, create_ret);
        syscall.shutdown();
    }
    const other_handle: u64 = @bitCast(create_ret);

    // pin_exclusive with another thread's handle → E_INVAL (-1).
    const pin_other = syscall.pin_exclusive_thread(other_handle);
    if (pin_other == -1) {
        t.pass("§2.4.20 other thread E_INVAL");
    } else {
        t.failWithVal("§2.4.20 other thread E_INVAL", -1, pin_other);
    }

    // pin_exclusive with own handle → should succeed.
    // First ensure single-core affinity.
    _ = syscall.set_affinity_thread(self_handle, 0x1);
    const pin_self = syscall.pin_exclusive_thread(self_handle);
    if (pin_self == 0) {
        t.pass("§2.4.20 self pin");
    } else {
        t.failWithVal("§2.4.20 self pin", 0, pin_self);
    }

    // pin_exclusive with invalid handle → E_BADHANDLE (-3).
    const pin_bad = syscall.pin_exclusive_thread(0xDEAD);
    if (pin_bad == -3) {
        t.pass("§2.4.20 bad handle");
    } else {
        t.failWithVal("§2.4.20 bad handle", -3, pin_bad);
    }

    // Clean up.
    _ = syscall.thread_kill(other_handle);
    syscall.shutdown();
}
