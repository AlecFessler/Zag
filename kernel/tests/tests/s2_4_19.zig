const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    for (0..100) |_| syscall.thread_yield();
    syscall.thread_exit();
}

/// §2.4.19 — `set_affinity` requires both `ProcessRights.set_affinity` on slot 0 AND `ThreadHandleRights.set_affinity` on the target thread handle; returns `E_PERM` if either is absent
///           `ThreadHandleRights.set_affinity` on the target thread handle; returns `E_PERM`
///           if either is absent.
///
/// Root has both ProcessRights.set_affinity and full ThreadHandleRights (including set_affinity),
/// so set_affinity_thread should succeed. We test:
///   1. set_affinity_thread with own thread handle (from thread_self) → E_OK
///   2. set_affinity_thread with a created thread handle → E_OK
///   3. set_affinity_thread with invalid handle → E_BADHANDLE (-3)
pub fn main(_: u64) void {
    // Get our own thread handle.
    const self_ret = syscall.thread_self();
    if (self_ret <= 0) {
        t.failWithVal("§2.4.19 thread_self", 1, self_ret);
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(self_ret);

    // Set affinity on self to core 0 (bit 0).
    const aff_ret = syscall.set_affinity_thread(self_handle, 0x1);
    if (aff_ret == 0) {
        t.pass("§2.4.19 set_affinity self");
    } else {
        t.failWithVal("§2.4.19 set_affinity self", 0, aff_ret);
    }

    // Create a thread and set its affinity.
    const create_ret = syscall.thread_create(&worker, 0, 4);
    if (create_ret <= 0) {
        t.failWithVal("§2.4.19 thread_create", 1, create_ret);
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(create_ret);

    const aff_ret2 = syscall.set_affinity_thread(thread_handle, 0x1);
    if (aff_ret2 == 0) {
        t.pass("§2.4.19 set_affinity other thread");
    } else {
        t.failWithVal("§2.4.19 set_affinity other thread", 0, aff_ret2);
    }

    // Invalid handle should return E_BADHANDLE, not E_PERM.
    const bad_ret = syscall.set_affinity_thread(0xDEAD, 0x1);
    if (bad_ret == -3) {
        t.pass("§2.4.19 bad handle");
    } else {
        t.failWithVal("§2.4.19 bad handle", -3, bad_ret);
    }

    // Clean up.
    _ = syscall.thread_kill(thread_handle);
    syscall.shutdown();
}
