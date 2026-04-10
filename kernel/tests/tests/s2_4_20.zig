const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

fn worker() void {
    for (0..100) |_| syscall.thread_yield();
    syscall.thread_exit();
}

/// §2.4.20 — `pin_exclusive` requires both `ProcessRights.pin_exclusive` on slot 0 AND `ThreadHandleRights.set_affinity` on the thread handle; the thread handle must refer to the calling thread; returns `E_INVAL` if it refers to any other thread.
///
/// Root has both required process and thread handle rights. We test:
///   1. pin_exclusive with another thread's handle → E_INVAL (-1)
///   2. pin_exclusive with own handle → E_OK
///   3. pin_exclusive with an invalid handle → E_BADHANDLE (-3)
///   4. Child without ProcessRights.pin_exclusive calling pin_exclusive on
///      its own thread → E_PERM (missing ProcessRights branch).
pub fn main(_: u64) void {
    const self_ret = syscall.thread_self();
    if (self_ret <= 0) {
        t.failWithVal("§2.4.20 thread_self", 1, self_ret);
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(self_ret);

    const create_ret = syscall.thread_create(&worker, 0, 4);
    if (create_ret <= 0) {
        t.failWithVal("§2.4.20 thread_create", 1, create_ret);
        syscall.shutdown();
    }
    const other_handle: u64 = @bitCast(create_ret);

    // 1. Other thread's handle → E_INVAL.
    const pin_other = syscall.pin_exclusive_thread(other_handle);
    if (pin_other == -1) {
        t.pass("§2.4.20 other thread E_INVAL");
    } else {
        t.failWithVal("§2.4.20 other thread E_INVAL", -1, pin_other);
    }

    // Clean up the worker before pinning so no other thread can contend
    // for our chosen core.
    _ = syscall.thread_kill(other_handle);
    for (0..20) |_| syscall.thread_yield();

    // 2. Own handle → success (after single-core affinity to a non-0 core).
    _ = syscall.set_affinity_thread(self_handle, 0x2);
    syscall.thread_yield();
    const pin_self = syscall.pin_exclusive_thread(self_handle);
    if (pin_self > 0) {
        t.pass("§2.4.20 self pin");
        _ = syscall.revoke_perm(@bitCast(pin_self));
    } else {
        t.failWithVal("§2.4.20 self pin", 1, pin_self);
    }

    // 3. Invalid handle → E_BADHANDLE.
    const pin_bad = syscall.pin_exclusive_thread(0xDEAD);
    if (pin_bad == -3) {
        t.pass("§2.4.20 bad handle");
    } else {
        t.failWithVal("§2.4.20 bad handle", -3, pin_bad);
    }

    // 4. Missing ProcessRights.pin_exclusive → E_PERM. child_try_pin_exclusive
    //    sets single-core affinity and calls pin_exclusive() on its own thread
    //    (thread handle = thread_self), so the ThreadHandleRights branch is
    //    satisfied (proc_create grants full ThreadHandleRights) while
    //    ProcessRights.pin_exclusive is absent.
    const child_rights = (perms.ProcessRights{ .set_affinity = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_pin_exclusive.ptr),
        children.child_try_pin_exclusive.len,
        child_rights,
    )));
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{}, &reply);
    if (rc != 0) {
        t.failWithVal("§2.4.20 child ipc_call", 0, rc);
        syscall.shutdown();
    }
    const child_result: i64 = @bitCast(reply.words[0]);
    if (child_result == E_PERM) {
        t.pass("§2.4.20 missing ProcessRights E_PERM");
    } else {
        t.failWithVal("§2.4.20 missing ProcessRights E_PERM", E_PERM, child_result);
    }

    syscall.shutdown();
}
