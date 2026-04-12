const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;
const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// §3.3.19 — `send` never queues — it returns `E_AGAIN` if no receiver is waiting.
///
/// Distinct from §2.11.3: that test asserts only that the parent's
/// ipc_send returns E_AGAIN at the moment no receiver exists. This test
/// asserts the *behavioral* consequence of "never queues" — a child that
/// enters its first recv AFTER a prior ipc_send must see no message.
///
/// Protocol: parent maps SHM, cap-transfers it to the child, then waits
/// for the child to signal "ready". Parent issues ipc_send (returns
/// E_AGAIN since child is not in recv). Parent then wakes the child,
/// which does a NON-BLOCKING recv and reports the rc via SHM. If send
/// had queued, that recv would return 0 with the message; instead it
/// must return E_AGAIN, proving the message was not queued.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_late_recv.ptr),
        children.child_iter1_c_late_recv.len,
        child_rights,
    )));

    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm, shm_rights.bits() }, &setup_reply);

    // Wait for child to map SHM and signal ready. From this point the
    // child is NOT in recv — it is blocked on a futex.
    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Send: child is not waiting on recv, so this must return E_AGAIN.
    const send_rc = syscall.ipc_send(ch, &.{0x42});
    if (send_rc != E_AGAIN) {
        t.failWithVal("§3.3.19 [send rc]", E_AGAIN, send_rc);
        syscall.shutdown();
    }

    // Wake the child to do its non-blocking recv.
    const b1: *u64 = @ptrCast(@volatileCast(&buf[1]));
    @atomicStore(u64, b1, 1, .release);
    _ = syscall.futex_wake(b1, 1);

    // Wait for child's recv to complete.
    const b3: *u64 = @ptrCast(@volatileCast(&buf[3]));
    while (@atomicLoad(u64, b3, .acquire) == 0) {
        _ = syscall.futex_wait(b3, 0, MAX_TIMEOUT);
    }

    const b2: *u64 = @ptrCast(@volatileCast(&buf[2]));
    const child_recv_rc: i64 = @bitCast(@atomicLoad(u64, b2, .acquire));
    t.expectEqual("§3.3.19", E_AGAIN, child_recv_rc);
    syscall.shutdown();
}
