const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// §3.3.15 — `reply` to a `send` clears the pending state.
///
/// Observability via SHM: the child signals buf[0] = 1 when ready,
/// buf[0] = 2 after it has reply'd the send, and buf[2] = 1 if its
/// follow-up recv returned successfully (not E_BUSY). If the reply to
/// send did NOT clear pending, the follow-up recv returns E_BUSY, which
/// the child writes into buf[1]. No thread_yield-based sync.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_reply_clears.ptr),
        children.child_iter1_c_reply_clears.len,
        child_rights,
    )));

    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm, shm_rights.bits() }, &setup_reply);

    // Wait until child is ready to receive the send.
    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Send (fire-and-forget). Child recvs and replies, clearing pending.
    const send_rc = syscall.ipc_send(ch, &.{0x42});
    if (send_rc != 0) {
        t.failWithVal("§3.3.15 [send failed]", 0, send_rc);
        syscall.shutdown();
    }

    // Wait until the child has replied to the send.
    while (@atomicLoad(u64, b0, .acquire) != 2) {
        _ = syscall.futex_wait(b0, 1, MAX_TIMEOUT);
    }

    // Call the child. This observes the post-reply state: the child must
    // be able to recv again, which requires pending state to have been
    // cleared by its reply to the send.
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(ch, &.{0x10}, &reply);

    const b1: *u64 = @ptrCast(@volatileCast(&buf[1]));
    const b2: *u64 = @ptrCast(@volatileCast(&buf[2]));
    const second_recv_err = @atomicLoad(u64, b1, .acquire);
    const second_recv_ok = @atomicLoad(u64, b2, .acquire);

    if (second_recv_err != 0) {
        t.failWithVal("§3.3.15 [second recv err]", 0, @bitCast(second_recv_err));
        syscall.shutdown();
    }
    if (second_recv_ok != 1) {
        t.fail("§3.3.15 [second recv not observed ok]");
        syscall.shutdown();
    }
    if (call_rc == 0 and reply.words[0] == 0x11) {
        t.pass("§3.3.15");
    } else {
        t.failWithVal("§3.3.15 [call]", 0, call_rc);
    }
    syscall.shutdown();
}
