const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

/// §2.11.11 — `recv` with blocking flag blocks when the queue is empty.
///
/// Child maps a shared buffer, records pre-recv and post-recv timestamps,
/// and flips a state sentinel in buf[2] (1 = pre-recv, 2 = post-recv). The
/// parent ensures the child has reached state 1, then sleeps well past any
/// spin period before sending; if recv had not blocked, state would
/// transition to 2 before the parent sends.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_recv_then_signal.ptr),
        children.child_recv_then_signal.len,
        child_rights,
    )));

    // Setup: cap-transfer SHM.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm, shm_rights.bits() }, &reply);

    // Wait until child has entered recv (state 1).
    while (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), .acquire) != 1) {
        _ = syscall.futex_wait(@as(*u64, @ptrCast(@volatileCast(&buf[2]))), 0, MAX_TIMEOUT);
    }

    // Confirm child is still in state 1 (not 2) after many yields. If recv
    // returned spuriously (not blocked), state would be 2 by now.
    for (0..2000) |_| syscall.thread_yield();
    if (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), .acquire) != 1) {
        t.fail("§2.11.11 recv returned before send");
        syscall.shutdown();
    }

    // Now send — child's recv should return and state become 2.
    const send_rc = syscall.ipc_send(ch, &.{0xAB});
    if (send_rc != 0) {
        t.failWithVal("§2.11.11 send", 0, send_rc);
        syscall.shutdown();
    }

    // Wait for state 2 and verify ordering of timestamps: t0 < t1.
    while (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[2]))), .acquire) != 2) {
        syscall.thread_yield();
    }
    const t0 = buf[0];
    const t1 = buf[1];
    if (t1 > t0) {
        t.pass("§2.11.11");
    } else {
        t.fail("§2.11.11 t1 not after t0");
    }
    syscall.shutdown();
}
