const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;
const E_MAXCAP: i64 = -5;
const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

// Thread 1 announces it's about to block, then calls blocking recv.
// Since nothing sends to us, it will stay blocked until shutdown.
var blocked_flag: u64 align(8) = 0;

fn blocking_recv_thread() void {
    @atomicStore(u64, &blocked_flag, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&blocked_flag), 1);
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
}

// ---- E_MAXCAP sub-test state ----
var maxcap_child_h: u64 = 0;
var maxcap_caller_queued: u64 align(8) = 0;
var maxcap_caller_done: u64 align(8) = 0;

fn maxcap_caller_thread() void {
    // Transfer an SHM handle. The receiver's perm table is saturated, so
    // at recv dequeue the cap transfer must fail with E_MAXCAP.
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_to_transfer: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights)));
    @atomicStore(u64, &maxcap_caller_queued, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&maxcap_caller_queued), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(
        @atomicLoad(u64, &maxcap_child_h, .acquire),
        &.{ shm_to_transfer, shm_rights },
        &reply,
    );
    @atomicStore(u64, &maxcap_caller_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&maxcap_caller_done), 1);
}

fn runMaxcapSubtest() bool {
    // Control SHM for signaling with the receiver child.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const ctl_shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(ctl_shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_full_table_receiver.ptr),
        children.child_iter1_c_full_table_receiver.len,
        child_rights,
    )));
    @atomicStore(u64, &maxcap_child_h, h, .release);

    // Setup cap transfer: child gets control SHM.
    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(h, &.{ ctl_shm, shm_rights.bits() }, &setup_reply);

    // Wait until child has saturated its perm table and is parked.
    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Spawn a caller thread that issues ipc_call_cap to the child — since
    // the child is not in recv, this will queue in the wait queue.
    _ = syscall.thread_create(&maxcap_caller_thread, 0, 4);
    t.waitUntilNonZero(&maxcap_caller_queued);
    for (0..2000) |_| syscall.thread_yield();

    // Wake the child: now it does recv, which dequeues our caller and
    // attempts cap transfer. The child's perm table is full, so recv
    // must return E_MAXCAP.
    const b1: *u64 = @ptrCast(@volatileCast(&buf[1]));
    @atomicStore(u64, b1, 1, .release);
    _ = syscall.futex_wake(b1, 1);

    // Wait for child to record the recv result.
    const b3: *u64 = @ptrCast(@volatileCast(&buf[3]));
    while (@atomicLoad(u64, b3, .acquire) == 0) {
        _ = syscall.futex_wait(b3, 0, MAX_TIMEOUT);
    }

    const b2: *u64 = @ptrCast(@volatileCast(&buf[2]));
    const recv_rc: i64 = @bitCast(@atomicLoad(u64, b2, .acquire));

    // Unblock the queued caller thread: revoking the child unblocks it
    // with E_NOENT (the thread exits on its own).
    _ = syscall.revoke_perm(h);
    t.waitUntilNonZero(&maxcap_caller_done);

    if (recv_rc != E_MAXCAP) {
        t.failWithVal("§3.3.13 [maxcap recv rc]", E_MAXCAP, recv_rc);
        return false;
    }
    return true;
}

/// §3.3.13 — Only one thread per process may be blocked on `recv` at a time; a second thread gets `E_BUSY`.
///
/// This test also exercises the second clause of §2.11.14: "If capability
/// transfer validation fails during recv dequeue, the receiver gets
/// E_MAXCAP".
pub fn main(_: u64) void {
    // Sub-test 1: E_MAXCAP at recv dequeue on cap-transfer overflow.
    if (!runMaxcapSubtest()) {
        syscall.shutdown();
    }

    // Sub-test 2: second blocking recv on the same process yields E_BUSY.
    _ = syscall.thread_create(&blocking_recv_thread, 0, 4);
    t.waitUntilNonZero(&blocked_flag);
    for (0..2000) |_| syscall.thread_yield();

    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(true, &msg);
    t.expectEqual("§3.3.13", E_BUSY, rc);
    syscall.shutdown();
}
