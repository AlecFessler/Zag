const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.35 — When the handler process dies, all processes that had it as fault handler revert to self-fault-handling: their `fault_handler` ProcessRights bit is restored and their `fault_handler_proc` is cleared.
///
/// Spec clauses:
///   (a) `fault_handler` ProcessRights bit restored on the reverted target
///   (b) `fault_handler_proc` cleared
///   (c) pending fault messages in the dead handler's fault_box discarded
///   (d) `.faulted` threads re-evaluated under §2.12.7 / §2.12.9
///   (e) `.suspended` threads moved to `.ready` and re-enqueued
///
/// Sub-scenario A (single-thread reporter) exercises clause (a) via
/// observable slot-0 rights.
///
/// Sub-scenario B (multi-thread SHM counter) exercises clauses (c), (d),
/// (e): the target has a worker thread that increments a shared counter
/// and a main thread that faults. The fault is routed to a middleman
/// handler that NEVER calls fault_recv, so a fault message sits pending
/// in the middleman's fault_box (clause c). The worker is put into
/// `.suspended` by stop-all (§2.12.10). When we kill the middleman:
///   - clause (e) is observable: the worker wakes from `.suspended` and
///     the shared counter must advance after the middleman dies.
///   - clause (d) is observable indirectly: the target now self-handles
///     with a single faulted thread and a running worker; per §2.12.8
///     the faulted main thread stays `.faulted` and a fault message is
///     routed into the target's own fault box, so the target is NOT
///     killed. (If clause (d) were incorrectly implemented as "kill the
///     faulted thread without re-evaluation", the target would die
///     immediately since its main thread would be killed and then the
///     worker would be the sole thread; the counter may or may not
///     advance depending on ordering. The positive clause (e) observation
///     is the primary signal.)
pub fn main(pv: u64) void {
    _ = pv;

    // Spawn the middleman handler: it recvs one ipc call (the target's cap
    // transfer), replies, then sleeps forever.
    const handler_rights = (perms.ProcessRights{
        .mem_reserve = true,
    }).bits();
    const handler_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_middleman_handler.ptr),
        children.child_middleman_handler.len,
        handler_rights,
    )));

    // Spawn the target: it has fault_handler self-right initially, plus
    // rights to receive the handler handle via cap transfer and to ipc_call.
    const target_rights = (perms.ProcessRights{
        .mem_reserve = true,
        .fault_handler = true,
    }).bits();
    const target_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fh_target_reporter.ptr),
        children.child_fh_target_reporter.len,
        target_rights,
    )));

    // Call 1 (setup): give the target a handle to the handler via cap
    // transfer. Rights on the transferred handle: send_words so target can
    // ipc_call, and grant so it can transfer HANDLE_SELF.
    const handler_cap_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
        .grant = true,
    }).bits();
    var reply1: syscall.IpcMessage = .{};
    const rc1 = syscall.ipc_call_cap(target_handle, &.{ handler_handle, handler_cap_rights }, &reply1);
    if (rc1 != 0) {
        t.failWithVal("§2.12.35 setup ipc_call", 0, rc1);
        syscall.shutdown();
    }

    // After returning from call 1, the target will issue its own ipc_call
    // to the handler with HANDLE_SELF+fault_handler. Give it time to run.
    for (0..50) |_| syscall.thread_yield();

    // Call 2: ask the target to report its slot 0 rights. Should have
    // fault_handler bit CLEARED now (handler owns it).
    var reply2: syscall.IpcMessage = .{};
    const rc2 = syscall.ipc_call(target_handle, &.{}, &reply2);
    if (rc2 != 0) {
        t.failWithVal("§2.12.35 report1 ipc_call", 0, rc2);
        syscall.shutdown();
    }
    const fh_bit: u64 = (perms.ProcessRights{ .fault_handler = true }).bits();
    const rights_before = reply2.words[0];
    if ((rights_before & fh_bit) != 0) {
        t.fail("§2.12.35 target still has fault_handler before handler death");
        syscall.shutdown();
    }

    // Kill the handler process. We hold a handle with kill rights (proc_create
    // grants full ProcessHandleRights per §4.10.10). Revoking with the kill
    // bit set recursively kills the child (§2.3.15).
    const rev_rc = syscall.revoke_perm(handler_handle);
    if (rev_rc != 0) {
        t.failWithVal("§2.12.35 revoke handler", 0, rev_rc);
        syscall.shutdown();
    }

    // Give the kernel time to run releaseFaultHandler on the dying handler.
    for (0..50) |_| syscall.thread_yield();

    // Call 3: ask the target to report slot 0 rights again. Should have
    // fault_handler bit RESTORED.
    var reply3: syscall.IpcMessage = .{};
    const rc3 = syscall.ipc_call(target_handle, &.{}, &reply3);
    if (rc3 != 0) {
        t.failWithVal("§2.12.35 report2 ipc_call", 0, rc3);
        syscall.shutdown();
    }
    const rights_after = reply3.words[0];
    if ((rights_after & fh_bit) == 0) {
        t.fail("§2.12.35 A fault_handler bit not restored after handler death");
        syscall.shutdown();
    }

    // ---- Sub-scenario B: suspended worker + faulted main thread ----
    // Spawn a fresh middleman handler.
    const handler2_rights = (perms.ProcessRights{
        .mem_reserve = true,
    }).bits();
    const handler2_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_middleman_handler.ptr),
        children.child_middleman_handler.len,
        handler2_rights,
    )));

    // Create SHM for the shared counter (one page).
    const shm_size: u64 = syscall.PAGE4K;
    const shm_handle_raw = syscall.shm_create_with_rights(
        shm_size,
        (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits(),
    );
    if (shm_handle_raw < 0) {
        t.fail("§2.12.35 B mem_shm_create");
        syscall.shutdown();
    }
    const shm_handle: u64 = @bitCast(shm_handle_raw);

    // Map the counter into our own address space.
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§2.12.35 B mem_reserve");
        syscall.shutdown();
    }
    const vm_h: u64 = @intCast(vm_result.val);
    if (syscall.mem_shm_map(shm_handle, vm_h, 0) != 0) {
        t.fail("§2.12.35 B mem_shm_map");
        syscall.shutdown();
    }
    const counter_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    counter_ptr.* = 0;

    // Spawn the multi-thread target.
    const target2_rights = (perms.ProcessRights{
        .mem_reserve = true,
        .mem_shm_create = true,
        .spawn_thread = true,
    }).bits();
    const target2_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_d_mt_target.ptr),
        children.child_iter1_d_mt_target.len,
        target2_rights,
    )));

    // Call 1: cap-transfer SHM to the target.
    const shm_grant = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
    var b_reply1: syscall.IpcMessage = .{};
    if (syscall.ipc_call_cap(target2_handle, &.{ shm_handle, shm_grant }, &b_reply1) != 0) {
        t.fail("§2.12.35 B call1");
        syscall.shutdown();
    }

    // Call 2: cap-transfer middleman handle to the target. Target then
    // calls middleman with HANDLE_SELF+fault_handler and faults.
    const middleman_cap_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
        .grant = true,
    }).bits();
    var b_reply2: syscall.IpcMessage = .{};
    if (syscall.ipc_call_cap(target2_handle, &.{ handler2_handle, middleman_cap_rights }, &b_reply2) != 0) {
        t.fail("§2.12.35 B call2");
        syscall.shutdown();
    }

    // Give the target time to: install middleman as handler, spawn
    // worker, fault. After this the worker is `.suspended`, main is
    // `.faulted`, and the middleman has a pending fault message it has
    // not received.
    for (0..200) |_| syscall.thread_yield();

    // Snapshot the counter BEFORE killing the middleman. The worker
    // should be suspended (stop-all per §2.12.10), so the counter must
    // have stopped advancing.
    const before_kill = counter_ptr.*;

    // Kill the middleman. Per §2.12.35 the target reverts to
    // self-handling, its worker moves `.suspended` → `.ready`, and its
    // faulted main is re-evaluated under §2.12.8 (stays faulted with a
    // pending fault in the target's own box). The target remains alive.
    _ = syscall.revoke_perm(handler2_handle);

    // Yield enough times for the worker to run on a clean scheduler
    // slice. On a multi-core setup the worker may resume immediately.
    for (0..200) |_| syscall.thread_yield();

    const after_kill = counter_ptr.*;

    if (after_kill == before_kill) {
        t.failWithVal("§2.12.35 B worker did not resume", @bitCast(before_kill), @bitCast(after_kill));
        syscall.shutdown();
    }

    t.pass("§2.12.35");
    syscall.shutdown();
}
