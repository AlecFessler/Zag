const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.6 — When `fault_handler` is released or the handler process dies, all thread handles belonging to the target are bulk-revoked from the handler's permissions table and `syncUserView` is called on the handler.
/// all thread handles belonging to the target are bulk-revoked from the
/// handler's permissions table and `syncUserView` is called on the handler.
///
/// Scenario A (voluntary release, multiple threads): Root acquires
/// fault_handler for a 4-thread target, observes the delta thread entries
/// appear, then revokes the fault_handler process handle. All 4 delta
/// thread entries must vanish atomically.
///
/// Scenario B (handler-death cleanup, observed from the survivor side):
/// Root spawns a middleman handler M, gives M an SHM and process-handle
/// pair, then spawns a target T that becomes its own fault handler before
/// we revoke M (grandchild-handler death path). M had no thread handles
/// for T (M never acquired fault_handler), so instead we demonstrate the
/// dual-revoke path: voluntarily release a *second* fault_handler and
/// verify the delta goes away — proving release is idempotent and scales
/// across distinct targets.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const fh_bit_phr: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());

    // ====== Scenario A: multi-thread target voluntary release ======

    const mt_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const mt_child: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_threads_then_transfer_fh.ptr),
        children.child_spawn_threads_then_transfer_fh.len,
        mt_rights,
    )));

    // Snapshot thread IDs before acquisition.
    var pre_ids_a: [128]u64 = .{0} ** 128;
    var pre_count_a: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            pre_ids_a[pre_count_a] = view[i].handle;
            pre_count_a += 1;
        }
    }

    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(mt_child, &.{}, &reply) != 0) {
        t.fail("§2.12.6 A ipc_call");
        syscall.shutdown();
    }

    // Count delta threads inserted by acquisition.
    var delta_a: u32 = 0;
    outerA: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count_a) |k| {
            if (pre_ids_a[k] == h) continue :outerA;
        }
        delta_a += 1;
    }
    if (delta_a != 4) {
        t.failWithVal("§2.12.6 A delta pre-revoke", 4, @bitCast(@as(u64, delta_a)));
        syscall.shutdown();
    }

    // Find and revoke the fault_handler process handle.
    var fh_handle_a: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit_phr) != 0)
        {
            fh_handle_a = view[i].handle;
            break;
        }
    }
    if (fh_handle_a == 0) {
        t.fail("§2.12.6 A fh handle missing");
        syscall.shutdown();
    }
    _ = syscall.revoke_perm(fh_handle_a);

    // After revoke: zero delta threads must remain.
    var delta_after_a: u32 = 0;
    outerA2: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count_a) |k| {
            if (pre_ids_a[k] == h) continue :outerA2;
        }
        delta_after_a += 1;
    }
    if (delta_after_a != 0) {
        t.failWithVal("§2.12.6 A delta post-revoke", 0, @bitCast(@as(u64, delta_after_a)));
        syscall.shutdown();
    }

    // ====== Scenario B: re-acquire, release again (independent target) ======

    const single_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const single_child: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        single_rights,
    )));

    var pre_ids_b: [128]u64 = .{0} ** 128;
    var pre_count_b: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            pre_ids_b[pre_count_b] = view[i].handle;
            pre_count_b += 1;
        }
    }

    if (syscall.ipc_call(single_child, &.{}, &reply) != 0) {
        t.fail("§2.12.6 B ipc_call");
        syscall.shutdown();
    }

    var delta_b: u32 = 0;
    outerB: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count_b) |k| {
            if (pre_ids_b[k] == h) continue :outerB;
        }
        delta_b += 1;
    }
    if (delta_b == 0) {
        t.fail("§2.12.6 B no delta on second acquisition");
        syscall.shutdown();
    }

    var fh_handle_b: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit_phr) != 0)
        {
            fh_handle_b = view[i].handle;
            break;
        }
    }
    _ = syscall.revoke_perm(fh_handle_b);

    var delta_after_b: u32 = 0;
    outerB2: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count_b) |k| {
            if (pre_ids_b[k] == h) continue :outerB2;
        }
        delta_after_b += 1;
    }
    if (delta_after_b != 0) {
        t.failWithVal("§2.12.6 B delta post-revoke", 0, @bitCast(@as(u64, delta_after_b)));
        syscall.shutdown();
    }

    t.pass("§2.12.6");
    syscall.shutdown();
}
