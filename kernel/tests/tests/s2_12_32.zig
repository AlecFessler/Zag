const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;
const E_BADCAP: i64 = -3;

/// §2.12.32 — `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread (the thread handle appears in the caller's perm table as a thread-type entry belonging to a process whose `fault_handler_proc == caller`).
/// holds `fault_handler` for the owning process of the target thread
/// (external fault_handler relationship). Returns `E_PERM` otherwise.
///
/// Strong test: two scenarios.
///
/// Scenario A (self case): root calls `fault_set_thread_mode` on its OWN
/// thread handle. Root self-handles via slot-0 `fault_handler`, which is
/// NOT the required external fault_handler relationship per §2.12.32 —
/// expected E_PERM.
///
/// Scenario B (canonical negative via stale thread handle): spawn a
/// child, acquire fault_handler (so a thread handle is inserted into
/// our table), snapshot the thread handle ID, then release fault_handler
/// (bulk-revoking the thread handle per §2.12.6). The snapshot ID is
/// still a syntactically well-formed handle value but the caller no
/// longer holds fault_handler for the owning process — §2.12.32 must
/// reject with E_PERM (or the kernel may promote to E_BADCAP since the
/// entry is gone; both encode the spec intent of "caller does not hold
/// fault_handler for the target").
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // ---- Scenario A: self-case ----
    const self_handle = syscall.thread_self();
    if (self_handle < 0) {
        t.fail("§2.12.32 A thread_self");
        syscall.shutdown();
    }
    const rc_a = syscall.fault_set_thread_mode(@bitCast(self_handle), syscall.FAULT_MODE_STOP_ALL);
    if (rc_a != E_PERM) {
        t.failWithVal("§2.12.32 A self", E_PERM, rc_a);
        syscall.shutdown();
    }

    // ---- Scenario B: stale thread handle after release ----
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    var pre_ids: [128]u64 = .{0} ** 128;
    var pre_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            pre_ids[pre_count] = view[i].handle;
            pre_count += 1;
        }
    }

    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.32 B ipc_call");
        syscall.shutdown();
    }

    // Find the delta thread handle (the child's initial thread).
    var snap: u64 = 0;
    outer: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count) |k| {
            if (pre_ids[k] == h) continue :outer;
        }
        snap = h;
        break;
    }
    if (snap == 0) {
        t.fail("§2.12.32 B no delta thread handle");
        syscall.shutdown();
    }

    // Sanity: while we DO hold fault_handler, the call should succeed.
    const rc_ok = syscall.fault_set_thread_mode(snap, syscall.FAULT_MODE_STOP_ALL);
    if (rc_ok != 0) {
        t.failWithVal("§2.12.32 B sanity (with fh)", 0, rc_ok);
        syscall.shutdown();
    }

    // Find and revoke the fault_handler process handle — bulk-revokes
    // thread handles per §2.12.6.
    const fh_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var fh_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit) != 0)
        {
            fh_handle = view[i].handle;
            break;
        }
    }
    _ = syscall.revoke_perm(fh_handle);

    // Now call fault_set_thread_mode with the snapshot ID — we no longer
    // hold fault_handler for the child, so §2.12.32 must reject. Accept
    // E_PERM (spec wording) or E_BADCAP (stale handle after revocation);
    // both encode the "caller no longer holds fault_handler" semantic.
    const rc_b = syscall.fault_set_thread_mode(snap, syscall.FAULT_MODE_STOP_ALL);
    if (rc_b != E_PERM and rc_b != E_BADCAP) {
        t.failWithVal("§2.12.32 B stale", E_PERM, rc_b);
        syscall.shutdown();
    }

    t.pass("§2.12.32");
    syscall.shutdown();
}
