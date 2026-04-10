const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.16 — Revoking a process handle without `kill` right drops the handle without killing.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_send_self_then_recv — it replies with HANDLE_SELF (send_words+grant,
    // no kill right) then blocks on a second recv so we can do a round-trip
    // ipc_call through h1 AFTER revoking h2 to prove the child is still alive.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h1: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self_then_recv.ptr), children.child_send_self_then_recv.len, child_rights.bits())));

    // Call child — get second handle without kill right.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(h1, &.{}, &reply);

    // Find the second handle (process entry, not h1, not HANDLE_SELF).
    var h2: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != h1 and view[i].handle != 0) {
            h2 = view[i].handle;
            break;
        }
    }

    // Revoke h2 (no kill right) — should just drop the handle, NOT kill the child.
    _ = syscall.revoke_perm(h2);

    // Verify h2 is gone from perm_view.
    var h2_found = false;
    for (0..128) |i| {
        if (view[i].handle == h2 and view[i].entry_type != perm_view.ENTRY_TYPE_EMPTY) {
            h2_found = true;
            break;
        }
    }

    // Direct liveness check: do an ipc_call round-trip through h1. If the
    // child were dead, this would return E_BADHANDLE (§2.11.9); a successful
    // round-trip proves the revoke on h2 did not kill the child.
    var probe_reply: syscall.IpcMessage = .{};
    const probe_rc = syscall.ipc_call(h1, &.{}, &probe_reply);
    const h1_alive = probe_rc == 0;

    if (!h2_found and h1_alive) {
        t.pass("§2.3.16");
    } else {
        t.fail("§2.3.16");
    }
    syscall.shutdown();
}
