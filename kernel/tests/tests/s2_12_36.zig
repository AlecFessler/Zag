const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;
const E_BUSY: i64 = -11;

/// §2.12.36 — The fault box state is fully independent from the IPC message box state.
/// `fault_recv` and `fault_reply` do not interact with `recv`/`reply` pending state;
/// both boxes may be in `pending_reply` simultaneously.
///
/// Three sub-scenarios:
///   A. fault_box pending → ipc_recv unaffected (must return E_AGAIN, not
///      E_BUSY).
///   B. msg_box pending  → fault_recv unaffected (must return E_AGAIN, not
///      E_BUSY) — the converse of A.
///   C. Both boxes pending simultaneously — the spec explicitly permits
///      this. Re-issuing either kind of recv on its own box must return
///      E_BUSY (the box is already in pending_reply), but neither reply
///      may corrupt the other box.
pub fn main(_: u64) void {
    // ---- Sub-scenario A: fault_box pending, ipc_recv must see E_AGAIN ----
    {
        const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_fault_after_transfer.ptr),
            children.child_fault_after_transfer.len,
            child_rights,
        )));

        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(child_handle, &.{}, &reply);

        var fault_buf: [256]u8 align(8) = undefined;
        const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
        if (token < 0) {
            t.failWithVal("§2.12.36 A fault_recv", 0, token);
            syscall.shutdown();
        }

        // Confirm fault_box is in pending_reply (re-recv returns E_BUSY).
        var fault_buf2: [256]u8 align(8) = undefined;
        const second_fault = syscall.fault_recv(@intFromPtr(&fault_buf2), 0);
        if (second_fault != E_BUSY) {
            t.failWithVal("§2.12.36 A fault_box not pending_reply", E_BUSY, second_fault);
            syscall.shutdown();
        }

        // Independence: ipc_recv must return E_AGAIN (not E_BUSY).
        var ipc_msg: syscall.IpcMessage = .{};
        const ipc_rc = syscall.ipc_recv(false, &ipc_msg);
        if (ipc_rc != E_AGAIN) {
            t.failWithVal("§2.12.36 A ipc_recv leaked fault_box state", E_AGAIN, ipc_rc);
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
            syscall.shutdown();
        }

        // Cleanup: kill the faulting thread. Revoke the child so the next
        // sub-scenario runs with a clean permissions table.
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        _ = syscall.revoke_perm(child_handle);
    }

    // ---- Sub-scenario B: msg_box pending, fault_recv must see E_AGAIN ----
    // Drive root's msg_box into `pending_reply` by having a child ipc_call
    // us. If the boxes shared state, a fault_recv against the idle
    // fault_box would incorrectly return E_BUSY.
    var scenarioB_caller_handle: u64 = 0;
    {
        const caller_rights: u64 = 0;
        scenarioB_caller_handle = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_iter1_d_call_parent.ptr),
            children.child_iter1_d_call_parent.len,
            caller_rights,
        )));

        // Give the child a handle back to us via cap transfer.
        const back_rights: u64 = (perms.ProcessHandleRights{
            .send_words = true,
        }).bits();
        var setup_reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call_cap(scenarioB_caller_handle, &.{ 0, back_rights }, &setup_reply);

        // Now wait for the child's ipc_call to arrive and recv it, which
        // transitions root's msg_box into pending_reply.
        var in: syscall.IpcMessage = .{};
        const recv_rc = syscall.ipc_recv(true, &in);
        if (recv_rc != 0) {
            t.failWithVal("§2.12.36 B ipc_recv", 0, recv_rc);
            syscall.shutdown();
        }

        // Confirm msg_box is in pending_reply — a second non-blocking
        // ipc_recv must return E_BUSY.
        var ignore: syscall.IpcMessage = .{};
        const second_ipc = syscall.ipc_recv(false, &ignore);
        if (second_ipc != E_BUSY) {
            t.failWithVal("§2.12.36 B msg_box not pending_reply", E_BUSY, second_ipc);
            syscall.shutdown();
        }

        // Independence: fault_recv must NOT be poisoned by msg_box state.
        // Root holds self fault_handler (start.zig-supplied slot 0) so
        // fault_recv is permitted. The fault_box is idle, so it must
        // return E_AGAIN, not E_BUSY.
        var fb: [256]u8 align(8) = undefined;
        const fr_rc = syscall.fault_recv(@intFromPtr(&fb), 0);
        if (fr_rc != E_AGAIN) {
            t.failWithVal("§2.12.36 B fault_recv leaked msg_box state", E_AGAIN, fr_rc);
            _ = syscall.ipc_reply(&.{});
            syscall.shutdown();
        }

        // ---- Sub-scenario C: both boxes pending simultaneously ----
        // msg_box is already pending from scenario B. Now drive fault_box
        // into pending_reply as well by triggering a fault in a second
        // child and receiving it. Per §2.12.36 this is explicitly allowed.
        const f_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
        const f_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_fault_after_transfer.ptr),
            children.child_fault_after_transfer.len,
            f_rights,
        )));
        var f_reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(f_handle, &.{}, &f_reply);

        var fault_buf3: [256]u8 align(8) = undefined;
        const c_token = syscall.fault_recv(@intFromPtr(&fault_buf3), 1);
        if (c_token < 0) {
            t.failWithVal("§2.12.36 C fault_recv", 0, c_token);
            _ = syscall.ipc_reply(&.{});
            syscall.shutdown();
        }

        // Both boxes are now in pending_reply. Re-issue non-blocking recv
        // on each — both must report E_BUSY on their own box (proving
        // they are in pending_reply) without corrupting the other.
        var ignore2: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(false, &ignore2) != E_BUSY) {
            t.fail("§2.12.36 C msg_box lost pending_reply");
            _ = syscall.fault_reply_simple(@bitCast(c_token), syscall.FAULT_KILL);
            _ = syscall.ipc_reply(&.{});
            syscall.shutdown();
        }
        var fb2: [256]u8 align(8) = undefined;
        if (syscall.fault_recv(@intFromPtr(&fb2), 0) != E_BUSY) {
            t.fail("§2.12.36 C fault_box lost pending_reply");
            _ = syscall.fault_reply_simple(@bitCast(c_token), syscall.FAULT_KILL);
            _ = syscall.ipc_reply(&.{});
            syscall.shutdown();
        }

        // Reply to the faulting thread first. This must clear fault_box
        // pending_reply without touching msg_box.
        _ = syscall.fault_reply_simple(@bitCast(c_token), syscall.FAULT_KILL);
        var ignore3: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(false, &ignore3) != E_BUSY) {
            t.fail("§2.12.36 C fault_reply corrupted msg_box");
            _ = syscall.ipc_reply(&.{});
            syscall.shutdown();
        }

        // Finally reply to the ipc caller. This unblocks the child.
        _ = syscall.ipc_reply(&.{});
    }

    t.pass("§2.12.36");
    syscall.shutdown();
}
