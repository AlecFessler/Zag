const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.2 — `ProcessHandleRights` bit 6 is `fault_handler`.
/// process may hold `fault_handler` for a given process at a time.
///
/// Observable: spawn a child with the self-handling fault_handler bit.
/// Acquire fault_handler for the child by cap-transferring HANDLE_SELF +
/// fault_handler back to us (P1 = root). Because §2.12.2 is enforced by
/// §2.12.3 atomically clearing the sender's slot 0 fault_handler bit, a
/// second would-be acquirer (P2) cannot obtain the capability: the child
/// no longer has the bit to give away. We verify both (a) P1's new
/// process handle carries fault_handler rights, and (b) the child's own
/// slot 0 ProcessRights no longer has fault_handler — so no P2 could
/// acquire it from the same child.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_report_self_rights.ptr),
        children.child_report_self_rights.len,
        child_rights,
    )));

    // First IPC: the child reports its slot 0 rights in word 0 and
    // replies with HANDLE_SELF + fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.2 first ipc_call");
        syscall.shutdown();
    }
    const pre_child_rights = reply.words[0];
    const fh_bit_proc: u64 = 0x80;
    if ((pre_child_rights & fh_bit_proc) == 0) {
        t.failWithVal("§2.12.2 pre-transfer child fh bit", @bitCast(fh_bit_proc), @bitCast(pre_child_rights));
        syscall.shutdown();
    }

    // (a) P1 (root) now holds a process handle to the child with the
    // fault_handler ProcessHandleRights bit set — this is the single
    // holder permitted by §2.12.2.
    const fh_bit_phr: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var p1_fh_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit_phr) != 0)
        {
            p1_fh_count += 1;
        }
    }
    if (p1_fh_count != 1) {
        t.failWithVal("§2.12.2 P1 fault_handler entry count", 1, @bitCast(@as(u64, p1_fh_count)));
        syscall.shutdown();
    }

    // Second IPC: child re-reports its slot 0 rights. Because §2.12.3
    // cleared the sender's fault_handler bit on cap transfer, the child
    // no longer has the capability — so no P2 could ever acquire it.
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.2 second ipc_call");
        syscall.shutdown();
    }
    const post_child_rights = reply.words[0];
    if ((post_child_rights & fh_bit_proc) != 0) {
        t.failWithVal("§2.12.2 post-transfer child fh bit not cleared", 0, @bitCast(post_child_rights));
        syscall.shutdown();
    }

    t.pass("§2.12.2");
    syscall.shutdown();
}
