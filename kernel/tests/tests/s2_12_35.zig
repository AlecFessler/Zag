const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.35 — When the handler process dies, all processes that had it as fault handler revert to self-fault-handling: their `fault_handler` ProcessRights bit is restored and their `fault_handler_proc` is cleared.
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
    if ((rights_after & fh_bit) != 0) {
        t.pass("§2.12.35");
    } else {
        t.fail("§2.12.35 fault_handler bit not restored after handler death");
    }

    syscall.shutdown();
}
