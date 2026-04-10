const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.4 — Once cleared via `disable_restart`, the restart capability cannot be re-enabled.
/// be re-enabled.
///
/// We check three paths:
///   1) A second `disable_restart` call returns E_PERM (already cleared).
///   2) Attempting to create a child with `.restart = true` fails E_PERM
///      (you cannot grant what you do not have).
///   3) Receiving a capability transfer from a child (HANDLE_SELF) is NOT a
///      loophole: ProcessHandleRights carried on that handle never touch the
///      recipient's slot-0 `ProcessRights`. After the transfer slot 0's
///      `restart` bit remains clear.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Restart must be set on slot 0 at boot (root service has full
    // ProcessRights per §2.1.14).
    const restart_bit: u16 = @truncate((perms.ProcessRights{ .restart = true }).bits());
    const had_restart = (view[0].rights & restart_bit) != 0;

    // Clear it.
    _ = syscall.disable_restart();
    const cleared_after_disable = (view[0].rights & restart_bit) == 0;

    // (2) Cannot create a restartable child once restart is cleared.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .restart = true };
    const create_ret = syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits());

    // (1) disable_restart twice → E_PERM.
    const second_disable = syscall.disable_restart();

    // (3) Cap-transfer path: spawn a plain child and have it send back
    // HANDLE_SELF with all ProcessHandleRights. The transfer grants us a
    // ProcessHandleRights handle on the child — nothing about this should
    // touch our own slot 0.
    const plain_rights = perms.ProcessRights{ .spawn_thread = true };
    const plain_child: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self.ptr),
        children.child_send_self.len,
        plain_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(plain_child, &.{}, &reply);

    const still_cleared = (view[0].rights & restart_bit) == 0;

    if (had_restart and
        cleared_after_disable and
        create_ret == E_PERM and
        second_disable == E_PERM and
        still_cleared)
    {
        t.pass("§2.3.4");
    } else {
        t.fail("§2.3.4");
    }
    syscall.shutdown();
}
