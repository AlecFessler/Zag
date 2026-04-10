const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

/// (1) Receives first IPC, reads its own slot 0 ProcessRights from the user
///     permissions view and reports them in reply word 0, then replies with
///     HANDLE_SELF + fault_handler via cap transfer. After this cap transfer,
///     per §2.12.3 the child's own slot 0 `fault_handler` bit is cleared.
/// (2) Receives a second IPC, re-reads its own slot 0 rights from the user
///     permissions view (which the kernel has just called syncUserView on)
///     and reports them in reply word 0. Cap-transfer exclusivity per
///     §2.12.2 manifests as this post-transfer bit being clear.
/// (3) Stays alive on a futex.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    const pre_rights: u64 = view[0].rights;
    const transfer_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ pre_rights, 0, transfer_rights });

    _ = syscall.ipc_recv(true, &msg);
    const post_rights: u64 = view[0].rights;
    _ = syscall.ipc_reply(&.{post_rights});

    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}
