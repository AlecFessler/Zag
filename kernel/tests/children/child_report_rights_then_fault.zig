const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

/// (1) Receives first IPC, replies with the child's own slot 0 rights in
///     word 0 AND cap-transfers HANDLE_SELF + fault_handler to the caller.
/// (2) Receives a second IPC, re-reads slot 0 rights, replies with them
///     in word 0.
/// (3) Null-dereferences, triggering a fault that the caller (now the
///     fault handler per §2.12.3) should observe in its fault box.
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

    // Null-deref — fault routes to the caller's fault box per §2.12.3.
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true });
}
