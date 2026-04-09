const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.33.6 — `fault_recv` returns `E_PERM` if the calling process holds neither its own `fault_handler` ProcessRights nor `fault_handler` on any process handle
pub fn main(_: u64) void {
    // The root process has all ProcessRights, so it will not get E_PERM.
    // Spawn child_try_fault_recv which has no fault_handler right and attempts
    // fault_recv, returning the result via IPC.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_try_fault_recv.ptr),
        children.child_try_fault_recv.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.33.6 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    // Call the child to trigger its fault_recv attempt and get the result.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Child sends fault_recv result in word 0.
    const fault_recv_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.33.6", E_PERM, fault_recv_result);

    syscall.shutdown();
}
