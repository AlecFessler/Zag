const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.37.2 — `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread; returns `E_PERM` otherwise
pub fn main(_: u64) void {
    // Spawn a child WITHOUT fault_handler ProcessRights. The child has its
    // own thread but does not hold fault_handler for itself, so when it calls
    // fault_set_thread_mode on its own thread the kernel must return E_PERM
    // (no other process holds fault_handler for it either, per §2.12.2).
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
    }).bits();
    const ret = syscall.proc_create(
        @intFromPtr(children.child_try_fault_set_thread_mode.ptr),
        children.child_try_fault_set_thread_mode.len,
        child_rights,
    );
    if (ret <= 0) {
        t.failWithVal("§4.37.2 proc_create", 1, ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(@as(i64, ret));

    // Tell the child to attempt fault_set_thread_mode and reply with the result.
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(child_handle, &.{0}, &reply);
    if (call_rc != 0) {
        t.failWithVal("§4.37.2 ipc_call", 0, call_rc);
        syscall.shutdown();
    }

    const child_rc: i64 = @bitCast(reply.words[0]);
    if (child_rc == E_PERM) {
        t.pass("§4.37.2");
    } else {
        t.failWithVal("§4.37.2", E_PERM, child_rc);
    }
    syscall.shutdown();
}
