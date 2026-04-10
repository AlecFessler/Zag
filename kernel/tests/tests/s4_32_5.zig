const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.32.5 — If the killed thread is the last non-exited thread in the process, process exit or restart proceeds per §2.6.
///
/// The child is spawned without `.restart` so we can assert the observable
/// final state is DEAD_PROCESS (not a silent `t.pass` fall-through).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.32.5 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the child's thread handle (skip slot 1 = parent's own thread).
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§4.32.5 no thread handle found");
        syscall.shutdown();
    }

    // Locate the child's process slot.
    var child_slot: usize = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            child_slot = i;
            break;
        }
    }
    if (child_slot == 0xFFFF) {
        t.fail("§4.32.5 child slot not found");
        syscall.shutdown();
    }

    const kill_ret = syscall.thread_kill(thread_handle);
    t.expectEqual("§4.32.5 kill last thread", E_OK, kill_ret);

    // Poll for the child's entry to flip to DEAD_PROCESS (non-restartable child).
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[child_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            t.pass("§4.32.5 process exited (DEAD_PROCESS)");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }

    t.fail("§4.32.5 entry did not become DEAD_PROCESS");
    syscall.shutdown();
}
