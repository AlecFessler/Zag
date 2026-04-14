const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.55 — The user permissions view is a read-only region mapped into the process's address space.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Verify we can read from perm_view (slot 0 = HANDLE_SELF).
    if (pv == 0 or view[0].entry_type != perm_view.ENTRY_TYPE_PROCESS) {
        t.fail("§2.1.55");
        syscall.shutdown();
    }
    // Spawn child_write_perm_view — it writes to its perm_view, which should fault.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_write_perm_view.ptr),
        children.child_write_perm_view.len,
        child_rights.bits(),
    )));
    // Sync: call child so it knows to proceed.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    // Wait for child to die from write fault.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // Child should have died with invalid_write from writing to read-only perm_view.
    if (view[slot].processCrashReason() == .invalid_write) {
        t.pass("§2.1.55");
    } else {
        t.fail("§2.1.55");
    }
    syscall.shutdown();
}
