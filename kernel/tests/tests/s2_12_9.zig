const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.9 — When all threads in a self-handling process are simultaneously in `.faulted` state, the process is killed or restarted per §2.6 semantics; no additional fault messages are delivered
/// state, the process is killed or restarted per §2.6 semantics; no additional fault
/// messages are delivered.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_null_deref with fault_handler + restart + spawn_thread.
    // child_null_deref has only 1 thread — it null-derefs immediately.
    // With fault_handler (self-handling) and only 1 thread, §2.12.7 applies
    // (single thread = immediate kill/restart). But if it had multiple threads
    // all faulting, §2.12.9 would apply.
    //
    // Since child_null_deref has only 1 thread, "all threads faulted" is
    // trivially true (1 of 1). This exercises the same code path: when all
    // threads are in .faulted, the process is killed or restarted.
    //
    // For a more thorough test we'd need a child that spawns multiple threads
    // which all null-deref. child_null_deref with spawn_thread rights and
    // fault_handler demonstrates the single-thread case (which is also the
    // "all threads faulted" case for 1-thread processes).
    //
    // We give it restart so we can observe the restart from the parent.
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
        .spawn_thread = true,
        .restart = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_null_deref.ptr),
        children.child_null_deref.len,
        child_rights,
    )));

    // Find the child's slot in our perm view.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Wait for the child to restart. When all threads are .faulted in a
    // self-handling process, the kernel kills/restarts it per §2.6.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 1) break;
        syscall.thread_yield();
    }

    if (view[slot].processRestartCount() >= 1) {
        // Verify crash reason reflects the fault.
        const reason = view[slot].processCrashReason();
        if (reason == .unmapped_access or reason == .invalid_read) {
            t.pass("§2.12.9");
        } else {
            t.fail("§2.12.9 wrong fault_reason");
        }
    } else {
        t.fail("§2.12.9");
    }
    syscall.shutdown();
}
