const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.7 — When a thread faults and the process is its own fault handler and only one thread exists (the faulting thread), the process is killed or restarted immediately per §2.6 semantics; no fault message is delivered
/// exists (the faulting thread), the process is killed or restarted immediately per §2.6
/// semantics; no fault message is delivered.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_null_deref with fault_handler + restart rights.
    // The child is its own fault handler (fault_handler in ProcessRights),
    // has only 1 thread, and will null-deref immediately.
    // Since it's self-handling with 1 thread, it should be killed or restarted
    // immediately with no fault message delivered.
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
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

    // Wait for the child to restart (proving it was killed/restarted, not stuck
    // waiting for a fault message that will never be handled).
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        const restart_count = view[slot].processRestartCount();
        if (restart_count >= 1) break;
        syscall.thread_yield();
    }

    if (view[slot].processRestartCount() < 1) {
        // No restart means the child is stuck in .faulted waiting for a fault
        // message that nobody can handle — i.e., a fault message WAS delivered,
        // contradicting §2.12.7.
        t.fail("§2.12.7 child did not restart");
        syscall.shutdown();
    }

    const reason = view[slot].processCrashReason();
    if (reason != .unmapped_access and reason != .invalid_read) {
        t.fail("§2.12.7 wrong fault_reason");
        syscall.shutdown();
    }

    // Explicit "no fault message is delivered" check: the parent does not hold
    // fault_handler over the child, and §2.12.2 makes fault_handler exclusive,
    // so no other process can have received the child's fault either. Verify
    // the parent's own fault box stays empty. Combined with the restart-count
    // check above (which proves the child wasn't stuck in .faulted in its own
    // self-handled box), this proves the kernel did not enqueue a fault
    // message anywhere.
    var fmsg: syscall.FaultMessage = undefined;
    const E_AGAIN: i64 = -9;
    const E_PERM: i64 = -2;
    const fr = syscall.fault_recv(@intFromPtr(&fmsg), 0);
    // Root may not hold fault_handler at all, in which case fault_recv returns
    // E_PERM per §2.12.18; otherwise it must be E_AGAIN. Either result proves
    // no message about the child reached the parent.
    if (fr != E_AGAIN and fr != E_PERM) {
        t.failWithVal("§2.12.7 unexpected fault_recv result", E_AGAIN, fr);
        syscall.shutdown();
    }

    t.pass("§2.12.7");
    syscall.shutdown();
}
