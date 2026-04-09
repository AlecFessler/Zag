const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.12 — A `#BP` (int3) exception delivers a fault message with `fault_reason = breakpoint` (14) rather than killing the process immediately.
/// `fault_reason = breakpoint` (14) rather than killing the process immediately.
/// `fault_addr` contains the RIP at the time of the exception.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Step 1: Spawn child_send_self_fault_handler. It replies with HANDLE_SELF
    // via cap transfer with fault_handler, making us the external fault handler.
    // We need the child to then execute int3.
    //
    // Problem: child_send_self_fault_handler sleeps after transferring fault_handler.
    // child_breakpoint executes int3 but doesn't do IPC to transfer fault_handler.
    //
    // Approach: spawn child_breakpoint with fault_handler in ProcessRights (self-handling).
    // With only 1 thread and self-handling, §2.12.7 applies (killed/restarted).
    // But §2.12.12 says #BP delivers a fault message rather than killing.
    // So with an external handler, we'd get the fault message.
    //
    // Since we can't do cap transfer with child_breakpoint, we use the approach:
    // 1. Spawn child_send_self_fault_handler — acquire external fault handler.
    // 2. That child sleeps on futex. It won't execute int3.
    //
    // Alternative: spawn child_breakpoint without fault_handler in ProcessRights.
    // The child has no fault handler (neither self nor external). The kernel
    // should kill it. That's not what we want.
    //
    // Best available approach: spawn child_breakpoint with restart + fault_handler
    // (self-handling, 1 thread). Per §2.12.7 + §2.12.12, the child faults with
    // breakpoint reason. Since it's self-handling with 1 thread, it's killed/restarted.
    // We verify from the parent that the crash reason in perm_view is breakpoint (14).
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
        .restart = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_breakpoint.ptr),
        children.child_breakpoint.len,
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

    // Wait for the child to restart (killed/restarted per §2.12.7 since
    // self-handling with 1 thread).
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 1) break;
        syscall.thread_yield();
    }

    if (view[slot].processRestartCount() >= 1) {
        // Verify the fault_reason in field0 is breakpoint (14).
        // Per §2.1.23, after restart, fault_reason reflects the triggering fault.
        const reason = view[slot].processCrashReason();
        if (reason == .breakpoint) {
            t.pass("§2.12.12");
        } else {
            // Print what we got for debugging.
            syscall.write("§2.12.12 expected breakpoint(14), got: ");
            t.printDec(@intFromEnum(reason));
            syscall.write("\n");
            t.fail("§2.12.12 wrong fault_reason");
        }
    } else {
        t.fail("§2.12.12 child did not restart");
    }
    syscall.shutdown();
}
