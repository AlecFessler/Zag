const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.25 — `fault_reply` with `FAULT_RESUME` resumes the faulting thread with its register state unchanged
/// with its register state unchanged.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler then triggers a breakpoint.
    // We use child_fault_after_transfer which null-derefs. After FAULT_RESUME
    // the child will fault again at the same instruction (register state unchanged).
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the first fault.
    var fault_buf: [256]u8 align(8) = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token1 < 0) {
        t.fail("§4.1.25 fault_recv 1 failed");
        syscall.shutdown();
    }

    // Snapshot the RIP from the first fault. `fault_addr` for a page fault
    // reports CR2 (the faulting data address) which is always 0 for a null
    // deref — comparing that would be trivially equal regardless of whether
    // the register state was actually preserved. RIP is the meaningful check
    // because it reflects the faulting instruction pointer; if FAULT_RESUME
    // leaves registers unchanged, the child re-executes the same instruction
    // and faults again with the same RIP.
    const fault_msg1: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const fault_rip1 = fault_msg1.rip;
    const fault_addr1 = fault_msg1.fault_addr;

    // Reply with FAULT_RESUME — register state unchanged, so the child should
    // re-execute the same faulting instruction and fault again.
    const rc = syscall.fault_reply_simple(@bitCast(token1), syscall.FAULT_RESUME);

    if (rc != 0) {
        t.fail("§4.1.25 fault_reply failed");
        syscall.shutdown();
    }

    // Receive the second fault — should be at the same address since registers
    // were not modified.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);

    if (token2 < 0) {
        t.fail("§4.1.25 fault_recv 2 failed");
        syscall.shutdown();
    }

    const fault_msg2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
    const fault_rip2 = fault_msg2.rip;
    const fault_addr2 = fault_msg2.fault_addr;

    // Same RIP confirms register state was unchanged: the child re-executed
    // the same faulting instruction. fault_addr is additionally checked as a
    // sanity cross-check (both null derefs yield CR2 == 0).
    if (fault_rip1 == fault_rip2 and fault_addr1 == fault_addr2) {
        t.pass("§4.1.25");
    } else if (fault_rip1 != fault_rip2) {
        t.failWithVal("§4.1.25 RIP changed after FAULT_RESUME", @bitCast(fault_rip1), @bitCast(fault_rip2));
    } else {
        t.fail("§4.1.25 fault_addr changed after FAULT_RESUME");
    }

    // Clean up: kill the faulting thread.
    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);

    _ = view;
    syscall.shutdown();
}
