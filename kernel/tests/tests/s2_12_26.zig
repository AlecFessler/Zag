const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.26 — `fault_reply` with `FAULT_RESUME_MODIFIED` resumes the faulting thread with its register state replaced by the contents of `modified_regs_ptr` (must be a readable region of `sizeof(arch.SavedRegs)` bytes).
///
/// Setup: spawn child_double_fault_after_transfer — after transferring
/// fault_handler to us, it executes two consecutive 2-byte null-deref
/// instructions. The first faults at virtual address 0x0, the second (if
/// reached) at 0xCAFE0000. Strategy: after the first fault we advance the
/// saved RIP by 2 bytes via FAULT_RESUME_MODIFIED. Correct kernel behavior
/// is to resume the thread at the second instruction, producing a second
/// fault at a distinct address we can observe.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_double_fault_after_transfer.ptr),
        children.child_double_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [176]u8 align(8) = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token1 < 0) {
        t.failWithVal("§2.12.26 fault_recv 1", 0, token1);
        syscall.shutdown();
    }
    const fm1: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const first_addr = fm1.fault_addr;
    const first_rip = fm1.rip;

    // Build a 144-byte SavedRegs blob from the FaultMessage tail (offset 32)
    // and bump RIP by 2 to skip the first 2-byte null-deref instruction.
    var modified_regs: [144]u8 align(8) = undefined;
    @memcpy(modified_regs[0..144], fault_buf[32 .. 32 + 144]);
    const rip_slot: *align(8) u64 = @ptrCast(&modified_regs[0]);
    rip_slot.* = first_rip + 2;

    const rc = syscall.fault_reply_action(
        @bitCast(token1),
        syscall.FAULT_RESUME_MODIFIED,
        @intFromPtr(&modified_regs),
    );
    if (rc != 0) {
        t.failWithVal("§2.12.26 fault_reply", 0, rc);
        syscall.shutdown();
    }

    // Expect a second fault at 0xCAFE0000 (distinct from the first at 0x0).
    var fault_buf2: [176]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§2.12.26 fault_recv 2", 0, token2);
        syscall.shutdown();
    }
    const fm2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
    if (fm2.fault_addr != first_addr and fm2.fault_addr == 0xCAFE0000) {
        t.pass("§2.12.26");
    } else {
        t.failWithVal("§2.12.26 second fault addr", 0xCAFE0000, @bitCast(fm2.fault_addr));
    }

    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}
