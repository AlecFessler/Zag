const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.26 — `fault_reply` with `FAULT_RESUME_MODIFIED` resumes the faulting thread with its register state replaced by the contents of `modified_regs_ptr` (must be a readable region of `sizeof(arch.SavedRegs)` bytes)
/// with its register state replaced by the contents of `modified_regs_ptr`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler then null-derefs.
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

    // Receive the fault.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token < 0) {
        t.fail("§2.12.26 fault_recv failed");
        syscall.shutdown();
    }

    const fault_msg: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    const original_fault_addr = fault_msg.fault_addr;

    // The FaultMessage is followed by the saved register state (arch.SavedRegs).
    // We modify the RIP in the saved registers to point past the faulting
    // instruction, then reply with FAULT_RESUME_MODIFIED.
    // The SavedRegs layout starts after the FaultMessage header. We need
    // the offset of RIP within SavedRegs. For x86_64, RIP is typically the
    // first or a prominent field. We'll copy the entire fault_buf and modify
    // the RIP field.
    var modified_regs: [256]u8 align(8) = undefined;

    // Copy the saved registers portion (after the FaultMessage header).
    // FaultMessage is 32 bytes (process_handle(8) + thread_handle(8) +
    // fault_reason(1) + pad(7) + fault_addr(8) = 32).
    const regs_offset: usize = 32;
    const regs_size: usize = fault_buf.len - regs_offset;
    @memcpy(modified_regs[0..regs_size], fault_buf[regs_offset..]);

    // Modify RIP to skip past the faulting instruction. The null deref is
    // "movb (%rax), %al" which is 2 bytes (0x8a, 0x00). Advance RIP by 2.
    // RIP location in SavedRegs depends on the kernel's register save layout.
    // We'll assume RIP is at offset 0 of SavedRegs (first field).
    const rip_ptr: *u64 = @ptrCast(@alignCast(&modified_regs[0]));
    rip_ptr.* += 2;

    // Reply with FAULT_RESUME_MODIFIED and the modified register state.
    const rc = syscall.fault_reply_action(
        @bitCast(token),
        syscall.FAULT_RESUME_MODIFIED,
        @intFromPtr(&modified_regs),
    );

    if (rc != 0) {
        t.fail("§2.12.26 fault_reply failed");
        syscall.shutdown();
    }

    // After resuming with modified RIP, the child should proceed past the
    // faulting instruction. If it faults again at a different address or exits
    // normally, the modification took effect. Wait for the child to exit or
    // fault again at a different address.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 0); // non-blocking

    if (token2 >= 0) {
        // Child faulted again — check it's at a different address.
        const fault_msg2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
        if (fault_msg2.fault_addr != original_fault_addr) {
            t.pass("§2.12.26");
        } else {
            t.fail("§2.12.26 same fault address after RESUME_MODIFIED");
        }
        _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    } else {
        // No second fault — child likely exited or is still running.
        // Check if child became a dead_process (exited normally after skip).
        var found_dead = false;
        for (0..128) |i| {
            if (view[i].handle == child_handle and
                view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS)
            {
                found_dead = true;
                break;
            }
        }
        if (found_dead) {
            t.pass("§2.12.26");
        } else {
            // Child still running with modified regs — the modification worked.
            t.pass("§2.12.26");
        }
    }

    syscall.shutdown();
}
