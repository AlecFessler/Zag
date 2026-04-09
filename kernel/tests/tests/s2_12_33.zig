const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.33 — `fault_read_mem` reads bytes from the target process's virtual address space into the caller's buffer.
/// into the caller's buffer. Requires fault_handler ProcessHandleRights bit on proc_handle.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler then faults so we have a
    // known mapped address (the faulting RIP) to read from.
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler for the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the child's fault to learn its RIP.
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§2.12.33 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Find the process handle entry for the child with fault_handler bit.
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            proc_handle = view[i].handle;
            break;
        }
    }

    if (proc_handle == 0) {
        t.fail("§2.12.33 no fault_handler proc handle");
        syscall.shutdown();
    }

    // The child's ELF is loaded at a known base. The ELF header starts with
    // the magic bytes 0x7f 'E' 'L' 'F'. We can read from the child's entry
    // point area. However, the child's code is at its text segment base.
    // A simpler approach: read from a low address in the child's address space.
    // The ELF loads at the default base. We'll try reading the first 4 bytes
    // of the child's text segment (the ELF entry point code).
    //
    // Actually, the child's code is loaded by the kernel. The simplest valid
    // read: read any mapped page in the child. The child's stack or code page
    // will be mapped. We'll read 4 bytes from a reasonable code address.
    // If we don't know the exact layout, just attempt the read and verify
    // it returns E_OK (0). The data content depends on the child's memory.

    var buf: [4]u8 = .{0} ** 4;
    const rc = syscall.fault_read_mem(proc_handle, fault_msg.rip, @intFromPtr(&buf), 4);
    t.expectEqual("§2.12.33", 0, rc);
    syscall.shutdown();
}
