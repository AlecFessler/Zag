const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.34 — `fault_write_mem` writes bytes from the caller's buffer into the target process's virtual address space via physmap, bypassing the target's page table permission bits.
/// process's virtual address space via physmap, bypassing page table permission bits.
/// Requires fault_handler ProcessHandleRights bit on proc_handle.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler then faults — gives us a known mapped RIP.
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
        t.failWithVal("§2.12.34 fault_recv", 0, recv_ret);
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
        t.fail("§2.12.34 no fault_handler proc handle");
        syscall.shutdown();
    }

    // Write 4 bytes to the child's address space, then read them back
    // to verify the write succeeded.
    const write_buf = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var read_buf: [4]u8 = .{0} ** 4;

    // Write to the child's RIP — guaranteed mapped (it's the faulting code).
    const target_addr: u64 = fault_msg.rip;

    const wrc = syscall.fault_write_mem(proc_handle, target_addr, @intFromPtr(&write_buf), 4);
    if (wrc != 0) {
        t.failWithVal("§2.12.34 write", 0, wrc);
        syscall.shutdown();
    }

    // Read back what we wrote to verify.
    const rrc = syscall.fault_read_mem(proc_handle, target_addr, @intFromPtr(&read_buf), 4);
    if (rrc != 0) {
        t.failWithVal("§2.12.34 read", 0, rrc);
        syscall.shutdown();
    }

    // Verify the data matches.
    if (read_buf[0] == 0xDE and read_buf[1] == 0xAD and read_buf[2] == 0xBE and read_buf[3] == 0xEF) {
        t.pass("§2.12.34");
    } else {
        t.fail("§2.12.34 data mismatch");
    }
    syscall.shutdown();
}
