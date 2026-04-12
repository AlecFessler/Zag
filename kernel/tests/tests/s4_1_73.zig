const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn findFaultHandlerProcHandle(view: [*]const perm_view.UserViewEntry) u64 {
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            return view[i].handle;
        }
    }
    return 0;
}

/// §4.1.73 — `fault_write_mem` writes to pages mapped read-only in the target succeed; the write is performed via physmap and bypasses the target's page table permission bits.
///
/// Verifies the bytes actually landed by reading them back via fault_read_mem.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.1.73 proc_create", 1, child_ret);
        syscall.shutdown();
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.73 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        t.fail("§4.1.73 no fault_handler proc handle");
        syscall.shutdown();
    }

    // Write to the child's code section (read-only + execute in the target).
    const pattern: [4]u8 = .{ 0x90, 0x90, 0x90, 0x90 };
    const write_ret = syscall.fault_write_mem(proc_handle, fault_msg.rip, @intFromPtr(&pattern), 4);
    t.expectEqual("§4.1.73 write rc", E_OK, write_ret);

    // Read back the same bytes from the child's (read-only) code and verify.
    var check: [4]u8 = .{ 0, 0, 0, 0 };
    const read_ret = syscall.fault_read_mem(proc_handle, fault_msg.rip, @intFromPtr(&check), 4);
    t.expectEqual("§4.1.73 readback rc", E_OK, read_ret);
    if (check[0] == 0x90 and check[1] == 0x90 and check[2] == 0x90 and check[3] == 0x90) {
        t.pass("§4.1.73 bytes landed in RO page");
    } else {
        t.fail("§4.1.73 readback mismatch");
    }
    syscall.shutdown();
}
