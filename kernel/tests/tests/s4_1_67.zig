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

/// §4.1.67 — `fault_write_mem` returns `E_OK` on success
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child that transfers fault_handler then faults.
    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.1.67 proc_create", 1, child_ret);
        syscall.shutdown();
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.67 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        t.fail("§4.1.67 no fault_handler proc handle");
        syscall.shutdown();
    }

    var buf: [4]u8 = .{ 0x42, 0x42, 0x42, 0x42 };
    // Write 4 bytes to the faulting child's RIP — guaranteed mapped code page.
    // Code pages are read-only in the child; fault_write_mem bypasses via physmap.
    const write_ret = syscall.fault_write_mem(proc_handle, fault_msg.rip, @intFromPtr(&buf), 4);
    t.expectEqual("§4.1.67 rc", E_OK, write_ret);

    // Read the bytes back and verify the pattern actually landed.
    var check: [4]u8 = .{ 0, 0, 0, 0 };
    const read_ret = syscall.fault_read_mem(proc_handle, fault_msg.rip, @intFromPtr(&check), 4);
    t.expectEqual("§4.1.67 readback rc", E_OK, read_ret);
    if (check[0] == 0x42 and check[1] == 0x42 and check[2] == 0x42 and check[3] == 0x42) {
        t.pass("§4.1.67 bytes landed");
    } else {
        t.fail("§4.1.67 readback mismatch");
    }

    syscall.shutdown();
}
