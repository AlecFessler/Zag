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

/// §4.36.7 — `fault_write_mem` writes to pages mapped read-only in the target succeed; the write is performed via physmap and bypasses the target's page table permission bits
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
        t.failWithVal("§4.36.7 proc_create", 1, child_ret);
        syscall.shutdown();
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.36.7 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        t.fail("§4.36.7 no fault_handler proc handle");
        syscall.shutdown();
    }

    // Write to the child's code section (read-only + execute in the target).
    // fault_write_mem should succeed because it uses physmap, bypassing page permissions.
    var buf: [4]u8 = .{ 0x90, 0x90, 0x90, 0x90 };
    const write_ret = syscall.fault_write_mem(proc_handle, fault_msg.rip, @intFromPtr(&buf), 4);
    t.expectEqual("§4.36.7", E_OK, write_ret);

    syscall.shutdown();
}
