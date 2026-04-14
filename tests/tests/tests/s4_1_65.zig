const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

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

/// §4.1.65 — `fault_read_mem` with `buf_ptr` not writable in the caller's address space returns `E_BADADDR`.
///
/// Uses `fault_msg.rip` (known mapped in the child) as the target vaddr so the
/// validation failure can only come from `buf_ptr`. `buf_ptr` is set to an
/// address in the kernel partition (0xFFFF_8000_0000_0000), which fails the
/// kernel's `AddrSpacePartition.user.contains(buf_ptr)` check.
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
        t.failWithVal("§4.1.65 proc_create", 1, child_ret);
        syscall.shutdown();
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.65 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        t.fail("§4.1.65 no fault_handler proc handle");
        syscall.shutdown();
    }

    // Kernel-partition address — not in user partition, so the buf_ptr check
    // must fire regardless of anything else.
    const kernel_buf: u64 = 0xFFFF_8000_0000_0000;
    const ret = syscall.fault_read_mem(proc_handle, fault_msg.rip, kernel_buf, 8);
    t.expectEqual("§4.1.65", E_BADADDR, ret);

    syscall.shutdown();
}
