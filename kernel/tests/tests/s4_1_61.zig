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

/// §4.1.61 — `fault_read_mem` returns `E_OK` on success
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
        t.failWithVal("§4.1.61 proc_create", 1, child_ret);
        syscall.shutdown();
    }

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    // Receive the fault.
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.61 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Find the process handle with fault_handler bit in perm_view.
    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        t.fail("§4.1.61 no fault_handler proc handle");
        syscall.shutdown();
    }

    var buf: [8]u8 = .{0} ** 8;
    // Read 8 bytes from the faulting child's RIP — guaranteed mapped code page.
    const read_ret = syscall.fault_read_mem(proc_handle, fault_msg.rip, @intFromPtr(&buf), 8);
    t.expectEqual("§4.1.61 rc", E_OK, read_ret);

    // Verify bytes actually landed in our buffer. The child faulted via a null
    // deref (mov (%rax), %al with rax=0). The faulting instruction sequence
    // lives on a code page, so at least one byte must be non-zero — an all-zero
    // readback would indicate the kernel returned E_OK without copying anything.
    var any_nonzero = false;
    for (buf) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    if (any_nonzero) {
        t.pass("§4.1.61 bytes landed");
    } else {
        t.fail("§4.1.61 buf all zero (bytes did not land)");
    }

    syscall.shutdown();
}
