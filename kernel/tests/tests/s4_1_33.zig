const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.33 — `fault_read_mem` reads bytes from the target process's virtual address space into the caller's buffer.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault to learn the child's faulting RIP — that's the
    // address of the null-deref opcode `movb (%rax), %al`, which is the
    // 2-byte sequence 0x8a 0x00 in the child's text segment.
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§4.1.33 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Find the child's process handle (with fault_handler bit).
    const fh_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit) != 0)
        {
            proc_handle = view[i].handle;
            break;
        }
    }
    if (proc_handle == 0) {
        t.fail("§4.1.33 no fault_handler proc handle");
        syscall.shutdown();
    }

    // Read 2 bytes from the faulting RIP. They must be the null-deref opcode
    // `movb (%rax), %al` (0x8a 0x00). A stub returning E_OK with zeros would
    // get 0x00 in buf[0] and fail this check.
    var buf: [2]u8 = .{ 0xff, 0xff };
    const rc = syscall.fault_read_mem(proc_handle, fault_msg.rip, @intFromPtr(&buf), 2);
    if (rc != 0) {
        t.failWithVal("§4.1.33 fault_read_mem rc", 0, rc);
        _ = syscall.fault_reply_simple(@bitCast(recv_ret), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    if (buf[0] == 0x8a and buf[1] == 0x00) {
        t.pass("§4.1.33");
    } else {
        t.fail("§4.1.33 wrong bytes read");
    }

    _ = syscall.fault_reply_simple(@bitCast(recv_ret), syscall.FAULT_KILL);
    syscall.shutdown();
}
