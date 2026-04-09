const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.5 — VM reservation handles are not transferable via message passing.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create a VM reservation.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.vm_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    // Spawn a child to receive.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));
    // Try to send VM reservation handle via cap transfer — should fail with E_INVAL.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call_cap(child_handle, &.{ vm_handle, rw.bits() }, &reply);
    t.expectEqual("§2.3.5", E_INVAL, ret);
    syscall.shutdown();
}
