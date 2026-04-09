const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.36.2 — `fault_write_mem` requires the `fault_handler` bit on `proc_handle`; returns `E_PERM` without it
pub fn main(_: u64) void {
    // Spawn a child with no fault_handler right to get a proc_handle without fault_handler.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.36.2 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    var buf: [8]u8 = .{0} ** 8;
    const ret = syscall.fault_write_mem(child_handle, 0x1000, @intFromPtr(&buf), 8);
    t.expectEqual("§4.36.2", E_PERM, ret);

    syscall.shutdown();
}
