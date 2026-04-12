const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.62 — On first boot, process entry `field0` = 0.
pub fn main(_: u64) void {
    // Spawn a fresh child; at its first boot, its own slot 0 (HANDLE_SELF)
    // process entry must have field0 == 0 (fault_reason=0, restart_count=0).
    const child_rights = (perms.ProcessRights{}).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_report_self_field0.ptr),
        children.child_report_self_field0.len,
        child_rights,
    )));
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(ch, &.{}, &reply);
    if (rc != 0) {
        t.failWithVal("§2.1.62 ipc_call", 0, rc);
        syscall.shutdown();
    }
    if (reply.words[0] == 0) {
        t.pass("§2.1.62");
    } else {
        t.fail("§2.1.62");
    }
    syscall.shutdown();
}
