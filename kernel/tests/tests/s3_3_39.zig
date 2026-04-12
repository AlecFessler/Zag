const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.39 — `call` returns `E_OK` with reply payload on success.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{0x42}, &reply);
    t.expectEqual("§3.3.39 rc", 0, rc);
    // child_ipc_server adds 1 to first word: 0x42 -> 0x43
    if (reply.words[0] != 0x43) {
        t.fail("§3.3.39 payload");
        syscall.shutdown();
    }
    t.pass("§3.3.39");
    syscall.shutdown();
}
