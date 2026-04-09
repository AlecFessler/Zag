const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.17.1 — `call` returns `E_OK` with reply payload on success.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{0x42}, &reply);
    t.expectEqual("§4.17.1 rc", 0, rc);
    // child_ipc_server adds 1 to first word: 0x42 -> 0x43
    if (reply.words[0] != 0x43) {
        t.fail("§4.17.1 payload");
        syscall.shutdown();
    }
    t.pass("§4.17.1");
    syscall.shutdown();
}
