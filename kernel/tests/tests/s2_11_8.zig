const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.11.8 — `call` returns with reply payload in the payload registers.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{0x42}, &reply);
    // child_ipc_server increments word[0] by 1
    if (reply.words[0] == 0x43) {
        t.pass("§2.11.8");
    } else {
        t.fail("§2.11.8");
    }
    syscall.shutdown();
}
